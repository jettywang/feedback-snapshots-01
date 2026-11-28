require File.expand_path(File.dirname(__FILE__) + '/test_helper')

test_class = defined?(Minitest::Test) ? Minitest::Test : MiniTest::Unit::TestCase

# Replay evidence for stubbed responses: every selected stub produces one
# immutable version, and each delivery produces one receipt that records the
# bytes the client actually received. Runs offline, with no real connections.
class ReplayEvidenceTest < test_class
  include HttpRequestTestHelper

  RACK_AVAILABLE = begin
    require "rack"
    true
  rescue LoadError
    false
  end

  def evidence
    WebMock.replay_evidence
  end

  def rack_available?
    RACK_AVAILABLE
  end

  def read_body_in_chunks(url, max_chunks: nil)
    uri = URI.parse(url)
    chunks = []
    Net::HTTP.start(uri.host, uri.port) do |http|
      http.request_get(uri.path) do |response|
        response.read_body do |chunk|
          chunks << chunk
          break if max_chunks && chunks.size >= max_chunks
        end
      end
    end
    chunks.join
  end

  def test_full_delivery_of_a_direct_body_is_complete_and_names_its_stub
    stub = stub_request(:get, "http://www.example.com/direct").
      to_return(body: "abcdef")

    assert_equal "abcdef", read_body_in_chunks("http://www.example.com/direct")

    version = evidence.versions_for_stub(stub).first
    receipt = evidence.receipts_for_stub(stub).first

    refute_nil version
    assert_equal :direct, version.source
    assert_equal [6], version.segment_sizes
    assert_equal Digest::SHA256.hexdigest("abcdef"), version.body_digest
    assert_equal stub.request_pattern.to_s, version.stub_pattern

    assert_equal :complete, receipt.state
    assert receipt.complete?
    assert_equal 6, receipt.delivered_bytes
    assert_equal [6], receipt.delivered_segments
    assert_equal version.body_digest, receipt.delivered_sha256
    assert_same version, evidence.version(receipt.version_id)
  end

  def test_a_client_that_stops_after_the_first_chunk_leaves_only_a_partial_receipt
    stub = stub_request(:get, "http://www.example.com/direct").
      to_return(body: "abcdef")

    read_body_in_chunks("http://www.example.com/direct", max_chunks: 1)

    receipt = evidence.receipts_for_stub(stub).last
    assert_equal :partial, receipt.state
    assert receipt.partial?
    refute receipt.complete?
    assert_equal 6, receipt.delivered_bytes
    assert_equal Digest::SHA256.hexdigest("abcdef"), receipt.delivered_sha256
  end

  def test_two_requests_to_the_same_stub_get_one_version_each_in_order
    stub = stub_request(:get, "http://www.example.com/twice").
      to_return(body: "first").then.
      to_return(body: "second")

    assert_equal "first", http_request(:get, "http://www.example.com/twice").body
    assert_equal "second", http_request(:get, "http://www.example.com/twice").body

    versions = evidence.versions_for_stub(stub)
    assert_equal 2, versions.length
    assert_equal versions.map { |version| version.id }.sort, versions.map(&:id)
    assert_equal [stub.stub_id, stub.stub_id], versions.map(&:stub_id)
    assert_equal Digest::SHA256.hexdigest("first"), versions[0].body_digest
    assert_equal Digest::SHA256.hexdigest("second"), versions[1].body_digest
    assert_equal [:complete, :complete], evidence.receipts_for_stub(stub).map(&:state)
    assert_equal [5, 6], evidence.receipts_for_stub(stub).map(&:delivered_bytes)
  end

  def test_version_survives_stub_removal_for_traceability
    old_stub = stub_request(:get, "http://www.example.com/swap").
      to_return(body: "old-body")
    assert_equal "old-body", http_request(:get, "http://www.example.com/swap").body

    WebMock.remove_request_stub(old_stub)
    new_stub = stub_request(:get, "http://www.example.com/swap").
      to_return(body: "new-body")
    assert_equal "new-body", http_request(:get, "http://www.example.com/swap").body

    old_receipt = evidence.receipts_for_stub(old_stub).last
    new_receipt = evidence.receipts_for_stub(new_stub).last

    assert_equal old_stub.stub_id, old_receipt.stub_id
    assert_equal new_stub.stub_id, new_receipt.stub_id
    refute_equal old_receipt.stub_id, new_receipt.stub_id
    assert_equal Digest::SHA256.hexdigest("old-body"), old_receipt.body_digest
    assert_equal Digest::SHA256.hexdigest("new-body"), new_receipt.body_digest
    assert_equal old_stub.request_pattern.to_s, old_receipt.stub_pattern
  end

  def test_receipts_record_the_request_signature_that_was_replayed
    stub_request(:post, "http://www.example.com/sign").
      to_return(body: "ok")
    http_request(:post, "http://www.example.com/sign", body: "payload")

    receipt = evidence.receipts.last
    refute_nil receipt.request_signature
    assert_match %r{\APOST http://www.example.com/sign}, receipt.request_signature
    assert_match(/with body 'payload'/, receipt.request_signature)
    assert_equal Digest::SHA256.hexdigest(receipt.request_signature),
      receipt.request_signature_digest
  end

  def test_a_response_that_was_never_delivered_stays_pending
    stub = stub_request(:get, "http://www.example.com/never").
      to_return(body: "abc")

    # Select the stub without handing the body to a client.
    response = WebMock::StubRegistry.instance.response_for_request(
      WebMock::RequestSignature.new(:get, "http://www.example.com/never"))

    refute_nil response
    receipt = evidence.receipts_for_stub(stub).last
    assert_equal :pending, receipt.state
    assert receipt.pending?
    assert_equal 0, receipt.delivered_bytes
    assert_equal [receipt], evidence.pending_receipts
  end

  def test_reset_clears_evidence_with_the_other_registries
    stub_request(:get, "http://www.example.com/clear").to_return(body: "abc")
    http_request(:get, "http://www.example.com/clear")
    refute_empty evidence.receipts

    WebMock.reset!
    assert_empty evidence.receipts
    assert_empty evidence.versions
  end

  def test_exception_in_the_client_block_leaves_a_partial_receipt
    stub = stub_request(:get, "http://www.example.com/boom").to_return(body: "abcdef")
    error = assert_raises(RuntimeError) do
      Net::HTTP.start("www.example.com", 80) do |http|
        http.request_get("/boom") do |response|
          response.read_body { |_chunk| raise "client failed" }
        end
      end
    end

    assert_equal "client failed", error.message
    receipt = evidence.receipts_for_stub(stub).last
    assert_equal :partial, receipt.state
    assert_equal 6, receipt.delivered_bytes
  end

  def test_rack_response_version_keeps_the_app_chunks_as_segments
    skip "Rack is not available" unless rack_available?

    app = lambda do |_env|
      [201, {"Content-Type" => "text/plain"}, ["hello ", "world"]]
    end
    stub = stub_request(:get, "http://www.example.com/rack")
    stub.to_rack(app)

    assert_equal "hello world", http_request(:get, "http://www.example.com/rack").body

    version = evidence.versions_for_stub(stub).last
    receipt = evidence.receipts_for_stub(stub).last

    assert_equal :rack, version.source
    assert_equal [201, "Created"], version.status
    assert_equal [6, 5], version.segment_sizes
    assert_equal 11, version.body_bytesize
    assert_equal Digest::SHA256.hexdigest("hello world"), version.body_digest
    assert_equal :complete, receipt.state
    assert_equal 11, receipt.delivered_bytes
    assert_equal [6, 5], receipt.delivered_segments
    assert_equal version.body_digest, receipt.delivered_sha256
  end

  def test_aborted_rack_stream_reports_only_the_chunks_the_client_received
    skip "Rack is not available" unless rack_available?

    app = lambda do |_env|
      [200, {"Content-Type" => "text/plain"}, ["first-", "second-", "third"]]
    end
    stub = stub_request(:get, "http://www.example.com/rack-stream")
    stub.to_rack(app)

    body = read_body_in_chunks("http://www.example.com/rack-stream", max_chunks: 1)
    assert_equal "first-", body

    receipt = evidence.receipts_for_stub(stub).last
    assert_equal :partial, receipt.state
    assert_equal 6, receipt.delivered_bytes
    assert_equal [6], receipt.delivered_segments
    assert_equal receipt.version_id, evidence.versions_for_stub(stub).last.id
  end

  def test_two_recorded_versions_for_the_same_request_can_be_told_apart
    skip "Rack is not available" unless rack_available?

    first = stub_request(:get, "http://www.example.com/same")
    first.to_rack(lambda { |_env| [200, {}, ["rack-alpha"]] })
    second = stub_request(:get, "http://www.example.com/same")
    second.to_return(body: "direct-beta")

    # The last registered stub answers both requests.
    read_body_in_chunks("http://www.example.com/same")
    read_body_in_chunks("http://www.example.com/same")

    direct_receipts = evidence.receipts_for_stub(second)
    assert_equal 2, direct_receipts.length
    assert_equal [:complete, :complete], direct_receipts.map(&:state)
    assert_equal [11, 11], direct_receipts.map(&:delivered_bytes)
    # Swap the stubs: the next request belongs to the Rack stub, and the
    # older receipts still point at the first stub by its id.
    WebMock.remove_request_stub(second)
    read_body_in_chunks("http://www.example.com/same")

    rack_receipt = evidence.receipts_for_stub(first).last
    assert_equal :rack, rack_receipt.source
    assert_equal 10, rack_receipt.delivered_bytes
    refute_equal direct_receipts.first.version_id, rack_receipt.version_id
    assert_equal 3, evidence.versions.length
  end

  def test_rack_and_direct_stubs_of_one_request_stay_separate
    skip "Rack is not available" unless rack_available?

    rack_stub = stub_request(:get, "http://www.example.com/mixed")
    rack_stub.to_rack(lambda { |_env| [200, {}, ["rack-body"]] })
    direct_stub = stub_request(:get, "http://www.example.com/mixed")
    direct_stub.to_return(body: "direct-body")

    # The last registered stub wins for the first request.
    assert_equal "direct-body", read_body_in_chunks("http://www.example.com/mixed")

    WebMock.remove_request_stub(direct_stub)
    assert_equal "rack-body", read_body_in_chunks("http://www.example.com/mixed")

    direct_receipt = evidence.receipts_for_stub(direct_stub).last
    rack_receipt = evidence.receipts_for_stub(rack_stub).last

    assert_equal :direct, direct_receipt.source
    assert_equal 11, direct_receipt.delivered_bytes
    assert_equal :rack, rack_receipt.source
    assert_equal 9, rack_receipt.delivered_bytes
    refute_equal direct_receipt.version_id, rack_receipt.version_id
  end

  def test_a_streamed_rack_post_records_the_signature_and_the_partial_prefix
    skip "Rack is not available" unless rack_available?

    stub = stub_request(:post, "http://www.example.com/stream-post")
    stub.to_rack(lambda { |_env| [200, {}, ["part-1-", "part-2-", "part-3"]] })

    uri = URI.parse("http://www.example.com/stream-post")
    Net::HTTP.start(uri.host, uri.port) do |http|
      request = Net::HTTP::Post.new(uri.path)
      request.body = "payload"
      http.request(request) do |response|
        response.read_body { |_chunk| break }
      end
    end

    receipt = evidence.receipts_for_stub(stub).last
    version = evidence.versions_for_stub(stub).last

    assert_match %r{\APOST http://www.example.com/stream-post with body 'payload'},
      receipt.request_signature
    assert_equal Digest::SHA256.hexdigest(receipt.request_signature),
      receipt.request_signature_digest
    assert_equal :rack, receipt.source
    assert_equal :partial, receipt.state
    assert_equal 7, receipt.delivered_bytes
    assert_equal [7], receipt.delivered_segments
    assert_equal [7, 7, 6], version.segment_sizes
    assert_equal 20, version.body_bytesize
    refute_equal version.body_digest, receipt.delivered_sha256
  end

  def test_after_request_callbacks_still_see_the_original_response
    order = []
    WebMock.after_request do |request, response|
      order << [request.method, response.body]
    end

    stub_request(:get, "http://www.example.com/callback").to_return(body: "cb-body")
    assert_equal "cb-body", http_request(:get, "http://www.example.com/callback").body

    assert_equal [[:get, "cb-body"]], order
  ensure
    WebMock.reset_callbacks
  end

  def test_receipts_round_trip_as_plain_data
    stub = stub_request(:get, "http://www.example.com/data").to_return(body: "abc")
    http_request(:get, "http://www.example.com/data")

    hash = evidence.receipts_for_stub(stub).last.to_h
    assert_equal :complete, hash[:state]
    assert_equal 3, hash[:delivered_bytes]
    assert_equal stub.stub_id, hash[:stub_id]
    JSON.parse(JSON.generate(hash))
  end
end
