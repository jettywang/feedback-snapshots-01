require File.expand_path(File.dirname(__FILE__) + '/test_helper')
require File.expand_path(File.dirname(__FILE__) + '/../test/support/recording_adapters')

describe "WebMock request evidence" do
  include WebMock::API

  STUB_URL = "http://www.example.com/stubbed"
  DENIED_URL = "http://www.example.net/denied"

  let(:patron) { WebMock::RecordingAdapters::PatronStyleAdapter }
  let(:curb)   { WebMock::RecordingAdapters::CurbStyleAdapter }

  before do
    WebMock::RequestEvidenceRegistry.instance.reset!
    patron.reset!
    curb.reset!
    stub_request(:any, STUB_URL).to_return(
      status: [200, "OK"], headers: { "Content-Type" => "text/plain" }, body: "stub-body"
    )
    WebMock.enable_request_evidence!
  end

  after do
    WebMock.disable_request_evidence!
  end

  def evidence
    WebMock.request_evidence.evidence
  end

  describe "opt-in collection" do
    it "is disabled by default and records nothing until enabled" do
      WebMock.disable_request_evidence!
      patron.handle_request(:get, STUB_URL)
      assert WebMock.request_evidence.empty?
      refute WebMock.request_evidence_enabled?
    end

    it "collects evidence once enabled and stays empty before any request" do
      assert WebMock.request_evidence_enabled?
      assert_equal 0, WebMock.request_evidence.size
    end
  end

  describe "existing request-count assertions" do
    it "keeps counting requests through the recording adapters" do
      patron.handle_request(:get, STUB_URL)
      curb.perform(:get, STUB_URL)
      assert_requested(:get, STUB_URL, times: 2)
      assert_not_requested(:post, DENIED_URL)
    end

    it "still counts the request even when the policy refuses it" do
      assert_raises(WebMock::NetConnectNotAllowedError) do
        patron.handle_request(:get, DENIED_URL)
      end
      # The signature is recorded before the refusal, so count assertions hold.
      assert_requested(:get, DENIED_URL, times: 1)
    end
  end

  WebMock::RecordingAdapters.constants.
    select { |name| name.to_s.end_with?("StyleAdapter") }.
    each do |constant|
      adapter = WebMock::RecordingAdapters.const_get(constant)

      describe "#{constant}" do
        define_method(:run_request) do |*args, **kwargs|
          if adapter == WebMock::RecordingAdapters::PatronStyleAdapter
            adapter.handle_request(*args, **kwargs)
          else
            adapter.perform(*args, **kwargs)
          end
        end

        it "records a stubbed hit that never sends over the network" do
          response = run_request(:get, STUB_URL, headers: { "X-Trace" => "abc" })

          assert_equal 200, response.status
          assert_equal 0, adapter.sent_count

          assert_equal 1, evidence.size
          entry = evidence.first
          assert entry.stubbed?
          refute entry.sent?
          assert_equal adapter::LIB, entry.lib

          # Only allow-listed request content is retained.
          assert_equal WebMock::RequestEvidence::ALLOWED_REQUEST_KEYS.sort, entry.request.keys.sort
          assert_equal :get, entry.request[:method]
          assert_equal STUB_URL, entry.request[:uri]
          assert_equal({ "X-Trace" => "abc" }, entry.request[:headers])
          assert_includes entry.diagnostics, "stub_response"
        end

        it "records a policy refusal with no real send" do
          error = assert_raises(WebMock::NetConnectNotAllowedError) do
            run_request(:post, DENIED_URL, body: "payload")
          end
          assert_match(/Real HTTP connections are disabled/, error.message)
          assert_equal 0, adapter.sent_count

          entry = evidence.first
          assert entry.policy_denied?
          refute entry.sent?
          assert_equal adapter::LIB, entry.lib
          assert_equal :post, entry.request[:method]
          assert_includes entry.diagnostics, "net_connect_disabled"
        end

        it "records an interrupted callback as incomplete without sending" do
          boom = ->(*) { raise "callback blew up" }

          assert_raises(RuntimeError) do
            run_request(:get, STUB_URL, callbacks: [boom])
          end
          assert_equal 0, adapter.sent_count

          entry = evidence.last
          assert entry.incomplete?
          refute entry.sent?
          assert_equal adapter::LIB, entry.lib
          assert entry.diagnostics.any? { |note| note.start_with?("callback_interrupted") }
        end
      end
    end

  describe "signatures and cross-checking" do
    it "exposes a matching signature derived from the actual request" do
      patron.handle_request(:get, STUB_URL, body: "hello")
      entry = evidence.first

      signature = WebMock::RequestSignature.new(:get, STUB_URL, body: "hello", headers: {})
      assert entry.matches_signature?(signature)

      different = WebMock::RequestSignature.new(:get, STUB_URL, body: "other", headers: {})
      refute entry.matches_signature?(different)
    end

    it "lets the registry filter evidence by signature, outcome and library" do
      patron.handle_request(:get, STUB_URL)
      curb.perform(:get, STUB_URL)
      assert_raises(WebMock::NetConnectNotAllowedError) do
        patron.handle_request(:get, DENIED_URL)
      end

      assert_equal 3, evidence.size
      assert_equal 1, WebMock.request_evidence.for_outcome(:policy_denied).size
      assert_equal 2, WebMock.request_evidence.for_outcome(:stubbed).size
      assert_equal 2, WebMock.request_evidence.for_lib(:recording_patron).size
      assert_equal 1, WebMock.request_evidence.for_lib(:recording_curb).size

      denied_signature = WebMock::RequestSignature.new(:get, DENIED_URL)
      matches = WebMock.request_evidence.matching(denied_signature)
      assert_equal 1, matches.size
      assert matches.first.policy_denied?
    end

    it "exports an immutable, serialisable evidence hash" do
      patron.handle_request(:get, STUB_URL)
      entry = evidence.first
      exported = entry.to_h

      assert exported[:request].frozen?
      assert_raises(FrozenError) { exported[:request][:uri] = "tampered" }
      assert_equal entry.signature, exported[:signature]
      assert_equal false, exported[:real_request_sent]
    end
  end

  describe "cross-adapter comparison" do
    def run_with(adapter, *args, **kwargs)
      if adapter == WebMock::RecordingAdapters::PatronStyleAdapter
        adapter.handle_request(*args, **kwargs)
      else
        adapter.perform(*args, **kwargs)
      end
    end

    [
      WebMock::RecordingAdapters::PatronStyleAdapter,
      WebMock::RecordingAdapters::CurbStyleAdapter
    ].each do |adapter|
      it "reports identical real-send status, attribution and diagnostics for #{adapter}" do
        # Stub hit: answered locally, never sent.
        run_with(adapter, :get, STUB_URL)
        stubbed = evidence.last
        assert stubbed.stubbed?
        refute stubbed.sent?
        assert_equal adapter::LIB, stubbed.lib
        assert_equal ["stub_response"], stubbed.diagnostics

        # Policy refusal: raised before any send.
        assert_raises(WebMock::NetConnectNotAllowedError) do
          run_with(adapter, :get, DENIED_URL)
        end
        refused = evidence.last
        assert refused.policy_denied?
        refute refused.sent?
        assert_equal adapter::LIB, refused.lib
        assert_equal ["net_connect_disabled"], refused.diagnostics

        # Callback interruption: replaces the provisional stub outcome.
        assert_raises(RuntimeError) do
          run_with(adapter, :get, STUB_URL, callbacks: [->(*) { raise "boom" }])
        end
        interrupted = evidence.last
        assert interrupted.incomplete?
        refute interrupted.sent?
        assert_equal adapter::LIB, interrupted.lib
        assert interrupted.diagnostics.join.include?("callback_interrupted")

        # Nothing was really sent in any of the three scenarios.
        assert_equal 0, adapter.sent_count
      end
    end

    it "attributes evidence to the adapter that actually handled each request" do
      patron.handle_request(:get, STUB_URL)
      curb.perform(:get, STUB_URL)

      libs = evidence.map(&:lib)
      assert_equal [:recording_patron, :recording_curb], libs
      assert(evidence.all? { |entry| entry.signature.is_a?(String) && entry.signature.length == 64 })
    end
  end
end
