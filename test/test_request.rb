require 'common'
require 'set'

class RequestTest < Net::SFTP::TestCase
  include Net::SFTP::Constants::PacketTypes

  def test_property_setter_should_symbolize_key
    request = Net::SFTP::Request.new(stub("session"), :open, 1)
    request["key"] = :value
    assert_equal :value, request['key']
    assert_equal :value, request[:key]
    assert_equal :value, request.properties[:key]
    assert_nil request.properties['key']
  end

  def test_pending_should_query_pending_requests_of_session
    session = stub("session", :pending_requests => {1 => true})
    request = Net::SFTP::Request.new(session, :open, 1)
    assert request.pending?
    request = Net::SFTP::Request.new(session, :open, 2)
    assert !request.pending?
  end

  def test_wait_should_run_loop_while_pending_and_return_self
    session = MockSession.new
    request = Net::SFTP::Request.new(session, :open, 1)
    request.expects(:pending?).times(4).returns(true, true, true, false)
    assert_equal 0, session.loops
    assert_equal request, request.wait
    assert_equal 4, session.loops
  end

  def test_respond_to_should_set_response_property
    packet = stub("packet", :type => FXP_HANDLE)
    session = stub("session", :protocol => mock("protocol"))
    session.protocol.expects(:parse).with(packet).returns({:handle => "h"})
    request = Net::SFTP::Request.new(session, :open, 1)
    assert_nil request.response
    request.respond_to(packet)
    assert_instance_of Net::SFTP::Response, request.response
    assert_equal "h", request.response[:handle]
  end

  def test_respond_to_with_callback_should_invoke_callback
    packet = stub("packet", :type => FXP_HANDLE)
    session = stub("session", :protocol => mock("protocol"))
    session.protocol.expects(:parse).with(packet).returns({:handle => "h"})

    called = false
    request = Net::SFTP::Request.new(session, :open, 1) do |response|
      called = true
      assert_equal request.response, response
    end

    request.respond_to(packet)
    assert called
  end

  def test_respond_to_should_reject_packet_that_does_not_match_the_request_contract
    packet = stub("packet", :type => FXP_DATA)
    session = stub("session", :protocol => mock("protocol"))
    session.protocol.expects(:parse).with(packet).returns({:data => "x"})

    request = Net::SFTP::Request.new(session, :open, 7)
    error = assert_raises(Net::SFTP::MalformedPacketError) { request.respond_to(packet) }
    assert_match(/FXP_HANDLE.*open/, error.message)
    assert_nil request.response
    assert_same error, request.instance_variable_get(:@error)
  end

  def test_respond_to_should_reject_status_ok_that_carries_no_handle
    packet = stub("packet", :type => FXP_STATUS)
    session = stub("session", :protocol => mock("protocol"))
    session.protocol.expects(:parse).with(packet).returns({:code => Net::SFTP::Constants::StatusCodes::FX_OK})

    request = Net::SFTP::Request.new(session, :open, 7)
    error = assert_raises(Net::SFTP::MalformedPacketError) { request.respond_to(packet) }
    assert_match(/FX_OK status without a FXP_HANDLE packet/, error.message)
    assert_nil request.response
  end

  def test_respond_to_should_reject_eof_status_for_non_read_operations
    packet = stub("packet", :type => FXP_STATUS)
    session = stub("session", :protocol => mock("protocol"))
    session.protocol.expects(:parse).with(packet).returns({:code => Net::SFTP::Constants::StatusCodes::FX_EOF})

    request = Net::SFTP::Request.new(session, :open, 7)
    error = assert_raises(Net::SFTP::MalformedPacketError) { request.respond_to(packet) }
    assert_match(/FX_EOF status is not a valid response for the open request/, error.message)
  end

  def test_respond_to_should_accept_error_status_for_any_request
    packet = stub("packet", :type => FXP_STATUS)
    session = stub("session", :protocol => mock("protocol"))
    session.protocol.expects(:parse).with(packet).returns({:code => Net::SFTP::Constants::StatusCodes::FX_FAILURE})

    called = false
    request = Net::SFTP::Request.new(session, :open, 7) { |response| called = true }
    request.respond_to(packet)
    assert called
    assert !request.response.ok?
    assert_equal Net::SFTP::Constants::StatusCodes::FX_FAILURE, request.response.code
  end

  def test_respond_to_should_accept_eof_status_for_read_and_readdir
    eof = Net::SFTP::Constants::StatusCodes::FX_EOF
    [:read, :readdir].each do |type|
      packet = stub("packet", :type => FXP_STATUS)
      session = stub("session", :protocol => mock("protocol"))
      session.protocol.expects(:parse).with(packet).returns({:code => eof})

      request = Net::SFTP::Request.new(session, type, 1)
      request.respond_to(packet)
      assert request.response.eof?
    end
  end

  def test_respond_to_should_not_invoke_callback_when_contract_violation_raises
    packet = stub("packet", :type => FXP_STATUS)
    session = stub("session", :protocol => mock("protocol"))
    session.protocol.expects(:parse).with(packet).returns({:code => Net::SFTP::Constants::StatusCodes::FX_OK})

    called = false
    request = Net::SFTP::Request.new(session, :read, 1) { called = true }
    assert_raises(Net::SFTP::MalformedPacketError) { request.respond_to(packet) }
    refute called
    assert_nil request.response
  end

  def test_respond_to_should_propagate_parse_errors_and_fail_the_request
    packet = stub("packet", :type => FXP_NAME)
    session = stub("session", :protocol => mock("protocol"))
    session.protocol.expects(:parse).with(packet).raises(Net::SFTP::Exception, "truncated packet")

    request = Net::SFTP::Request.new(session, :readdir, 1)
    error = assert_raises(Net::SFTP::Exception) { request.respond_to(packet) }
    assert_equal "truncated packet", error.message
    assert_same error, request.instance_variable_get(:@error)
  end

  def test_response_contract_keeps_payload_and_status_only_operations
    payload_operations = [:open, :opendir, :read, :readdir, :stat, :lstat,
                          :fstat, :realpath, :readlink]
    status_only_operations = [:close, :write, :setstat, :fsetstat, :remove,
                              :mkdir, :rmdir, :rename, :symlink, :link, :block, :unblock]

    assert_equal Set.new(payload_operations + status_only_operations),
                 Set.new(Net::SFTP::Request::RESPONSE_TYPES.keys)

    payload_operations.each do |operation|
      refute_empty Net::SFTP::Request::RESPONSE_TYPES[operation],
        "#{operation} must name the payload packet that carries its success result"
    end

    status_only_operations.each do |operation|
      assert_empty Net::SFTP::Request::RESPONSE_TYPES[operation],
        "#{operation} is answered by FXP_STATUS only"
    end

    assert_equal [:read, :readdir], Net::SFTP::Request::EOF_REQUESTS
  end

  private

    class MockSession
      attr_reader :loops

      def initialize
        @loops = 0
      end

      def loop
        while true
          @loops += 1
          break unless yield
        end
      end
    end
end