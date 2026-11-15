require 'common'

class RequestTest < Net::SFTP::TestCase
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
    packet = stub("packet", :type => 1)
    session = stub("session", :protocol => mock("protocol"))
    session.protocol.expects(:parse).with(packet).returns({})
    request = Net::SFTP::Request.new(session, :open, 1)
    assert_nil request.response
    request.respond_to(packet)
    assert_instance_of Net::SFTP::Response, request.response
  end

  def test_respond_to_with_callback_should_invoke_callback
    packet = stub("packet", :type => 1)
    session = stub("session", :protocol => mock("protocol"))
    session.protocol.expects(:parse).with(packet).returns({})

    called = false
    request = Net::SFTP::Request.new(session, :open, 1) do |response|
      called = true
      assert_equal request.response, response
    end

    request.respond_to(packet)
    assert called
  end

  def test_respond_to_should_raise_and_leave_no_response_when_the_packet_cannot_be_parsed
    packet = stub("packet", :type => 1)
    session = stub("session", :protocol => mock("protocol"))
    session.protocol.expects(:parse).with(packet).raises(Net::SFTP::TruncatedPacketError, "short")

    called = false
    request = Net::SFTP::Request.new(session, :open, 1) { called = true }

    error = assert_raises(Net::SFTP::TruncatedPacketError) { request.respond_to(packet) }
    assert_equal "short", error.message
    refute called
    assert_nil request.response
  end

  def test_wait_should_raise_the_parse_error_after_a_failed_response
    session = MockSession.new
    session.pending_requests = { 1 => true }
    request = Net::SFTP::Request.new(session, :open, 1)

    error = assert_raises(Net::SFTP::MalformedPacketError) do
      session.on_loop = proc { session.pending_requests.delete(1); request.fail!(Net::SFTP::MalformedPacketError.new("bad")) }
      request.wait
    end
    assert_equal "bad", error.message
  end

  private

    class MockSession
      attr_reader :loops
      attr_accessor :pending_requests, :on_loop

      def initialize
        @loops = 0
        @pending_requests = {}
      end

      def loop
        while true
          @loops += 1
          @on_loop.call if @on_loop
          break unless yield
        end
      end
    end
end