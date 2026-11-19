require 'ruby_smb/dispatcher'

# An in-memory dispatcher that feeds queued raw responses back to the client
# without touching the network. Used to exercise how the client handles
# crafted (valid, unsigned, tampered or foreign-session) responses.
class InMemoryDispatcher < RubySMB::Dispatcher::Base
  attr_reader :sent_packets

  def initialize
    @responses = []
    @sent_packets = []
  end

  def queue_response(raw_response)
    @responses << raw_response
  end

  def send_packet(packet, **_kwargs)
    @sent_packets << (packet.is_a?(String) ? packet : packet.to_binary_s)
    nil
  end

  def recv_packet(**_kwargs)
    response = @responses.shift
    raise RubySMB::Error::CommunicationError, 'No queued response' if response.nil?
    response
  end
end
