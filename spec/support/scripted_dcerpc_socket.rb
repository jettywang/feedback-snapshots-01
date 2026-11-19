# A minimal in-memory TCP socket stand-in that feeds a scripted sequence of
# DCE/RPC response PDUs to a RubySMB::Dcerpc::Client while recording every
# request PDU the client writes. It lets the specs drive real bind/request
# sessions over raw bytes without binding a network port.
class ScriptedDcerpcSocket
  # @param responses [Array<BinData::Record, String>] the PDUs the client will read, in order
  def initialize(responses)
    frames = responses.map { |response| response.respond_to?(:to_binary_s) ? response.to_binary_s : response.to_s }
    @read_io = StringIO.new(frames.join.b)
    @written_frames = []
  end

  # @return [Array<String>] the exact PDU bytes written by the client, one entry per write
  attr_reader :written_frames

  def read(*args)
    @read_io.read(*args)
  end

  def write(data)
    @written_frames << data.b
    data.bytesize
  end

  def closed?
    false
  end

  # Reset the read side with a new sequence of PDUs, keeping the frames the
  # client has already written. This is useful to script a second round-trip.
  def queue_responses(responses)
    frames = responses.map { |response| response.respond_to?(:to_binary_s) ? response.to_binary_s : response.to_s }
    @read_io = StringIO.new(frames.join.b)
  end
end
