require 'net/ssh/buffer'

module Net; module SFTP; module Protocol

  # The negotiated transport limits advertised by an SFTP server through the
  # "limits@openssh.com" extension. The extension lets a server tell the
  # client which packet sizes and request concurrency it is willing to
  # accept; see OpenSSH's PROTOCOL file for the wire description.
  #
  # Every value is validated against what a 32-bit SFTP packet can carry.
  # A zero value means "no limit" per the extension contract, as does a
  # value that is missing or unparseable, so a malformed or malicious reply
  # can only shrink the client's own defaults, never enlarge them.
  class Limits
    # Extension name used in FXP_VERSION and the FXP_EXTENDED request.
    EXTENSION_NAME = "limits@openssh.com"

    # SFTP fields are 32-bit, so no advertised value can legitimately exceed
    # this; anything larger is treated as absent rather than trusted.
    MAX_VALUE = 0xffffffff

    # The 4-byte length prefix, 1-byte packet type and 4-byte request id that
    # frame every SFTP packet, in addition to its type-specific fields.
    PACKET_FRAMING_BYTES = 4 + 1 + 4

    # Bytes on top of the framing for a FXP_WRITE request: handle (string),
    # offset (uint64) and the length prefix of the data string.
    WRITE_OVERHEAD = PACKET_FRAMING_BYTES + 4 + 8 + 4

    # Bytes on top of the framing for a FXP_READ request: handle (string),
    # offset (uint64) and the requested length (uint32).
    READ_REQUEST_OVERHEAD = PACKET_FRAMING_BYTES + 4 + 8 + 4

    # Bytes on top of the framing in a FXP_DATA reply: the request id is part
    # of the framing, leaving only the length prefix of the data string.
    READ_RESPONSE_OVERHEAD = PACKET_FRAMING_BYTES + 4

    attr_reader :max_packet_length, :max_read_length, :max_write_length, :max_open_handles

    # Builds limits from the four raw, already-decoded extension values.
    # Non-integer, negative or oversized values are treated as absent (zero).
    def initialize(max_packet_length = 0, max_read_length = 0, max_write_length = 0, max_open_handles = 0)
      @max_packet_length = sanitize(max_packet_length)
      @max_read_length    = sanitize(max_read_length)
      @max_write_length   = sanitize(max_write_length)
      @max_open_handles   = sanitize(max_open_handles)
    end

    # Parses a FXP_EXTENDED_REPLY packet answering a limits request. Missing
    # fields read as nil and are treated as zero, so a truncated reply still
    # yields a fully usable object.
    def self.from_extended_reply(packet)
      values = 4.times.map { packet.read_long }
      new(*values)
    end

    # The largest data string that may be sent in a FXP_WRITE packet for a
    # handle of +handle_bytes+ bytes, or nil when the server set no packet or
    # write limit. The actual protocol overhead is deducted from the packet
    # budget rather than a fixed safety margin.
    def write_payload_limit(handle_bytes = 0)
      limits = [
        positive(@max_write_length),
        packet_budget(WRITE_OVERHEAD + handle_bytes)
      ].compact
      limits.min
    end

    # The largest data string that may be requested in a FXP_READ for a
    # handle of +handle_bytes+ bytes, bounded by both the request packet and
    # the FXP_DATA reply the server would have to send. Returns nil when the
    # server set no read or packet limit.
    def read_payload_limit(handle_bytes = 0)
      limits = [
        positive(@max_read_length),
        packet_budget(READ_REQUEST_OVERHEAD + handle_bytes),
        packet_budget(READ_RESPONSE_OVERHEAD)
      ].compact
      limits.min
    end

    # The chunk size to use for a write, honoring the client's own +default+
    # (its configured read size) and every negotiated limit. Never below one
    # byte so progress is still possible against a very tight packet cap.
    def write_chunk_size(default, handle_bytes = 0)
      at_least_one([default, write_payload_limit(handle_bytes)].compact.min)
    end

    # The chunk size to use for a read request, honoring the client's own
    # +default+ (its configured read size) and every negotiated limit.
    def read_chunk_size(default, handle_bytes = 0)
      at_least_one([default, read_payload_limit(handle_bytes)].compact.min)
    end

    # The number of handles an operation may keep open at once, bounded by
    # the client's own +default+ and the negotiated cap.
    def open_handle_limit(default)
      [default, positive(@max_open_handles) || default].min
    end

    def ==(other)
      other.is_a?(self.class) &&
        max_packet_length == other.max_packet_length &&
        max_read_length == other.max_read_length &&
        max_write_length == other.max_write_length &&
        max_open_handles == other.max_open_handles
    end

    alias eql? ==

    def hash
      [max_packet_length, max_read_length, max_write_length, max_open_handles].hash
    end

    private

      def sanitize(value)
        return 0 unless value.is_a?(Integer)
        return 0 unless value > 0 && value <= MAX_VALUE

        value
      end

      def positive(value)
        value.zero? ? nil : value
      end

      def packet_budget(overhead)
        return nil if @max_packet_length.zero?

        @max_packet_length - overhead
      end

      def at_least_one(value)
        value < 1 ? 1 : value
      end
  end

end; end; end
