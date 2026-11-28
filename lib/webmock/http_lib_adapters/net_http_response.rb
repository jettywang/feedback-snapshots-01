# frozen_string_literal: true

# This code is entierly copied from VCR (http://github.com/myronmarston/vcr) by courtesy of Myron Marston

# A Net::HTTP response that has already been read raises an IOError when #read_body
# is called with a destination string or block.
#
# This causes a problem when VCR records a response--it reads the body before yielding
# the response, and if the code that consuming the HTTP requests uses #read_body, it
# can cause an error.
#
# This is a bit of a hack, but it allows a Net::HTTP response to be "re-read"
# after it has aleady been read.  This attemps to preserve the behavior of
# #read_body, acting just as if it had never been read.

module Net
  module WebMockHTTPResponse
    def read_body(dest = nil, &block)
      if defined?(@__webmock_replay_segments) && @__webmock_replay_segments
        return webmock_replay_read_body(dest, &block)
      end

      if !(defined?(@__read_body_previously_called).nil?) && @__read_body_previously_called
        return super
      end
      return @body if dest.nil? && block.nil?
      raise ArgumentError.new("both arg and block given for HTTP method") if dest && block
      return nil if @body.nil?

      dest ||= ::Net::ReadAdapter.new(block)
      dest << @body.dup
      @body = dest
    ensure
      # allow subsequent calls to #read_body to proceed as normal, without our hack...
      @__read_body_previously_called = true
    end

    # Attaches the segments of a replayed body. Each segment is handed to the
    # client separately and recorded in the receipt, so a client that stops
    # early leaves only a partial receipt.
    def webmock_replay_body!(segments, receipt)
      @__webmock_replay_segments = segments
      @__webmock_replay_receipt = receipt
      @__webmock_replay_position = 0
      self
    end

    private

    def webmock_replay_read_body(dest = nil, &block)
      segments = @__webmock_replay_segments
      receipt = @__webmock_replay_receipt
      remaining = @__webmock_replay_position < segments.length

      if !remaining
        if @__webmock_replay_delivered
          # The body was already handed over. Behave like an already read
          # response, as Net::HTTP does.
          raise IOError, "#{self.class}\#read_body called twice" if dest || block
          return @body
        end

        # The response has no body to deliver (204, HEAD, or an empty body).
        @__webmock_replay_delivered = true
        @__read_body_previously_called = true
        @read = true
        receipt&.complete!
        return @body
      end

      if dest.nil? && block.nil?
        # Reading the whole body without a block: every segment reaches the
        # caller.
        while @__webmock_replay_position < segments.length
          receipt&.record(segments[@__webmock_replay_position])
          @__webmock_replay_position += 1
        end
        receipt&.complete!
        @__webmock_replay_delivered = true
        @__read_body_previously_called = true
        @read = true
        return @body
      end

      raise ArgumentError.new("both arg and block given for HTTP method") if dest && block

      to = dest || ::Net::ReadAdapter.new(block)
      reached_end = false
      begin
        while @__webmock_replay_position < segments.length
          segment = segments[@__webmock_replay_position]
          receipt&.record(segment)
          @__webmock_replay_position += 1
          to << segment
        end
        reached_end = true
        @__webmock_replay_delivered = true
      ensure
        # A block that broke, threw or raised stops delivery early, even if
        # it happened to stop after the last byte. Such a receipt stays
        # partial; only a read that reached the end is complete.
        reached_end ? receipt&.complete! : receipt&.abort!
        @__read_body_previously_called = true
        @read = true
      end

      @body = to
      @body
    end
  end
end
