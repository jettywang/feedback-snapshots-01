# frozen_string_literal: true

module HTTP
  class Response
    class Streamer
      def initialize(str, encoding: Encoding::BINARY, receipt: nil)
        @io = StringIO.new str
        @encoding = encoding
        @receipt = receipt
      end

      def readpartial(size = nil, outbuf = nil)
        unless size
          if defined?(HTTP::Connection::BUFFER_SIZE)
            size = HTTP::Connection::BUFFER_SIZE
          elsif defined?(HTTP::Client::BUFFER_SIZE)
            size = HTTP::Client::BUFFER_SIZE
          end
        end

        chunk = @io.read(size, outbuf)

        # HTTP.rb 6.0+ expects EOFError at end-of-stream instead of nil
        if chunk.nil?
          @receipt&.complete! if @io.eof?
          raise EOFError if HTTP::VERSION >= "6.0.0"
          return nil
        end

        @receipt&.record(chunk)
        chunk.force_encoding(@encoding)
      end

      def close
        finish_receipt
        @io.close
      end

      def finished_request?
        @io.eof?
      end

      def sequence_id
        -1
      end

      private

      # A body closed before its end was only partly delivered. With no bytes
      # read at all, the receipt stays pending.
      def finish_receipt
        return if @receipt.nil? || @receipt.finished?

        if @io.eof?
          @receipt.complete!
        elsif @receipt.delivered_bytes > 0
          @receipt.abort!
        end
      end
    end
  end
end
