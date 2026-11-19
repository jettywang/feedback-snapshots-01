# Copyright 2016 Shawn Neal <sneal@sneal.net>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'base64'

module WinRM
  module WSMV
    # Incrementally decodes one WSMV output stream.
    #
    # WSMV delivers a stream as a sequence of Base64 encoded chunks. Each chunk
    # is a complete Base64 value, but chunk boundaries can fall anywhere in the
    # decoded bytes, including inside a multi-byte UTF-8 character. Bytes are
    # therefore buffered until they form complete characters. A BOM is only
    # removed when it appears at the very start of the stream.
    class CommandOutputDecoder
      BOM = "\xEF\xBB\xBF".b.freeze
      UTF8 = Encoding::UTF_8

      def initialize
        @base64_buffer = String.new(encoding: Encoding::BINARY)
        @byte_buffer = String.new(encoding: Encoding::BINARY)
        @at_stream_start = true
        @finished = false
      end

      # Decodes the next chunk of this stream.
      #
      # Returns only text whose characters are complete. An incomplete UTF-8
      # character is retained for the next chunk. An invalid Base64 chunk
      # raises ArgumentError instead of silently dropping bytes.
      # @param raw_output [String] The Base64 encoded output chunk
      # @return [String] Newly decoded, complete UTF-8 text
      def decode(raw_output)
        raise ArgumentError, 'cannot decode a finished output stream' if @finished

        @byte_buffer << decode_base64(raw_output)
        strip_initial_bom
        emit_complete_text
      end

      # Flushes this stream when its command ends.
      #
      # A trailing incomplete UTF-8 sequence is replaced with U+FFFD. It is
      # never combined with bytes from a later command because the reader
      # creates a fresh decoder for every command and stream. A leftover,
      # partial Base64 value raises ArgumentError. A command that fails with a
      # fault never calls this method, so the fault is not masked.
      # @return [String] Remaining UTF-8 text
      def finish
        raise ArgumentError, 'output stream already finished' if @finished

        @finished = true
        check_base64_tail
        text = @byte_buffer.force_encoding(UTF8).scrub
        @byte_buffer = String.new(encoding: Encoding::BINARY)
        text
      end

      private

      def decode_base64(raw_output)
        return String.new(encoding: Encoding::BINARY) if raw_output.nil?

        cleaned = raw_output.to_s.b.gsub(/[ \t\r\n]+/, '')
        validate_base64_alphabet(cleaned)
        @base64_buffer << cleaned
        decoded = String.new(encoding: Encoding::BINARY)
        loop do
          group_end = next_base64_group_end
          break unless group_end

          decoded << strict_decode(@base64_buffer.byteslice(0, group_end))
          @base64_buffer = @base64_buffer.byteslice(group_end..-1) ||
                           String.new(encoding: Encoding::BINARY)
        end
        decoded
      end

      # Returns the end of the next Base64 group that can be decoded without
      # waiting for another chunk. This accepts both independently padded
      # chunks and chunks that split the Base64 text itself. Padding is only
      # valid at the end of a four character group.
      def next_base64_group_end
        pad_index = @base64_buffer.index('=')
        if pad_index
          validate_padding(pad_index)
          group_end = ((pad_index / 4) + 1) * 4
          return nil if group_end > @base64_buffer.bytesize

          return group_end
        end

        complete = (@base64_buffer.bytesize / 4) * 4
        complete.zero? ? nil : complete
      end

      def validate_padding(pad_index)
        tail = @base64_buffer.byteslice(pad_index..-1)
        return if tail.match?(/\A={1,2}\z/) && (pad_index % 4) >= 2

        raise ArgumentError, 'invalid Base64 in WSMV output stream'
      end

      def validate_base64_alphabet(text)
        return if text.match?(%r{\A[A-Za-z0-9+/=]*\z})

        raise ArgumentError, 'invalid Base64 in WSMV output stream'
      end

      def strict_decode(text)
        Base64.strict_decode64(text)
      rescue ArgumentError => e
        raise ArgumentError, "invalid Base64 in WSMV output stream: #{e.message}"
      end

      def check_base64_tail
        return if @base64_buffer.empty?

        raise ArgumentError, 'truncated Base64 in WSMV output stream'
      end

      def strip_initial_bom
        return unless @at_stream_start

        if @byte_buffer.start_with?(BOM)
          @byte_buffer = @byte_buffer.byteslice(BOM.bytesize..-1) ||
                         String.new(encoding: Encoding::BINARY)
          @at_stream_start = false
        elsif @byte_buffer.bytesize >= BOM.bytesize || !BOM.start_with?(@byte_buffer)
          @at_stream_start = false
        end
      end

      def emit_complete_text
        incomplete = trailing_incomplete_bytes(@byte_buffer)
        complete_size = @byte_buffer.bytesize - incomplete
        complete = @byte_buffer.byteslice(0, complete_size) || String.new(encoding: Encoding::BINARY)
        @byte_buffer = @byte_buffer.byteslice(complete_size, incomplete) || String.new(encoding: Encoding::BINARY)
        complete.force_encoding(UTF8).scrub
      end

      # Number of bytes at the end that could still become a complete UTF-8
      # character once more bytes arrive.
      def trailing_incomplete_bytes(bytes)
        size = bytes.bytesize
        [3, size].min.downto(1) do |take|
          start = size - take
          expected = utf8_sequence_length(bytes.getbyte(start))
          next unless expected && expected > take

          following = bytes.byteslice(start + 1, take - 1)
          return take if following.each_byte.all? { |byte| continuation_byte?(byte) }
        end
        0
      end

      def utf8_sequence_length(byte)
        case byte
        when 0x00..0x7F then 1
        when 0xC2..0xDF then 2
        when 0xE0..0xEF then 3
        when 0xF0..0xF4 then 4
        end
      end

      def continuation_byte?(byte)
        byte >= 0x80 && byte <= 0xBF
      end
    end
  end
end
