module WinRM
  module HTTP
    # Parses the multipart envelope of an NTLM-encrypted WinRM response.
    #
    # The parser validates the MIME framing, the declared OriginalContent
    # length and the NTLM signature envelope before exposing any payload to the
    # caller. Invalid or ambiguous wrapping raises ParseError so the transport
    # can reject the response without decrypting, logging or parsing it.
    class EncryptedResponse
      class ParseError < StandardError; end

      SIGNATURE_LENGTH = 16
      SIGNATURE_PREFIX_LENGTH = 4
      MAX_BOUNDARY_LENGTH = 70
      PROTOCOL = 'application/http-spnego-session-encrypted'.freeze
      SOAP_MEDIA_TYPE = 'application/soap+xml'.freeze
      OCTET_STREAM_MEDIA_TYPE = 'application/octet-stream'.freeze
      HEADER_TERMINATOR = "\r\n".b

      # Quote-aware Content-Type parser shared by the response header and the
      # OriginalContent header.
      class ContentType
        attr_reader :media_type, :params

        def self.parse(value)
          return nil if value.nil?

          parts = split(value.to_s, ';')
          media_type = parts.shift.to_s.strip.downcase
          return nil if media_type.empty?

          new(media_type, parts)
        end

        def self.median(value)
          parsed = parse(value)
          parsed && parsed.media_type
        end

        def self.parameters(value)
          new(nil, split(value.to_s, ';')).params
        end

        def self.split(value, separator)
          parts = [+'']
          quoted = false
          escaped = false
          value.each_char do |char|
            if escaped
              parts.last << char
              escaped = false
            elsif quoted && char == '\\'
              parts.last << char
              escaped = true
            elsif char == '"'
              quoted = !quoted
              parts.last << char
            elsif char == separator && !quoted
              parts << +''
            else
              parts.last << char
            end
          end
          parts
        end

        def self.unquote(value)
          return value unless value.length >= 2 && value.start_with?('"') && value.end_with?('"')

          value[1..-2].gsub(/\\(.)/, '\1')
        end

        def initialize(media_type, parts)
          @media_type = media_type
          @params = {}
          @quoted = {}
          parts.each { |part| add_parameter(part) }
        end

        def [](key)
          @params[key]
        end

        def quoted?(key)
          @quoted[key]
        end

        private

        def add_parameter(part)
          key, raw = part.split('=', 2)
          return if raw.nil?

          key = key.to_s.strip.downcase
          value = raw.strip
          @params[key] = self.class.unquote(value)
          @quoted[key] = value.start_with?('"') && value.end_with?('"')
        end
      end

      attr_reader :boundary, :original_content_length, :signature, :sealed_message

      def self.media_type(value)
        ContentType.median(value)
      end

      def initialize(body, content_type)
        @body = body.to_s.dup.force_encoding(Encoding::BINARY)
        @content_type = ContentType.parse(content_type)
        @boundary = @content_type && @content_type['boundary']
        parse!
      end

      private

      def parse!
        validate_content_type!
        validate_boundary!

        parse_encrypted_part(extract_encrypted_part)
        parse_payload_part
      end

      def validate_content_type!
        raise ParseError, 'Missing NTLM response Content-Type' if @content_type.nil?
        unless @content_type.media_type == 'multipart/encrypted'
          raise ParseError, "Unexpected NTLM response Content-Type: #{@content_type.media_type}"
        end

        protocol = @content_type['protocol']
        return if !protocol.nil? && protocol.casecmp(PROTOCOL).zero?

        raise ParseError, 'Unexpected NTLM multipart encryption protocol'
      end

      def validate_boundary!
        raise ParseError, 'Missing NTLM multipart boundary' if @boundary.nil? || @boundary.empty?

        if @boundary.bytesize > MAX_BOUNDARY_LENGTH || !@boundary.ascii_only? ||
           @boundary.match?(/[\x00-\x1f\x7f]/) || @boundary.end_with?(' ')
          raise ParseError, 'Invalid NTLM multipart boundary'
        end

        return if @content_type.quoted?('boundary')
        return if @boundary.match?(/\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z/)

        raise ParseError, 'Unquoted NTLM multipart boundary contains invalid characters'
      end

      def delimiter
        "--#{@boundary}".b
      end

      def opening_delimiter
        "#{delimiter}\r\n".b
      end

      def inner_delimiter
        "\r\n#{delimiter}\r\n".b
      end

      def closing_delimiter
        "#{delimiter}--".b
      end

      # Extracts the headers of the first (encryption metadata) part. The
      # OriginalContent header has no binary content, so the first inner
      # delimiter is unambiguous there.
      def extract_encrypted_part
        unless @body.start_with?(opening_delimiter)
          raise ParseError, 'NTLM multipart response does not start with its boundary'
        end

        part_start = opening_delimiter.bytesize
        part_end = @body.index(inner_delimiter, part_start)
        raise ParseError, 'Missing NTLM multipart encrypted payload boundary' if part_end.nil?

        @payload_start = part_end + inner_delimiter.bytesize
        @body.byteslice(part_start, part_end - part_start)
      end

      def parse_encrypted_part(part)
        headers = parse_headers(part)
        unless ContentType.median(headers['content-type']) == PROTOCOL
          raise ParseError, 'Unexpected NTLM encrypted part Content-Type'
        end

        parse_original_content(headers['originalcontent'])
      end

      def parse_original_content(value)
        raise ParseError, 'Missing NTLM OriginalContent header' if value.nil?

        params = ContentType.parameters(value)
        unless params['type'].to_s.casecmp(SOAP_MEDIA_TYPE).zero?
          raise ParseError, 'Unexpected NTLM OriginalContent type'
        end

        length = params['length'].to_s
        raise ParseError, 'Invalid NTLM OriginalContent length' unless length.match?(/\A\d+\z/)

        @original_content_length = length.to_i
        raise ParseError, 'Invalid NTLM OriginalContent length' if @original_content_length <= 0
      end

      def parse_payload_part
        headers, content_offset = extract_payload_headers
        unless ContentType.median(headers['content-type']) == OCTET_STREAM_MEDIA_TYPE
          raise ParseError, 'Unexpected NTLM encrypted payload Content-Type'
        end

        parse_signature_and_payload(content_offset)
      end

      # The WinRM wire format places a single Content-Type header line before
      # the binary payload. Parsing exactly that line (plus an optional blank
      # line) avoids scanning ciphertext for a header terminator.
      def extract_payload_headers
        line_end = @body.index(HEADER_TERMINATOR, @payload_start)
        raise ParseError, 'Malformed NTLM encrypted payload headers' if line_end.nil?

        header_text = @body.byteslice(@payload_start, line_end - @payload_start)
        headers = parse_headers(header_text)
        raise ParseError, 'Missing NTLM encrypted payload Content-Type' unless headers.key?('content-type')

        content_offset = line_end + HEADER_TERMINATOR.bytesize
        content_offset += 2 if @body.byteslice(content_offset, 2) == "\r\n".b
        [headers, content_offset]
      end

      def parse_signature_and_payload(content_offset)
        payload_size = SIGNATURE_PREFIX_LENGTH + SIGNATURE_LENGTH + @original_content_length
        content_end = content_offset + payload_size
        raise ParseError, 'Truncated NTLM encrypted payload' if @body.bytesize < content_end

        payload = @body.byteslice(content_offset, payload_size)
        validate_closing_framing!(content_end)
        validate_signature!(payload)

        @signature = payload.byteslice(SIGNATURE_PREFIX_LENGTH, SIGNATURE_LENGTH)
        @sealed_message = payload.byteslice(
          SIGNATURE_PREFIX_LENGTH + SIGNATURE_LENGTH,
          @original_content_length
        )
      end

      def validate_signature!(payload)
        signature_length = payload.byteslice(0, SIGNATURE_PREFIX_LENGTH).unpack1('V')
        return if signature_length == SIGNATURE_LENGTH

        raise ParseError, 'Invalid NTLM signature length'
      end

      def validate_closing_framing!(content_end)
        tail = @body.byteslice(content_end, @body.bytesize - content_end)
        tail = tail.byteslice(2, tail.bytesize - 2) if tail.start_with?("\r\n".b)

        unless tail.start_with?(closing_delimiter)
          raise ParseError, 'NTLM encrypted payload length does not match OriginalContent length'
        end

        trailing = tail.byteslice(closing_delimiter.bytesize, tail.bytesize)
        return if trailing.empty? || trailing.match?(/\A[\r\n]*\z/)

        raise ParseError, 'Unexpected content after NTLM multipart closing boundary'
      end

      def parse_headers(text)
        lines = text.to_s.split("\r\n")
        lines.pop while lines.last == ''
        lines.each_with_object({}) do |line, headers|
          name, value = line.split(':', 2)
          if value.nil? || name.nil? || name.strip.empty?
            raise ParseError, 'Malformed NTLM multipart header'
          end

          key = name.strip.downcase
          raise ParseError, "Duplicate NTLM multipart header: #{key}" if headers.key?(key)

          headers[key] = value.strip
        end
      end
    end
  end
end
