# frozen_string_literal: true

module WebMock
  # Renders a RequestSignature the way RequestSignature#to_s does, but through a
  # RedactionPolicy. The wrapped signature is left untouched: matching and
  # callbacks keep using its real body, headers and URI, while only this view,
  # intended for shareable logs, hides the configured parts.
  class RedactedRequestSignature
    def initialize(request_signature, policy = RedactionPolicy.from_config)
      @request_signature = request_signature
      @policy = policy
    end

    def to_s
      return request_signature.to_s if policy.permissive?

      string = "#{request_signature.method.to_s.upcase}".dup
      string << " #{WebMock::Util::URI.strip_default_port_from_uri_string(policy.redact_uri(request_signature.uri))}"
      redacted_body = redacted_body_string
      string << " with body '#{redacted_body}'" unless redacted_body.nil? || redacted_body.empty?
      if request_signature.headers && !request_signature.headers.empty?
        string << " with headers #{redacted_headers_string}"
      end
      string
    end

    private

    attr_reader :request_signature, :policy

    # Mirrors RequestSignature#to_s, which only renders a body when its string
    # form is present. JSON and other structured bodies are redacted as data,
    # then serialized back to a string; plain string bodies are hidden whole.
    def redacted_body_string
      body = request_signature.body
      return nil if body.nil? || body.to_s.empty?

      if request_signature.json_headers? && parseable_json?(body)
        redacted = policy.redact(JSON.parse(body))
        return redacted if redacted == RedactionPolicy::REDACTED

        JSON.generate(redacted)
      else
        policy.redact(body).to_s
      end
    end

    def redacted_headers_string
      normalized = WebMock::Util::Headers.normalize_headers(request_signature.headers)
      redacted = policy.redact(normalized)
      return redacted unless redacted.is_a?(Hash)

      WebMock::Util::Headers.reshow_normalized_headers(redacted, ", ")
    end

    def parseable_json?(body)
      return false unless body.is_a?(String)

      JSON.parse(body)
      true
    rescue JSON::ParserError
      false
    end
  end
end
