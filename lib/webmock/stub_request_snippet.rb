# frozen_string_literal: true

module WebMock
  class StubRequestSnippet
    def initialize(request_stub, policy: RedactionPolicy.from_config)
      @request_stub = request_stub
      @policy = policy
    end

    def body_pattern
      request_pattern.body_pattern
    end

    def to_s(with_response = true)
      request_pattern = @request_stub.request_pattern
      string = "stub_request(:#{request_pattern.method_pattern.to_s},".dup
      string << " \"#{uri_snippet(request_pattern)}\")"

      with = "".dup

      if (request_pattern.body_pattern)
        with << "\n    body: #{body_snippet(request_pattern)}"
      end

      if (request_pattern.headers_pattern)
        with << "," unless with.empty?

        with << "\n    headers: #{headers_snippet(request_pattern)}"
      end
      string << ".\n  with(#{with})" unless with.empty?
      if with_response
        if request_pattern.headers_pattern && request_pattern.headers_pattern.matches?({ 'Accept' => "application/json" })
          string << ".\n  to_return(status: 200, body: \"{}\", headers: {})"
        else
          string << ".\n  to_return(status: 200, body: \"\", headers: {})"
        end
      end
      string
    end

    private

    # With the default permissive policy the original renderers are used
    # verbatim, so a redaction policy that hides nothing never changes output.
    def uri_snippet(request_pattern)
      return request_pattern.uri_pattern.to_s if @policy.permissive?

      @policy.redact_uri(request_pattern.uri_pattern.to_s)
    end

    def body_snippet(request_pattern)
      return request_pattern.body_pattern.to_s if @policy.permissive?

      body = request_pattern.body_pattern.pattern
      @policy.redact_body_pattern(body).inspect
    end

    def headers_snippet(request_pattern)
      return request_pattern.headers_pattern.pp_to_s if @policy.permissive?

      headers = request_pattern.headers_pattern.pattern
      redacted = @policy.redact(headers)
      return redacted.inspect unless redacted.is_a?(Hash)

      WebMock::Util::Headers.reshow_normalized_headers(redacted, "\n\t ")
    end
  end
end
