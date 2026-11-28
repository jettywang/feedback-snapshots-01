# frozen_string_literal: true

module WebMock
  class RackResponse < Response
    def initialize(app)
      @app = app
    end

    def evaluate(request)
      env = build_rack_env(request)

      status, headers, response = @app.call(env)
      segments = segments_from_rack_response(response)

      evaluated = Response.new(
        body: join_segments(segments),
        headers: headers,
        status: [status, Rack::Utils::HTTP_STATUS_CODES[status]]
      )
      evaluated.delivery_segments = segments
      evaluated.replay_source = :rack
      evaluated
    end

    def body_from_rack_response(response)
      join_segments(segments_from_rack_response(response))
    end

    def join_segments(segments)
      segments.inject("".dup) { |body, segment| body << segment }
    end

    # Keeps the body chunks the Rack app yielded, so a replay version can
    # record what the app produced and a receipt can record which of those
    # chunks the client actually received.
    def segments_from_rack_response(response)
      segments = []
      response.each { |line| segments << line.to_s }
      response.close if response.respond_to?(:close)
      segments
    end

    def build_rack_env(request)
      uri = request.uri
      port = uri.inferred_port
      headers = (request.headers || {}).dup
      body = (request.body || '').b
      content_type = headers.delete('Content-Type')
      headers.delete('Content-Length')
      # The body is already decoded, as a server passes it on.
      headers.delete('Transfer-Encoding')

      env = {
        # CGI variables specified by Rack
        'REQUEST_METHOD'  => request.method.to_s.upcase,
        'CONTENT_LENGTH'  => body.bytesize.to_s,
        'PATH_INFO'       => uri.path,
        'QUERY_STRING'    => uri.query || '',
        'SERVER_NAME'     => uri.host,
        'SERVER_PORT'     => port.to_s,
        'SERVER_PROTOCOL' => 'HTTP/1.1',
        'SCRIPT_NAME'     => ""
      }
      env['CONTENT_TYPE'] = header_value('Content-Type', content_type) if content_type

      env['HTTP_AUTHORIZATION'] = 'Basic ' + [uri.userinfo].pack('m').delete("\r\n") if uri.userinfo

      # Rack-specific variables
      env['rack.input']      = StringIO.new(body)
      env['rack.errors']     = $stderr
      if !Rack.const_defined?(:RELEASE) || Gem::Version.new(Rack::RELEASE) < Gem::Version.new("3")
        env['rack.version']      = Rack::VERSION
        env['rack.multithread']  = false
        env['rack.multiprocess'] = false
      end
      env['rack.url_scheme'] = uri.scheme
      env['rack.run_once']   = true

      headers.each do |k, v|
        env["HTTP_#{k.tr('-','_').upcase}"] = header_value(k, v)
      end

      # Many clients add Host only when sending, so fill it in as they would.
      env['HTTP_HOST'] ||= port == uri.default_port ? uri.host : "#{uri.host}:#{port}"

      env
    end

    private

    # Like a server, pass header values as bytes and join repeated ones. Rack
    # splits cookies on "; ", so join those that way.
    def header_value(name, value)
      Array(value).map { |v| v.to_s.b }.join(name == 'Cookie' ? '; ' : WebMock::Util::Headers::JOIN)
    end
  end
end
