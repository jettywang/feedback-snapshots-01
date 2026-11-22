require_relative "../spec_helper"

describe "json_parse_budget plugin" do
  # Rack input that records reads and closes, so specs can verify the
  # plugin consumes the body in a bounded way and cleans up the stream.
  class JsonParseBudgetRecordingInput
    attr_reader :reads, :closed_at, :bytes_read

    def initialize(str)
      @str = str.dup.force_encoding('BINARY')
      @pos = 0
      @reads = []
      @bytes_read = 0
      @closed = false
      @closed_at = nil
    end

    def read(length=nil, buffer=nil)
      @reads << length
      raise IOError, "closed stream" if @closed

      if length.nil?
        data = @str[@pos..-1]
      else
        data = @str[@pos, length]
      end

      if data.nil? || data.empty?
        data = length.nil? ? String.new : nil
      else
        @pos += data.bytesize
        @bytes_read += data.bytesize
      end

      if buffer
        buffer.replace(data || '')
        data = buffer
      end

      data
    end

    def gets
      raise IOError, "closed stream" if @closed
      line = @str[@pos..-1]
      return nil if line.nil? || line.empty?
      @pos = @str.length
      @bytes_read += line.bytesize
      line
    end

    def each
      while (line = gets)
        yield line
      end
    end

    def close
      @closed = true
      @closed_at ||= @reads.length
      nil
    end

    def closed?
      @closed
    end

    def rewind
      @pos = 0
      nil
    end
  end

  def budget_app(opts = {}, &route_block)
    app(:bare) do
      plugin :json_parse_budget, **opts
      route(&route_block)
    end
  end

  def json_env(input, headers = {})
    {"REQUEST_METHOD"=>"POST", "CONTENT_TYPE"=>"application/json", "rack.input"=>input}.merge(headers)
  end

  def recording_input(str)
    JsonParseBudgetRecordingInput.new(str)
  end

  it "keeps the ordinary json_parser plugin behavior without the budget" do
    app(:bare) do
      plugin :json_parser, content_type_regexp: /\Aapplication\/json\b/i
      route do |r|
        r.params['a']['b'].to_s
      end
    end

    body(json_env(recording_input('{"a":{"b":1}}'))).must_equal '1'
  end

  it "keeps ordinary requests working without changing the json parser defaults" do
    budget_app do |r|
      value = r.parse_json_budget!
      value['a']['b'].to_s
    end

    input = recording_input('{"a":{"b":1}}')
    body(json_env(input)).must_equal '1'
    input.bytes_read.must_equal 13
    input.reads.each{|n| n.must_be :<=, 65537}
  end

  it "can be called without a receiver from the route block scope" do
    budget_app do |r|
      value = parse_json_budget!
      value['a'].to_s
    end

    body(json_env(recording_input('{"a":1}'))).must_equal '1'
  end

  it "accepts a per-route budget smaller than the global default" do
    budget_app do |r|
      r.parse_json_budget!(max_bytes: 8)
      r.params['a'].to_s
    end

    body(json_env(recording_input('{"a":1}'))).must_equal '1'
  end

  it "rejects bodies over the byte budget with 413 and a public diagnostic" do
    budget_app(max_bytes: 8) do |r|
      r.parse_json_budget! if r.post?
      'unreachable'
    end

    input = recording_input('{"a":1234567890}')
    res = req(json_env(input))
    res[0].must_equal 413
    res[1][RodaResponseHeaders::CONTENT_TYPE].must_equal 'application/json'

    diagnostic = JSON.parse(res[2].join)
    diagnostic['reason'].must_equal 'too_large'
    diagnostic['limit'].must_equal 8
    diagnostic['bytes'].must_be :>, 8
    diagnostic.keys.sort.must_equal %w'bytes limit max_depth reason'

    input.closed?.must_equal true
    input.bytes_read.must_equal 9
    input.reads.each{|n| n.must_be :<=, 9}
  end

  it "rejects bodies over the byte budget based on Content-Length without reading" do
    budget_app(max_bytes: 8) do |r|
      r.parse_json_budget!
    end

    input = recording_input('{"a":1234567890}')
    res = req(json_env(input, 'CONTENT_LENGTH'=>'15'))
    res[0].must_equal 413
    input.reads.must_equal []
    input.closed?.must_equal true
    JSON.parse(res[2].join)['bytes'].must_equal 15
  end

  it "rejects overly nested documents with 413 and closes the input" do
    budget_app(max_depth: 2) do |r|
      r.parse_json_budget!
    end

    input = recording_input('[[[1]]]')
    res = req(json_env(input))
    res[0].must_equal 413
    diagnostic = JSON.parse(res[2].join)
    diagnostic['reason'].must_equal 'too_deep'
    diagnostic['max_depth'].must_equal 2
    input.closed?.must_equal true
  end

  it "handles empty bodies like the json_parser plugin" do
    budget_app do |r|
      r.parse_json_budget!
      r.POST.length.to_s
    end

    input = recording_input('')
    body(json_env(input)).must_equal '0'
  end

  it "honors a custom parser that accepts the request via include_request" do
    app(:bare) do
      plugin :json_parser,
        include_request: true,
        parser: lambda{|body, req, **| {'body'=>body, 'path'=>req.path_info}},
        content_type_regexp: /\Aapplication\/json\b/i
      plugin :json_parse_budget
      route do |r|
        value = r.parse_json_budget!
        "#{value['body']}:#{value['path']}"
      end
    end

    body(json_env(recording_input('{}'))).must_equal '{}:/'
  end

  it "works with a parser that does not accept max_nesting" do
    app(:bare) do
      plugin :json_parser,
        parser: lambda{|body| JSON.parse(body)},
        content_type_regexp: /\Aapplication\/json\b/i
      plugin :json_parse_budget, max_depth: 2
      route do |r|
        r.parse_json_budget!
        'ok'
      end
    end

    body(json_env(recording_input('{"a":1}'))).must_equal 'ok'

    res = req(json_env(recording_input('[[[1]]]')))
    res[0].must_equal 413
    JSON.parse(res[2].join)['reason'].must_equal 'too_deep'
  end

  it "rejects conversion errors with 400 and a stable reason" do
    parser = proc do |body|
      raise TypeError, "object_class cannot convert #{body}"
    end

    app(:bare) do
      plugin :json_parser, parser: parser, content_type_regexp: /\Aapplication\/json\b/i
      plugin :json_parse_budget
      route do |r|
        r.parse_json_budget!
      end
    end

    input = recording_input('{"a":1}')
    res = req(json_env(input))
    res[0].must_equal 400
    diagnostic = JSON.parse(res[2].join)
    diagnostic['reason'].must_equal 'conversion_error'
    diagnostic.keys.sort.must_equal %w'limit max_depth reason'
    res[2].join.wont_match(/object_class|convert|\{"a":1\}/)
    input.closed?.must_equal true
  end

  it "rejects invalid JSON with 400 and does not leak parser messages" do
    budget_app do |r|
      r.parse_json_budget!
    end

    input = recording_input('{"a":')
    res = req(json_env(input))
    res[0].must_equal 400
    diagnostic = JSON.parse(res[2].join)
    diagnostic['reason'].must_equal 'invalid_json'
    res[2].join.wont_match(/unexpected|token|parse|syntax/i)
    input.closed?.must_equal true
  end

  it "records rejection diagnostics through on_reject without request content" do
    events = []
    budget_app(max_bytes: 8, on_reject: proc{|r, d| events << d}) do |r|
      r.parse_json_budget!
    end

    input = recording_input('{"secret":"top-secret-value"}')
    req(json_env(input))
    events.length.must_equal 1
    events[0][:reason].must_equal :too_large
    events[0].inspect.wont_match(/secret|top-secret-value/)
    input.closed?.must_equal true
  end

  it "allows the audit callback to be supplied per route" do
    events = []
    budget_app do |r|
      r.parse_json_budget!(on_reject: proc{|_, d| events << d[:reason]})
    end

    req(json_env(recording_input('{"a":')))
    events.must_equal [:invalid_json]
  end

  it "keeps the rejection response even if the audit callback raises" do
    budget_app(on_reject: proc{|_, _| raise "audit failure"}) do |r|
      r.parse_json_budget!
    end

    res = req(json_env(recording_input('{"a":')))
    res[0].must_equal 400
  end

  it "does not add an event for a following successful request" do
    events = []
    budget_app(max_bytes: 8, on_reject: proc{|_, d| events << d}) do |r|
      r.parse_json_budget!
      r.params['a'].to_s
    end

    req(json_env(recording_input('{"a":1234567890}')))
    events.length.must_equal 1

    body(json_env(recording_input('{"a":1}'))).must_equal '1'
    events.length.must_equal 1
  end

  it "exposes the diagnostic during the audit callback" do
    seen = []
    budget_app(on_reject: proc{|r, d| seen << r.json_parse_budget_diagnostic}) do |r|
      r.parse_json_budget!
    end

    req(json_env(recording_input('{"a":')))
    seen.length.must_equal 1
    seen[0].must_equal({reason: :invalid_json, limit: 65536, max_depth: 64})
  end

  it "does not affect routes that do not opt into the budget" do
    budget_app do |r|
      r.post 'admin' do
        r.parse_json_budget!
      end
      r.post 'plain' do
        'plain'
      end
    end

    body('/plain', json_env(recording_input('{"a":1}'))).must_equal 'plain'
  end

  it "leaves the json_parser defaults alone for non-JSON content types" do
    budget_app do |r|
      r.parse_json_budget!
      'plain'
    end

    input = recording_input('a[b]=1')
    body(json_env(input, 'CONTENT_TYPE'=>'application/x-www-form-urlencoded')).must_equal 'plain'
    input.closed?.must_equal false
  end

  it "allows the next request to parse normally after a rejection" do
    budget_app(max_bytes: 8) do |r|
      r.parse_json_budget!
      r.params['a'].to_s
    end

    res = req(json_env(recording_input('{"a":1234567890}')))
    res[0].must_equal 413

    input = recording_input('{"a":1}')
    body(json_env(input)).must_equal '1'
    input.reads.each{|n| n.must_be :<=, 9}
  end

  it "does not leave a parsed body behind after a rejection" do
    app(:bare) do
      plugin :json_parse_budget, max_depth: 2
      route do |r|
        r.parse_json_budget!
      end
    end

    env = json_env(recording_input('[[[1]]]'))
    req(env)[0].must_equal 413
    env.wont_include 'roda.json_params'
    env['rack.input'].closed?.must_equal true
  end

  it "supports wrap :unless_hash via the json_parser plugin" do
    app(:bare) do
      plugin :json_parser, wrap: :unless_hash, content_type_regexp: /\Aapplication\/json\b/i
      plugin :json_parse_budget
      route do |r|
        value = r.parse_json_budget!
        value['_json'][0].to_s
      end
    end

    body(json_env(recording_input('[1]'))).must_equal '1'
  end

  it "rejects when json_parser already parsed a document deeper than the budget" do
    app(:bare) do
      plugin :json_parser, content_type_regexp: /\Aapplication\/json\b/i
      plugin :json_parse_budget, max_depth: 2
      route do |r|
        r.POST
        r.parse_json_budget!
      end
    end

    input = recording_input('[[[1]]]')
    res = req(json_env(input))
    res[0].must_equal 413
    JSON.parse(res[2].join)['reason'].must_equal 'too_deep'
  end

  it "supports check_json_parse_budget! without a receiver" do
    budget_app do |r|
      check_json_parse_budget!
      'ok'
    end

    body(json_env(recording_input('{"a":1}'))).must_equal 'ok'
  end

  it "allows a per-route status and content type" do
    budget_app do |r|
      r.parse_json_budget!(max_bytes: 2, status: 400, content_type: 'application/problem+json')
    end

    res = req(json_env(recording_input('{"a":1}')))
    res[0].must_equal 400
    res[1][RodaResponseHeaders::CONTENT_TYPE].must_equal 'application/problem+json'
    JSON.parse(res[2].join)['reason'].must_equal 'too_large'
  end

  it "supports a single-argument audit callback" do
    events = []
    budget_app(on_reject: proc{|d| events << d[:reason]}) do |r|
      r.parse_json_budget!
    end

    req(json_env(recording_input('{"a":')))
    events.must_equal [:invalid_json]
  end

  it "raises for invalid limits and statuses" do
    proc{budget_app(max_bytes: 0)}.must_raise Roda::RodaError
    proc{budget_app(max_depth: -1)}.must_raise Roda::RodaError
    proc{budget_app(status: 200)}.must_raise Roda::RodaError
    budget_app do |r|
      proc{r.parse_json_budget!(max_bytes: 0)}.must_raise Roda::RodaError
      'ok'
    end
    body.must_equal 'ok'
  end
end
