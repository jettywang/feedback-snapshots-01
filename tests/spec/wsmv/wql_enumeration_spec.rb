require 'rexml/document'
require 'winrm/wsmv/wql_query'
require 'winrm/wsmv/wql_pull'

# A transport that records the exact target of every Pull and answers from a
# script. No network or WMI access involved.
class WqlScriptedTransport
  attr_reader :requests

  def initialize(&handler)
    @handler = handler
    @requests = []
  end

  def send_request(xml)
    request = parse(xml)
    @requests << request
    @handler.call(request, @requests.length - 1)
  end

  def pulls
    @requests.select { |r| r[:context] }
  end

  private

  def parse(xml)
    doc = REXML::Document.new(xml)
    {
      xml: xml,
      action: text(doc, 'Action'),
      message_id: text(doc, 'MessageID'),
      resource_uri: text(doc, 'ResourceURI'),
      to: text(doc, 'To'),
      context: text(doc, 'EnumerationContext'),
      filter: text(doc, 'Filter')
    }
  end

  def text(doc, name)
    node = REXML::XPath.first(doc, "//*[local-name()='#{name}']")
    node && node.text
  end
end

describe 'WQL enumeration ownership' do
  let(:enum_ns) { 'http://schemas.xmlsoap.org/ws/2004/09/enumeration' }
  let(:wmi_prefix) { 'http://schemas.microsoft.com/wbem/wsman/1/wmi/' }

  let(:opts) { default_connection_opts }
  let(:endpoint_a) { 'http://host-a:5985/wsman' }
  let(:endpoint_b) { 'http://host-b:5985/wsman' }
  let(:opts_a) { opts.merge(endpoint: endpoint_a) }
  let(:opts_b) { opts.merge(endpoint: endpoint_b) }

  before { WinRM::WSMV::WqlTokenRegistry.reset_default! }

  def response(action, body, relates_to: nil)
    header = +"<s:Header><a:Action>#{action}</a:Action>"
    header << "<a:RelatesTo>#{relates_to}</a:RelatesTo>" if relates_to
    header << '</s:Header>'
    "<?xml version='1.0'?><s:Envelope" \
      " xmlns:s='http://www.w3.org/2003/05/soap-envelope'" \
      " xmlns:a='http://schemas.xmlsoap.org/ws/2004/08/addressing'" \
      " xmlns:n='#{enum_ns}'" \
      " xmlns:p='http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2'>" \
      "#{header}<s:Body>#{body}</s:Body></s:Envelope>"
  end

  def process_items(names, namespace: 'p')
    nodes = names.map do |n|
      "<#{namespace}:Win32_Process><#{namespace}:Name>#{n}</#{namespace}:Name>" \
        "</#{namespace}:Win32_Process>"
    end
    "<n:Items>#{nodes.join}</n:Items>"
  end

  def enumerate_response(context: nil, names: [], eos: false, relates_to: nil)
    body = +'<n:EnumerateResponse>'
    body << "<n:EnumerationContext>#{context}</n:EnumerationContext>" if context
    body << process_items(names) unless names.empty?
    body << '<n:EndOfSequence/>' if eos
    body << '</n:EnumerateResponse>'
    response("#{enum_ns}/EnumerateResponse", body, relates_to: relates_to)
  end

  def pull_body(context: nil, names: [], eos: false, action: "#{enum_ns}/PullResponse", extra: '')
    body = +'<n:PullResponse>'
    body << "<n:EnumerationContext>#{context}</n:EnumerationContext>" if context
    body << process_items(names) unless names.empty?
    body << '<n:EndOfSequence/>' if eos
    body << extra
    body << '</n:PullResponse>'
    response(action, body)
  end

  def pull_response_for(request, context: nil, names: [], eos: false, relates_to: nil,
                        action: "#{enum_ns}/PullResponse")
    xml = pull_body(context: context, names: names, eos: eos, action: action)
    xml.sub('<s:Header>', "<s:Header><a:RelatesTo>#{relates_to || request[:message_id]}</a:RelatesTo>")
  end

  def fault_response(code: '2150858793', message: 'The WS-Management service cannot complete the operation.')
    body = "<s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code>" \
           "<s:Reason><s:Text xml:lang='en-US'>#{message}</s:Text></s:Reason>" \
           "<s:Detail><f:WSManFault Code='#{code}'><f:Message>#{message}</f:Message>" \
           '</f:WSManFault></s:Detail></s:Fault>'
    response("#{enum_ns}/fault", body).sub(
      "xmlns:p='http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2'",
      "xmlns:p='http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2'" \
      " xmlns:f='http://schemas.microsoft.com/wbem/wsman/1/wsmanfault'"
    )
  end

  def pull_body_for(request, _host, name, eos: false)
    xml = pull_body(context: 'ctx-twin', names: [name], eos: eos)
    xml.sub('<s:Header>', "<s:Header><a:RelatesTo>#{request[:message_id]}</a:RelatesTo>")
  end

  def names(result)
    (result[:win32_process] || []).map { |row| row[:name] }
  end

  describe 'legal pagination' do
    it 'keeps every row across an empty page and a final page with data' do
      transport = WqlScriptedTransport.new do |request, index|
        # Every request on this transport is a Pull; the Enumerate response is
        # passed to process_response directly.
        case index
        when 0 then pull_body(context: 'ctx-A', names: [])
        when 1 then pull_body(context: 'ctx-A', names: %w[r3], eos: true)
        end
      end

      query = WinRM::WSMV::WqlQuery.new(transport, opts_a, 'select * from Win32_Process', 'root/cimv2')
      result = query.process_response(enumerate_response(context: 'ctx-A', names: %w[r1 r2]))

      expect(result).to be_complete
      expect(result.termination).to eq(:end_of_sequence)
      expect(names(result)).to eq(%w[r1 r2 r3])
      expect(result.row_count).to eq(3)
      expect(transport.requests.length).to eq(2)
      expect(transport.pulls.map { |p| p[:context] }).to eq(%w[ctx-A ctx-A])
      expect(transport.pulls.map { |p| p[:resource_uri] }).to all(eq("#{wmi_prefix}root/cimv2"))
      expect(transport.pulls.map { |p| p[:to] }).to all(eq(endpoint_a))
      expect(result.pull_targets.map { |t| t[:namespace] }).to all(eq('root/cimv2'))
    end

    it 'accepts EndOfSequence on the initial Enumerate without pulling' do
      transport = WqlScriptedTransport.new { |_request, _index| raise 'should not pull' }
      query = WinRM::WSMV::WqlQuery.new(transport, opts_a, 'select * from Win32_Process', 'root/cimv2')
      result = query.process_response(enumerate_response(names: %w[only], eos: true))

      expect(result).to be_complete
      expect(result.termination).to eq(:end_of_sequence_on_enumerate)
      expect(names(result)).to eq(%w[only])
      expect(transport.requests).to be_empty
      expect(query.context).to be_complete
    end

    it 'yields every delivered row to the block and reports completeness' do
      seen = []
      transport = WqlScriptedTransport.new do |_request, index|
        case index
        when 0 then pull_body(context: 'ctx-A', names: %w[r2])
        when 1 then pull_body(context: 'ctx-A', names: %w[r3], eos: true)
        end
      end

      query = WinRM::WSMV::WqlQuery.new(transport, opts_a, 'select * from Win32_Process', 'root/cimv2')
      result = query.process_response(enumerate_response(context: 'ctx-A', names: %w[r1])) do |_type, item|
        seen << item[:name]
      end

      expect(seen).to eq(%w[r1 r2 r3])
      expect(result).to be_complete
      expect(result[:win32_process]).to be_empty
      expect(result.row_count).to eq(3)
    end
  end

  describe 'incomplete results' do
    it 'does not present rows as complete when no token and no EndOfSequence are returned' do
      transport = WqlScriptedTransport.new do |_request, _index|
        pull_body(names: %w[r2])
      end
      query = WinRM::WSMV::WqlQuery.new(transport, opts_a, 'select * from Win32_Process', 'root/cimv2')

      error = nil
      begin
        query.process_response(enumerate_response(context: 'ctx-A', names: %w[r1]))
      rescue WinRM::WqlEnumerationIncompleteError => e
        error = e
      end

      expect(error).not_to be_nil
      expect(error.result).to be_incomplete
      expect(names(error.result)).to eq(%w[r1 r2])
      expect(query.context.failure_reason).to eq(:missing_context)
      expect(transport.requests.length).to eq(1)
    end

    it 'rejects an initial response that has neither a context nor EndOfSequence' do
      transport = WqlScriptedTransport.new { |_request, _index| raise 'should not pull' }
      query = WinRM::WSMV::WqlQuery.new(transport, opts_a, 'select * from Win32_Process', 'root/cimv2')

      expect do
        query.process_response(enumerate_response(names: %w[r1]))
      end.to raise_error(WinRM::WqlEnumerationIncompleteError)

      expect(transport.requests).to be_empty
    end
  end

  describe 'interleaved queries and similar tokens' do
    it 'keeps each final row set bound to its own query and endpoint' do
      # Two queries interleave on separate connections and namespaces. Both
      # use the same literal token, so the transport routes by target rather
      # than by token.
      transport_a = WqlScriptedTransport.new do |request, _index|
        pull_response_for(request, context: 'ctx-shared', names: %w[a2], eos: true)
      end
      transport_b = WqlScriptedTransport.new do |request, _index|
        pull_response_for(request, context: 'ctx-shared', names: %w[b2], eos: true)
      end

      query_a = WinRM::WSMV::WqlQuery.new(transport_a, opts_a, 'select * from Win32_Process', 'root/cimv2')
      query_b = WinRM::WSMV::WqlQuery.new(transport_b, opts_b, 'select * from Win32_OS', 'root/cimv2/foo')

      # Interleave: start both queries, then let each pull in turn. The
      # scripted transports answer the interleaved Pulls without any shared
      # state beyond the target recorded on each request.
      result_a = query_a.process_response(enumerate_response(context: 'ctx-shared', names: %w[a1]))
      result_b = query_b.process_response(enumerate_response(context: 'ctx-shared', names: %w[b1]))

      expect(names(result_a)).to eq(%w[a1 a2])
      expect(names(result_b)).to eq(%w[b1 b2])
      expect(result_a.endpoint).to eq(endpoint_a)
      expect(result_b.endpoint).to eq(endpoint_b)
      expect(result_a.query_id).not_to eq(result_b.query_id)

      pulls_a = result_a.pull_targets
      pulls_b = result_b.pull_targets
      expect(pulls_a.map { |t| t[:endpoint] }).to all(eq(endpoint_a))
      expect(pulls_b.map { |t| t[:endpoint] }).to all(eq(endpoint_b))
      expect(pulls_a.map { |t| t[:resource_uri] }).to all(eq("#{wmi_prefix}root/cimv2"))
      expect(pulls_b.map { |t| t[:resource_uri] }).to all(eq("#{wmi_prefix}root/cimv2/foo"))
      expect(transport_a.pulls.map { |p| [p[:to], p[:context]] }).to eq([[endpoint_a, 'ctx-shared']])
      expect(transport_b.pulls.map { |p| [p[:to], p[:context]] }).to eq([[endpoint_b, 'ctx-shared']])
    end

    it 'refuses a token that another live query already owns on the same endpoint' do
      query_a = WinRM::WSMV::WqlQuery.new(WqlScriptedTransport.new, opts_a, 'select * from A', 'root/cimv2')
      transport_b = WqlScriptedTransport.new do |_request, _index|
        raise 'query B must never reach the wire with a token owned by query A'
      end
      query_b = WinRM::WSMV::WqlQuery.new(transport_b, opts_a, 'select * from B', 'root/cimv2')

      # Query A is genuinely mid-enumeration: it has received its context but
      # has not pulled yet, so the token is live and owned by A.
      query_a.context.bind_initial('ctx-similar')

      expect do
        query_b.process_response(enumerate_response(context: 'ctx-similar', names: %w[b1]))
      end.to raise_error(WinRM::WqlContextMismatchError, /belongs to/)

      expect(query_a.context).to be_active
      expect(query_b.context).to be_failed
      expect(query_b.context.failure_reason).to eq(:mismatched_response)
      expect(transport_b.requests).to be_empty
    end

    it 'scopes identical tokens by endpoint' do
      transport = WqlScriptedTransport.new do |request, _index|
        pull_response_for(request, context: 'ctx-1', eos: true)
      end

      query_a = WinRM::WSMV::WqlQuery.new(transport, opts_a, 'select * from A', 'root/cimv2')
      query_b = WinRM::WSMV::WqlQuery.new(transport, opts_b, 'select * from B', 'root/cimv2')

      expect { query_a.process_response(enumerate_response(context: 'ctx-1')) }.not_to raise_error
      expect { query_b.process_response(enumerate_response(context: 'ctx-1')) }.not_to raise_error
    end

    it 'interleaves two live queries with identical tokens without crossing rows' do
      # One router answers by the Pull target. Both queries use the same
      # literal token and the same namespace, but different endpoints, so any
      # misassociation would surface as rows from the wrong host.
      log = []
      counts = Hash.new(0)
      lock = Mutex.new
      router = lambda do |request, _index|
        host = request[:to].include?('host-a') ? 'a' : 'b'
        pull_index = lock.synchronize do
          log << [host, request[:resource_uri], request[:context]]
          counts[host] += 1
        end
        sleep 0.01
        if pull_index == 1
          pull_body_for(request, host, "#{host}2")
        else
          pull_body_for(request, host, "#{host}3", eos: true)
        end
      end
      transport = WqlScriptedTransport.new(&router)

      query_a = WinRM::WSMV::WqlQuery.new(transport, opts_a, 'select * from A', 'root/cimv2')
      query_b = WinRM::WSMV::WqlQuery.new(transport, opts_b, 'select * from B', 'root/cimv2')

      results = {}
      threads = { a: query_a, b: query_b }.map do |key, query|
        Thread.new do
          results[key] = query.process_response(
            enumerate_response(context: 'ctx-twin', names: ["#{key}1"])
          )
        end
      end
      threads.each(&:join)

      expect(names(results[:a])).to eq(%w[a1 a2 a3])
      expect(names(results[:b])).to eq(%w[b1 b2 b3])
      expect(results[:a].endpoint).to eq(endpoint_a)
      expect(results[:b].endpoint).to eq(endpoint_b)
      expect(results[:a].pull_targets.map { |t| t[:endpoint] }).to all(eq(endpoint_a))
      expect(results[:b].pull_targets.map { |t| t[:endpoint] }).to all(eq(endpoint_b))

      pulls_a = transport.pulls.select { |p| p[:to] == endpoint_a }
      pulls_b = transport.pulls.select { |p| p[:to] == endpoint_b }
      expect(pulls_a.length).to eq(2)
      expect(pulls_b.length).to eq(2)
      expect(pulls_a.map { |p| p[:context] }).to all(eq('ctx-twin'))
      expect(pulls_b.map { |p| p[:context] }).to all(eq('ctx-twin'))

      # The actual targets recorded by the transport prove no Pull crossed
      # hosts, even though both queries saw the same literal token.
      expect(log.map(&:first)).to contain_exactly('a', 'a', 'b', 'b')
      expect(log.map { |entry| entry[1] }).to all(eq("#{wmi_prefix}root/cimv2"))
    end
  end

  describe 'mismatched responses' do
    it 'does not credit rows from a response addressed to another request' do
      transport = WqlScriptedTransport.new do |request, _index|
        pull_response_for(request, context: 'ctx-A', names: %w[foreign], relates_to: 'uuid:SOMEONE-ELSE')
      end
      query = WinRM::WSMV::WqlQuery.new(transport, opts_a, 'select * from Win32_Process', 'root/cimv2')

      error = nil
      begin
        query.process_response(enumerate_response(context: 'ctx-A', names: %w[mine]))
      rescue WinRM::WqlContextMismatchError => e
        error = e
      end

      expect(error).not_to be_nil
      expect(error.message).to include('relates to')
      expect(names(error.result)).to eq(%w[mine])
      expect(error.result).to be_incomplete
      expect(query.context.failure_reason).to eq(:mismatched_response)
    end

    it 'rejects a response with a pull action when an enumerate response is expected' do
      query = WinRM::WSMV::WqlQuery.new(WqlScriptedTransport.new, opts_a, 'select * from A', 'root/cimv2')
      expect do
        query.process_response(pull_body(context: 'ctx-A', names: %w[x]))
      end.to raise_error(WinRM::WqlContextMismatchError, /expected enumerate response/)
    end

    it 'rejects a pulled page whose token belongs to another live query before ingesting rows' do
      owner = WinRM::WSMV::WqlQuery.new(WqlScriptedTransport.new, opts_a, 'select * from A', 'root/cimv2')
      owner.context.bind_initial('ctx-owned')

      transport = WqlScriptedTransport.new do |request, _index|
        pull_response_for(request, context: 'ctx-owned', names: %w[leaked])
      end
      victim = WinRM::WSMV::WqlQuery.new(transport, opts_a, 'select * from B', 'root/cimv2')

      error = nil
      begin
        victim.process_response(enumerate_response(context: 'ctx-victim', names: %w[mine]))
      rescue WinRM::WqlContextMismatchError => e
        error = e
      end

      expect(error).not_to be_nil
      expect(error.message).to include('belongs to')
      expect(names(error.result)).to eq(%w[mine])
      expect(error.result).to be_incomplete
      expect(victim.context.failure_reason).to eq(:mismatched_response)
    end

    it 'does not allow a Pull to be built for another query context or namespace' do
      query_a = WinRM::WSMV::WqlQuery.new(WqlScriptedTransport.new, opts_a, 'select * from A', 'root/cimv2')
      query_a.process_response(enumerate_response(context: 'ctx-A', eos: true))

      context = WinRM::WSMV::WqlEnumerationContext.new(
        endpoint: endpoint_a, namespace: 'root/cimv2', registry: WinRM::WSMV::WqlTokenRegistry.new
      )
      context.bind_initial('ctx-A')

      expect do
        WinRM::WSMV::WqlPull.new(opts_b, 'root/cimv2', 'ctx-A', context: context)
      end.to raise_error(WinRM::WqlContextMismatchError, /endpoint/)

      expect do
        WinRM::WSMV::WqlPull.new(opts_a, 'root/cimv2/other', 'ctx-A', context: context)
      end.to raise_error(WinRM::WqlContextMismatchError, /namespace/)

      expect do
        WinRM::WSMV::WqlPull.new(opts_a, 'root/cimv2', 'ctx-other', context: context)
      end.to raise_error(WinRM::WqlContextMismatchError, /current token/)
    end
  end

  describe 'bounded loops' do
    it 'stops a repeated empty page after the no-progress budget' do
      transport = WqlScriptedTransport.new do |request, _index|
        pull_response_for(request, context: 'ctx-A', names: [])
      end
      query = WinRM::WSMV::WqlQuery.new(transport, opts_a, 'select * from A', 'root/cimv2')

      error = nil
      begin
        query.process_response(enumerate_response(context: 'ctx-A', names: %w[r1]))
      rescue WinRM::WqlEnumerationStalledError => e
        error = e
      end

      expect(error).not_to be_nil
      expect(names(error.result)).to eq(%w[r1])
      expect(error.result.termination).to eq(:stalled)
      # Ten empty pages with the same token exhaust the default budget.
      expect(transport.requests.length).to eq(10)
      expect(query.context.failure_reason).to eq(:stalled)
    end

    it 'stops replaying the same page even when rows are present' do
      transport = WqlScriptedTransport.new do |request, _index|
        pull_response_for(request, context: 'ctx-A', names: %w[dup])
      end
      query = WinRM::WSMV::WqlQuery.new(transport, opts_a, 'select * from A', 'root/cimv2')

      error = nil
      begin
        query.process_response(enumerate_response(context: 'ctx-A', names: %w[r1]))
      rescue WinRM::WqlEnumerationStalledError => e
        error = e
      end

      expect(error).not_to be_nil
      expect(names(error.result)).to eq(%w[r1 dup])
      # The initial page plus ten identical replays all count as Pulls.
      expect(transport.requests.length).to eq(11)
      expect(error.result).to be_incomplete
    end

    it 'bounds servers that keep minting fresh empty contexts' do
      transport = WqlScriptedTransport.new do |request, index|
        pull_response_for(request, context: "ctx-#{index}", names: [])
      end
      query = WinRM::WSMV::WqlQuery.new(transport, opts_a, 'select * from A', 'root/cimv2')
      context = query.context
      # Rebuild the context with a small ceiling so the test stays fast.
      query.instance_variable_set(
        :@context,
        WinRM::WSMV::WqlEnumerationContext.new(
          endpoint: endpoint_a, namespace: 'root/cimv2', wql: 'select * from A', max_pulls: 5
        )
      )
      context = query.context

      expect do
        query.process_response(enumerate_response(context: 'ctx-seed', names: %w[r1]))
      end.to raise_error(WinRM::WqlEnumerationLimitError)

      expect(transport.requests.length).to eq(5)
      expect(context.failure_reason).to eq(:pull_limit)
    end
  end

  describe 'faults mid-enumeration' do
    it 'retains received rows but marks the result incomplete on a SOAP fault' do
      transport = WqlScriptedTransport.new do |request, index|
        # First Pull delivers a row, the next Pull faults mid-enumeration.
        if index.zero?
          pull_response_for(request, context: 'ctx-A', names: %w[r2])
        else
          fault_response
        end
      end
      query = WinRM::WSMV::WqlQuery.new(transport, opts_a, 'select * from A', 'root/cimv2')

      error = nil
      begin
        query.process_response(enumerate_response(context: 'ctx-A', names: %w[r1]))
      rescue WinRM::WqlEnumerationFailedError => e
        error = e
      end

      expect(error).not_to be_nil
      expect(error.message).to include('2150858793')
      expect(names(error.result)).to eq(%w[r1 r2])
      expect(error.result).to be_incomplete
      expect(error.result.termination).to eq(:fault)
      expect(query.context.failure_reason).to eq(:fault)
      expect(transport.pulls.length).to eq(2)
    end

    it 'wraps transport exceptions with the pull target and original cause' do
      transport = WqlScriptedTransport.new do |request, _index|
        raise WinRM::WinRMWSManFault.new('transport blew up', '2150858793') if request

        pull_response_for(request, context: 'ctx-A', names: %w[r2])
      end
      query = WinRM::WSMV::WqlQuery.new(transport, opts_a, 'select * from A', 'root/cimv2')

      error = nil
      begin
        query.process_response(enumerate_response(context: 'ctx-A', names: %w[r1]))
      rescue WinRM::WqlEnumerationFailedError => e
        error = e
      end

      expect(error).not_to be_nil
      expect(error.cause).to be_a(WinRM::WinRMWSManFault)
      expect(error.message).to include('endpoint=http://host-a:5985/wsman')
      expect(error.message).to include('namespace=root/cimv2')
      expect(names(error.result)).to eq(%w[r1])
      expect(error.result).to be_incomplete
    end
  end

  describe 'Connection#run_wql' do
    let(:connection) { WinRM::Connection.new(default_connection_opts) }

    it 'returns a result that reports completeness and the pulled targets' do
      transport = WqlScriptedTransport.new do |request, index|
        if index.zero?
          enumerate_response(context: 'ctx-A', names: %w[r1])
        else
          pull_response_for(request, context: 'ctx-A', names: %w[r2], eos: true)
        end
      end
      allow(connection).to receive(:transport).and_return(transport)

      result = connection.run_wql('select * from Win32_Process')

      expect(result).to be_a(WinRM::WSMV::WqlResult)
      expect(result).to be_complete
      expect(result[:win32_process].map { |row| row[:name] }).to eq(%w[r1 r2])
      expect(result.pull_targets.length).to eq(1)
      expect(transport.pulls.first[:to]).to eq(default_connection_opts[:endpoint])
    end

    it 'raises with retained rows when the enumeration never terminates' do
      transport = WqlScriptedTransport.new do |request, index|
        if index.zero?
          enumerate_response(context: 'ctx-A', names: %w[r1])
        else
          pull_body(context: 'ctx-A', names: [])
        end
      end
      allow(connection).to receive(:transport).and_return(transport)

      error = nil
      begin
        connection.run_wql('select * from Win32_Process')
      rescue WinRM::WqlEnumerationStalledError => e
        error = e
      end

      expect(error).not_to be_nil
      expect(error.result).to be_incomplete
      expect(error.result[:win32_process].map { |row| row[:name] }).to eq(%w[r1])
    end
  end

  describe 'query instance reuse' do
    it 'refuses to run a second enumeration on the same query instance' do
      transport = WqlScriptedTransport.new do |request, _index|
        pull_response_for(request, context: 'ctx-A', eos: true)
      end
      query = WinRM::WSMV::WqlQuery.new(transport, opts_a, 'select * from A', 'root/cimv2')

      expect(query.process_response(enumerate_response(context: 'ctx-A'))).to be_complete

      expect do
        query.process_response(enumerate_response(context: 'ctx-A'))
      end.to raise_error(WinRM::WqlContextMismatchError, /already complete/)
    end
  end

  describe 'WqlPull binding' do
    it 'builds the pull for the bound endpoint, resource URI and token' do
      transport = WqlScriptedTransport.new do |request, _index|
        pull_response_for(request, context: 'ctx-A', eos: true)
      end
      query = WinRM::WSMV::WqlQuery.new(transport, opts_a, 'select * from A', 'root/cimv2')
      query.process_response(enumerate_response(context: 'ctx-A'))

      pull = transport.pulls.first
      expect(pull[:to]).to eq(endpoint_a)
      expect(pull[:resource_uri]).to eq("#{wmi_prefix}root/cimv2")
      expect(pull[:context]).to eq('ctx-A')
      expect(pull[:message_id]).to match(/\Auuid:/)
    end
  end
end
