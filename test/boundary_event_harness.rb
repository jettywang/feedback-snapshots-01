# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

# BoundaryEventHarness records *boundary events* around WebMock-guarded HTTP
# adapters, so that security review can distinguish four moments that the
# legacy regression ("did the client call raise?") cannot:
#
#   1. connection_intent   - the client planned a connection (recorded by the
#                            harness itself, kept as its own event kind)
#   2. boundary_invocation - the client actually called the adapter's
#                            connection boundary (recorded by a test double
#                            only; the double never alters behaviour)
#   3. adjudication        - WebMock allowed or denied the request (observed
#                            through public configuration only)
#   4. completion_callback - WebMock.after_request fired
#
# The whole harness is offline: allowed traffic is served by WebMock stubs,
# denied traffic is rejected by WebMock before any socket is opened.
#
# See test/boundary_event_harness.md for the evidence analysis and for how
# the two adapters scheduled for upgrade plug into the same suite.
module BoundaryEventHarness
  EVENT_KINDS = %i[
    connection_intent
    boundary_invocation
    adjudication
    completion_callback
  ].freeze

  # Raised by client code that cancels before request construction.
  ClientCancelled = Class.new(StandardError)

  Event = Struct.new(:seq, :record_id, :kind, :detail) do
    def to_h
      {
        'seq' => seq,
        'record_id' => record_id,
        'kind' => kind.to_s,
        'detail' => detail
      }
    end
  end

  # Append-only, in-memory event log. Records are plain data and round-trip
  # through JSON, so a captured session can be replayed and re-analysed
  # offline.
  #
  # Events are only attributed to a request record while that record is open.
  # Anything emitted before a record is opened or after it is closed (for
  # example calls made before a test double is registered or after it is
  # unregistered) lands in the quarantine list and can never mix into a
  # request record.
  class EventLog
    attr_reader :events, :quarantine

    def initialize
      @events = []
      @quarantine = []
      @open_record_id = nil
      @seq = 0
    end

    def open_record(record_id)
      raise "another record is already open: #{@open_record_id}" if @open_record_id
      @open_record_id = record_id
    end

    def close_record
      @open_record_id = nil
    end

    def recording?
      !@open_record_id.nil?
    end

    def emit(kind, detail = {})
      kind = kind.to_sym
      raise "unknown event kind: #{kind}" unless EVENT_KINDS.include?(kind)
      @seq += 1
      event = Event.new(@seq, @open_record_id, kind, detail)
      recording? ? @events << event : @quarantine << event
      event
    end

    def record(record_id)
      @events.select { |event| event.record_id == record_id }
    end

    def kinds_for(record_id)
      record(record_id).map(&:kind)
    end

    def adjudication_for(record_id)
      event = record(record_id).find { |e| e.kind == :adjudication }
      event && event.detail['verdict']
    end

    # Derived, replayable verdicts: one entry per request record.
    def verdicts
      @events.group_by(&:record_id).map do |record_id, events|
        {
          'record_id' => record_id,
          'kinds' => events.map { |e| e.kind.to_s },
          'adjudication' => adjudication_for(record_id)
        }
      end
    end

    def to_h
      {
        'events' => @events.map(&:to_h),
        'quarantine' => @quarantine.map(&:to_h)
      }
    end

    def to_json(*args)
      to_h.to_json(*args)
    end

    def self.from_h(hash)
      log = new
      hash.fetch('events').each { |attrs| log.send(:restore, attrs, log.events) }
      hash.fetch('quarantine').each { |attrs| log.send(:restore, attrs, log.quarantine) }
      log
    end

    def self.from_json(json)
      from_h(JSON.parse(json))
    end

    protected

    def restore(attrs, target)
      event = Event.new(attrs['seq'], attrs['record_id'], attrs['kind'].to_sym, attrs['detail'])
      target << event
      @seq = [@seq, event.seq].max
    end
  end

  # Test double that records invocations of an adapter's connection boundary.
  # It is the only component allowed to emit :boundary_invocation events, and
  # only while armed (i.e. registered inside an open request record).
  class BoundaryDouble
    def initialize(log, boundary_label)
      @log = log
      @boundary_label = boundary_label
      @armed = false
    end

    def arm!
      @armed = true
    end

    def disarm!
      @armed = false
    end

    def armed?
      @armed
    end

    def invoked(detail = {})
      return unless armed?
      @log.emit(:boundary_invocation, { 'boundary' => @boundary_label }.merge(detail))
    end
  end

  # Evidence available from WebMock's public configuration, shared by every
  # adapter: a WebMock.after_request callback is the completion signal and
  # the first public signal that adjudication allowed the request.
  def self.install_webmock_evidence(log)
    WebMock.after_request do |request_signature, response|
      log.emit(:adjudication, {
        'verdict' => 'allowed',
        'observed_via' => 'WebMock.after_request (CallbackRegistry)'
      })
      log.emit(:completion_callback, {
        'method' => request_signature.method.to_s.upcase,
        'uri' => request_signature.uri.to_s,
        'status' => Array(response.status).first
      })
    end
  end

  # An adapter probe is the extension point that lets this harness run
  # unchanged against the two adapters scheduled for upgrade. A probe only
  # needs to expose the adapter's connection boundary through public client
  # behaviour:
  #
  #   boundary_label                       -> String naming the guarded boundary
  #   build_connection(uri_string)         -> [connection, uri]
  #   attach_double(connection, double)    -> attaches the recording double
  #   perform(connection, uri, method, body:, headers:) -> response
  #
  # Register upgraded adapters with BoundaryEventHarness.register_probe and
  # run the same scenario suite against them.
  class NetHttpProbe
    def boundary_label
      'net_http#request'
    end

    def build_connection(uri_string)
      uri = URI.parse(uri_string)
      connection = Net::HTTP.new(uri.host, uri.port)
      connection.use_ssl = true if uri.scheme == 'https'
      [connection, uri]
    end

    def attach_double(connection, double)
      recorder = Module.new do
        define_method(:request) do |request, body = nil, &block|
          double.invoked(
            'method' => request.method,
            'path' => request.path
          )
          super(request, body, &block)
        end
      end
      connection.singleton_class.prepend(recorder)
      connection
    end

    def perform(connection, uri, method, body: nil, headers: {})
      request_class = Net::HTTP.const_get(method.to_s.capitalize)
      request = request_class.new(uri.request_uri, headers)
      connection.start { |session| session.request(request, body) }
    end
  end

  @probes = {}

  def self.register_probe(name, probe)
    @probes[name.to_sym] = probe
  end

  def self.probe(name)
    @probes.fetch(name.to_sym) do
      raise ArgumentError,
        "no probe registered for #{name.inspect}; register one with " \
        "BoundaryEventHarness.register_probe (see test/boundary_event_harness.md)"
    end
  end

  register_probe(:net_http, NetHttpProbe.new)

  # The client-facing handle yielded to scenario client code.
  class ClientContext
    def initialize(probe, connection, uri)
      @probe = probe
      @connection = connection
      @uri = uri
    end

    def perform_request(method, body: nil, headers: {})
      @probe.perform(@connection, @uri, method, body: body, headers: headers)
    end
  end

  # The upper-level observation: exactly what the legacy regression could
  # see (did the call complete, and with which HTTP status). Failure causes
  # are deliberately not visible at this layer.
  Outcome = Struct.new(:completed, :http_status)

  # Runs one request record: opens the record, logs the connection intent,
  # registers the boundary double for exactly the duration of the client
  # call, then closes the record.
  class Scenario
    def initialize(probe:, log:, record_id:, method:, uri:)
      @probe = probe
      @log = log
      @record_id = record_id
      @method = method
      @uri_string = uri
    end

    def run
      @log.open_record(@record_id)
      @log.emit(:connection_intent,
        'method' => @method.to_s.upcase, 'uri' => @uri_string)
      double = nil
      begin
        double = BoundaryDouble.new(@log, @probe.boundary_label)
        connection, uri = @probe.build_connection(@uri_string)
        @probe.attach_double(connection, double)
        double.arm!
        response = yield ClientContext.new(@probe, connection, uri)
        Outcome.new(true, response.code)
      rescue ClientCancelled
        # The client cancelled before request construction; WebMock was
        # never involved, so there is no adjudication to record.
        Outcome.new(false, nil)
      rescue WebMock::NetConnectNotAllowedError
        @log.emit(:adjudication,
          'verdict' => 'denied',
          'observed_via' => 'WebMock::NetConnectNotAllowedError',
          'rule' => 'no stub matched and real connections are disabled')
        Outcome.new(false, nil)
      ensure
        double&.disarm!
        @log.close_record
      end
    end
  end

  SuiteResult = Struct.new(:log, :outcomes)

  ALLOWED_URI = 'http://www.example.com/'
  DENIED_URI = 'http://www.example.net/'

  # Runs the three-scenario acceptance suite against a registered probe.
  # The caller installs WebMock stubs (through WebMock::API) in the block, so
  # the suite itself stays adapter- and framework-agnostic and can be reused
  # verbatim for the upgraded adapters.
  def self.run_suite(probe_name, log: EventLog.new)
    adapter_probe = probe(probe_name)
    yield if block_given?

    outcomes = {}
    outcomes['allowed-stub'] = Scenario.new(
      probe: adapter_probe, log: log, record_id: 'allowed-stub',
      method: :get, uri: ALLOWED_URI
    ).run { |client| client.perform_request(:get) }

    outcomes['client-cancel'] = Scenario.new(
      probe: adapter_probe, log: log, record_id: 'client-cancel',
      method: :get, uri: ALLOWED_URI
    ).run { |_client| raise ClientCancelled, 'cancelled before request construction' }

    outcomes['rule-denied'] = Scenario.new(
      probe: adapter_probe, log: log, record_id: 'rule-denied',
      method: :get, uri: DENIED_URI
    ).run { |client| client.perform_request(:get) }

    SuiteResult.new(log, outcomes)
  end
end
