# frozen_string_literal: true

require 'webmock'

# A test double HTTP library. It never opens a real socket: its adapter only
# records the intention to connect, so the scope tests stay local and do not
# depend on any external service.
module RecordingHttp
  class Client
    attr_reader :host, :port

    def initialize(uri)
      @host = uri.host
      @port = uri.port
      @started = false
    end

    # Adapter lifecycle point 1: the connection is established before any
    # request is made.
    def start
      RecordingHttpAdapter.establish_connection(self)
      @started = true
      self
    end

    def started?
      @started
    end

    # Adapter lifecycle point 2: the first request decides whether a real
    # connection is allowed.
    def request(method, path)
      raise 'client is not started' unless started?

      RecordingHttpAdapter.perform_request(self, method, path)
    end
  end
end

# Minimal WebMock adapter for RecordingHttp. Following the same flow as the
# shipped adapters, it answers stubs from the StubRegistry and otherwise asks
# WebMock whether a real connection is permitted. Instead of connecting it
# appends a record of the connection intention.
class RecordingHttpAdapter < WebMock::HttpLibAdapter
  adapter_for :recording_http

  # This double does not monkey-patch a real library, so enabling and
  # disabling it is a no-op.
  def self.enable!; end
  def self.disable!; end

  CONNECTIONS = []

  def self.reset!
    CONNECTIONS.clear
  end

  def self.connections_for(host)
    CONNECTIONS.select { |record| record[:host] == host }
  end

  def self.establish_connection(client)
    uri = Addressable::URI.parse("http://#{client.host}:#{client.port}")

    return unless WebMock.net_http_connect_on_start?(uri)

    record_connection(client, :start)
  end

  def self.perform_request(client, method, path)
    uri = Addressable::URI.parse("http://#{client.host}:#{client.port}#{path}")
    request_signature = WebMock::RequestSignature.new(
      method.to_s.downcase.to_sym, uri.to_s
    )

    WebMock::RequestRegistry.instance.requested_signatures.put(request_signature)

    if webmock_response = WebMock::StubRegistry.instance.response_for_request(request_signature)
      WebMock::CallbackRegistry.invoke_callbacks(
        { lib: :recording_http }, request_signature, webmock_response
      )
      return stubbed_response(webmock_response)
    end

    if WebMock.net_connect_allowed?(request_signature.uri)
      record_connection(client, :request)
      return real_response
    end

    raise WebMock::NetConnectNotAllowedError.new(request_signature)
  end

  def self.record_connection(client, phase)
    CONNECTIONS << { host: client.host, port: client.port, phase: phase }
  end

  def self.stubbed_response(webmock_response)
    { status: webmock_response.status.first, body: webmock_response.body, real: false }
  end

  def self.real_response
    { status: 200, body: '', real: true }
  end
end
