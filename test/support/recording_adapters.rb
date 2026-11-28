# frozen_string_literal: true

require 'webmock'

# Self-contained, dependency-free adapters that reproduce the decision flow of
# the two "recording" HTTP libraries (Patron and Curb). They let the evidence
# behaviour be exercised without the native gems, while keeping the same shape:
# a session/easy object builds a RequestSignature, hands the decision to the
# shared adapter helper, then runs its own callbacks on the result.
#
# Each adapter counts the requests it truly sent over a socket so tests can
# assert that stubs and policy refusals never perform a real send.
module WebMock
  module RecordingAdapters
    # A plain stand-in for a library response object.
    FakeResponse = Struct.new(:status, :headers, :body, :url, keyword_init: true) do
      def code
        status
      end
    end

    # Shared signature construction, modelled on Patron/Curb#build_request_signature.
    def self.build_signature(method, url, body: nil, headers: nil)
      uri = WebMock::Util::URI.heuristic_parse(url)
      WebMock::RequestSignature.new(
        method.to_s.downcase.to_sym,
        uri.to_s,
        body: body,
        headers: headers || {}
      )
    end

    # Mirrors Patron::Session#handle_request: response first, then callbacks.
    class PatronStyleAdapter < WebMock::HttpLibAdapter
      adapter_for :recording_patron

      LIB = :recording_patron
      @sent_count = 0

      class << self
        attr_reader :sent_count

        def reset!
          @sent_count = 0
        end

        def handle_request(method, url, body: nil, headers: nil, callbacks: [])
          request_signature = RecordingAdapters.build_signature(
            method, url, body: body, headers: headers
          )

          _signature, _webmock_response, result, _context =
            WebMock::HttpLibAdapter.resolve_request(
              request_signature, LIB,
              stub_block: ->(response, tracking_context) { build_response(response, request_signature, callbacks, tracking_context) },
              real_block: ->(_tracking_context) { perform_real_send(request_signature, callbacks) }
            )

          result
        end

        private

        def build_response(webmock_response, request_signature, callbacks, context)
          fake = FakeResponse.new(
            status: webmock_response.status[0],
            headers: webmock_response.headers || {},
            body: webmock_response.body,
            url: request_signature.uri.to_s
          )
          invoke_callbacks(callbacks, context, request_signature, webmock_response)
          fake
        end

        def invoke_callbacks(callbacks, context, request_signature, webmock_response)
          callbacks.each do |callback|
            begin
              callback.call(request_signature, webmock_response)
            rescue StandardError => error
              WebMock::HttpLibAdapter.record_incomplete_request(
                context, false, "callback_interrupted: #{error.class}"
              )
              raise
            end
          end
        end

        def perform_real_send(request_signature, callbacks)
          @sent_count += 1
          webmock_response = WebMock::Response.new(
            status: [200, "OK"], headers: {}, body: "real-body"
          )
          callbacks.each { |callback| callback.call(request_signature, webmock_response) }
          FakeResponse.new(
            status: 200, headers: {}, body: "real-body",
            url: request_signature.uri.to_s
          )
        end
      end
    end

    # Mirrors Curl::Easy#curb_or_webmock: stub build, then the curb callbacks
    # (on_complete/on_success...) run after the WebMock callbacks.
    class CurbStyleAdapter < WebMock::HttpLibAdapter
      adapter_for :recording_curb

      LIB = :recording_curb
      @sent_count = 0

      class << self
        attr_reader :sent_count

        def reset!
          @sent_count = 0
        end

        def perform(method, url, body: nil, headers: nil, callbacks: [])
          request_signature = RecordingAdapters.build_signature(
            method, url, body: body, headers: headers
          )

          _signature, _webmock_response, result, _context =
            WebMock::HttpLibAdapter.resolve_request(
              request_signature, LIB,
              stub_block: ->(response, tracking_context) { build_curb_response(response, request_signature, callbacks, tracking_context) },
              real_block: ->(_tracking_context) { perform_real_send(request_signature, callbacks) }
            )

          result
        end

        private

        def build_curb_response(webmock_response, request_signature, callbacks, context)
          fake = FakeResponse.new(
            status: webmock_response.status[0],
            headers: webmock_response.headers || {},
            body: webmock_response.body,
            url: request_signature.uri.to_s
          )
          invoke_curb_callbacks(callbacks, context, fake)
          fake
        end

        def invoke_curb_callbacks(callbacks, context, fake)
          callbacks.each do |callback|
            begin
              callback.call(fake)
            rescue StandardError => error
              WebMock::HttpLibAdapter.record_incomplete_request(
                context, false, "callback_interrupted: #{error.class}"
              )
              raise
            end
          end
        end

        def perform_real_send(request_signature, callbacks)
          @sent_count += 1
          fake = FakeResponse.new(
            status: 200, headers: {}, body: "real-body",
            url: request_signature.uri.to_s
          )
          callbacks.each { |callback| callback.call(fake) }
          fake
        end
      end
    end
  end
end
