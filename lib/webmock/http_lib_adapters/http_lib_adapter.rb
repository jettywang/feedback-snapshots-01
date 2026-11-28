# frozen_string_literal: true

module WebMock
  class HttpLibAdapter
    def self.adapter_for(lib)
      WebMock::HttpLibAdapterRegistry.instance.register(lib, self)
    end

    # Adapters that do not patch an underlying library have nothing to toggle.
    def self.enable!; end

    def self.disable!; end

    # Records the request for the existing count assertions and resolves the
    # adapter's actual decision, collecting verifiable evidence when that is
    # enabled. The supplied blocks describe this adapter's real actions, so the
    # evidence reflects what genuinely happened rather than an assumed path:
    #
    #   +stub_block+   builds the stubbed response object (no network send)
    #   +real_block+   performs the allowed real request and returns its result
    #
    # The result is [request_signature, webmock_response, result, context].
    # +webmock_response+ is nil for a real request; +result+ is the adapter's
    # own return value for either branch. A policy refusal raises before any
    # real block runs. A provisional evidence record is written before the
    # branch action runs, so an interrupted callback can replace it with an
    # :incomplete outcome instead of leaving the request unaccounted for.
    def self.resolve_request(request_signature, lib, stub_block:, real_block:)
      WebMock::RequestRegistry.instance.requested_signatures.put(request_signature)

      evidence_registry = WebMock::RequestEvidenceRegistry.instance
      context = evidence_registry.start_request(request_signature, lib)

      webmock_response = WebMock::StubRegistry.instance.response_for_request(request_signature)

      if webmock_response
        evidence_registry.record(context, :stubbed, false, "stub_response")
        result = stub_block.call(webmock_response, context)
        [request_signature, webmock_response, result, context]
      elsif WebMock.net_connect_allowed?(request_signature.uri)
        evidence_registry.record(context, :real, true, "net_connect_allowed")
        result = real_block.call(context)
        [request_signature, nil, result, context]
      else
        evidence_registry.record(context, :policy_denied, false, "net_connect_disabled")
        raise WebMock::NetConnectNotAllowedError.new(request_signature)
      end
    end

    # Replaces the provisional evidence for a request with an :incomplete
    # outcome, used when an adapter callback interrupts handling.
    def self.record_incomplete_request(context, real_request_sent, note)
      return nil if context.nil?

      WebMock::RequestEvidenceRegistry.instance.replace(
        context, :incomplete, real_request_sent, note
      )
    end
  end
end