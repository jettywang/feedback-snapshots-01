# frozen_string_literal: true

require 'digest'

module WebMock
  # A single, auditable piece of evidence about how one HTTP request was
  # handled. Evidence is only collected when request evidence is explicitly
  # enabled (see WebMock::RequestEvidenceRegistry), so stubbing and the existing
  # request-count assertions are unaffected until then.
  #
  # Each record is built from the adapter's actual decision (a stubbed
  # response, a policy rejection, an allowed real request, or an interrupted
  # callback), and carries only an allow-listed projection of the request plus
  # a signature that can be matched back to a recorded RequestSignature.
  class RequestEvidence
    OUTCOMES = [:stubbed, :policy_denied, :real, :incomplete].freeze

    ALLOWED_REQUEST_KEYS = [:method, :uri, :body, :headers].freeze

    attr_reader :sequence, :outcome, :lib, :real_request_sent,
                :request_signature, :signature, :request, :diagnostics,
                :context_id

    def initialize(request_signature:, outcome:, lib:, real_request_sent:,
                   diagnostics: nil, sequence: nil, context_id: nil)
      raise ArgumentError, "unknown outcome #{outcome.inspect}" unless OUTCOMES.include?(outcome)

      @sequence = sequence
      @outcome = outcome
      @lib = lib.to_sym
      @real_request_sent = !!real_request_sent
      @request_signature = request_signature
      @signature = RequestEvidence.signature_for(request_signature)
      @request = RequestEvidence.allowed_request(request_signature)
      @diagnostics = Array(diagnostics).dup
      @context_id = context_id
      freeze_content
    end

    def stubbed?
      outcome == :stubbed
    end

    def policy_denied?
      outcome == :policy_denied
    end

    def real?
      outcome == :real
    end

    def incomplete?
      outcome == :incomplete
    end

    # True when the adapter actually performed a network send, as opposed to
    # answering from a stub or refusing before any socket was opened.
    def sent?
      real_request_sent
    end

    # Re-matches this evidence against a freshly computed signature, so a
    # compliance check never has to trust the stored object alone.
    def matches_signature?(other_request_signature)
      signature == RequestEvidence.signature_for(other_request_signature)
    end

    def to_h
      {
        sequence: sequence,
        context_id: context_id,
        outcome: outcome,
        lib: lib,
        real_request_sent: real_request_sent,
        signature: signature,
        request: request,
        diagnostics: diagnostics
      }
    end

    def to_s
      request_text = [request[:method].to_s.upcase, request[:uri]].join(' ')
      "#{sequence || '-'} #{outcome} [#{lib}] #{request_text} " \
        "(sent=#{real_request_sent}) sig=#{signature}#{diagnostics_text}"
    end

    # Deterministic signature derived from the request the adapter actually
    # built. Keeping the digest calculation in one place lets records and
    # verifiers always agree.
    def self.signature_for(request_signature)
      Digest::SHA256.hexdigest(request_signature.to_s)
    end

    # Projects only the allow-listed request fields, so evidence never carries
    # adapter internals or objects beyond what can be cross-checked.
    def self.allowed_request(request_signature)
      {
        method: request_signature.method,
        uri: WebMock::Util::URI.strip_default_port_from_uri_string(
          request_signature.uri.to_s
        ),
        body: request_signature.body.nil? ? nil : request_signature.body.to_s,
        headers: sanitized_headers(request_signature.headers)
      }
    end

    def self.sanitized_headers(headers)
      return {} if headers.nil?

      headers.each_with_object({}) do |(name, value), memo|
        memo[name.to_s] = value.is_a?(Array) ? value.map(&:to_s) : value.to_s
      end
    end
    private_class_method :sanitized_headers

    private

    def freeze_content
      @request = deep_freeze(@request)
      @diagnostics.freeze
      freeze
    end

    def deep_freeze(value)
      case value
      when Hash
        value.each { |key, item| deep_freeze(item) }
        value.freeze
      when Array
        value.each { |item| deep_freeze(item) }
        value.freeze
      else
        value.freeze
      end
    end

    def diagnostics_text
      return "" if diagnostics.empty?

      " #{diagnostics.join(' -> ')}"
    end
  end
end
