# frozen_string_literal: true

require 'securerandom'

module Sinatra
  module Middleware
    # Rack middleware that sets a Content-Security-Policy header with
    # support for a per-request nonce.
    #
    # == Contract
    #
    # * A fresh nonce is generated at the start of every request and stored
    #   in +env['sinatra.csp_nonce']+. Reading the key multiple times during
    #   the same request always returns the same value; different requests
    #   never share a nonce. No nonce is generated at middleware
    #   initialization time, so nonces are never shared across requests.
    #
    # * Downstream apps read the nonce from the env (e.g. to emit
    #   <tt><script nonce="..."></tt>) and the middleware puts that very
    #   same value into the policy header of the response, so the two are
    #   always consistent for a given request. The middleware never reads,
    #   buffers or rewrites the response body to inject the nonce; bodies
    #   (including streaming bodies) pass through untouched.
    #
    # * The policy may be given as a String, which is used verbatim on
    #   every response (the classic "fixed policy" interface -- byte
    #   identical across requests and therefore safe to cache), or as a
    #   Hash of directives:
    #
    #     use Sinatra::Middleware::ContentSecurityPolicy,
    #         default_src: :self,
    #         script_src:  [:self, :nonce],
    #         upgrade_insecure_requests: true
    #
    #   Directive names have underscores converted to dashes. Symbol
    #   sources become quoted CSP keywords (<tt>'self'</tt>,
    #   <tt>'unsafe-inline'</tt>, ...); the special symbol +:nonce+ expands
    #   to the per-request <tt>'nonce-...'</tt> value. String sources are
    #   used verbatim. A directive mapped to +true+ is emitted without a
    #   value; +false+/+nil+ omits it.
    #
    # * With <tt>report_only: true</tt> the policy is sent via the
    #   +Content-Security-Policy-Report-Only+ header instead, leaving any
    #   enforcing header alone.
    #
    # * If the application already set the header this middleware would
    #   set, the application's header wins and is left untouched. The env
    #   nonce is still available.
    #
    # * The header is applied to every response regardless of content
    #   type (CSP is meaningful on non-HTML resources too, e.g. SVG or
    #   sandboxed downloads).
    #
    # * If the downstream app raises, the exception propagates unchanged
    #   and no header is added; the request's nonce is discarded with its
    #   env and cannot leak into another request.
    #
    # == Caching caveat
    #
    # This middleware never modifies your Cache-Control headers. A policy
    # containing +:nonce+ makes every response's header unique; letting
    # such a response be reused from a shared cache means multiple users
    # receive the same nonce, which defeats its purpose (the nonce must be
    # unpredictable per response). If responses are cacheable, prefer a
    # static String policy or hash-based sources, or mark nonce-bearing
    # responses +no-store+/private yourself.
    class ContentSecurityPolicy
      NONCE_ENV_KEY = 'sinatra.csp_nonce'
      ENFORCED_HEADER = 'content-security-policy'
      REPORT_ONLY_HEADER = 'content-security-policy-report-only'

      DEFAULT_POLICY = { default_src: :self }.freeze

      def initialize(app, policy = nil, report_only: false)
        @app = app
        @policy = policy || DEFAULT_POLICY
        @header = report_only ? REPORT_ONLY_HEADER : ENFORCED_HEADER
      end

      def call(env)
        env[NONCE_ENV_KEY] = SecureRandom.base64(16)
        status, headers, body = @app.call(env)
        headers[@header] = build_policy(env[NONCE_ENV_KEY]) unless headers.key?(@header)
        [status, headers, body]
      end

      private

      def build_policy(nonce)
        case @policy
        when String then @policy
        when Hash then serialize_policy(@policy, nonce)
        else @policy.to_s
        end
      end

      def serialize_policy(policy, nonce)
        policy.filter_map do |directive, sources|
          name = directive.to_s.tr('_', '-')
          case sources
          when true then name
          when false, nil then nil
          else
            list = Array(sources).map { |source| serialize_source(source, nonce) }
            "#{name} #{list.join(' ')}"
          end
        end.join('; ')
      end

      def serialize_source(source, nonce)
        case source
        when :nonce then "'nonce-#{nonce}'"
        when Symbol then "'#{source.to_s.tr('_', '-')}'"
        else source.to_s
        end
      end
    end
  end
end
