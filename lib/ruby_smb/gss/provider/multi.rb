module RubySMB
  module Gss
    module Provider
      #
      # A GSS provider that offers more than one authentication mechanism to the client and routes each request to
      # whichever of its sub-providers understands the mechanism the client selected.
      #
      # SPNEGO exists so that a client and server can agree on a mechanism, but a server that only ever advertises one
      # has nothing to negotiate. This provider advertises the mechanisms of every provider it holds, in the order they
      # were given, so a client can pick the one it prefers.
      #
      # @example Offer Kerberos, falling back to NTLM
      #   provider = RubySMB::Gss::Provider::Multi.new([kerberos_provider, ntlm_provider])
      #   RubySMB::Server.new(gss_provider: provider)
      #
      class Multi < Base
        #
        # @param [Array<Provider::Base>] providers the providers to offer, in preference order (most preferred first).
        def initialize(providers)
          raise ArgumentError, 'at least one provider is required' if providers.nil? || providers.empty?

          @providers = providers.dup.freeze
        end

        # @return [Array<Provider::Base>] the providers this instance will route between.
        attr_reader :providers

        def new_authenticator(server_client)
          Authenticator.new(self, server_client)
        end

        #
        # Every mechanism offered by every provider, in provider order, with duplicates removed so a mechanism supported
        # by two providers is only advertised once.
        #
        # @return [Array<OpenSSL::ASN1::ObjectId>]
        def mech_types
          @providers.flat_map(&:mech_types).uniq(&:oid)
        end

        #
        # The first provider that handles the specified mechanism, or nil if none do.
        #
        # @param [OpenSSL::ASN1::ObjectId] mech_type the mechanism selected by the client
        # @return [Provider::Base, nil]
        def provider_for(mech_type)
          @providers.find { |provider| provider.supports_mech_type?(mech_type) }
        end

        # Anonymous and guest access are intentionally not aggregated across the providers. Each sub-provider owns its
        # own policy and applies it only to the mechanism it handles, so a provider that allows guests or anonymous
        # logons must never let an authentication against a stricter provider be downgraded. The Base accessors
        # ({Base#allow_anonymous} and {Base#allow_guests}) remain available on the Multi provider itself.

        class Authenticator < Authenticator::Base
          def initialize(provider, server_client)
            # built lazily, so a provider that is advertised but never selected is never instantiated
            @authenticators = {}
            @selected = nil
            @selected_provider = nil
            super
          end

          #
          # Tear the whole negotiation down: every sub-authenticator is discarded along with the selected mechanism,
          # leaving a clean slate on which a later NegTokenInit starts a fresh exchange. Sub-authenticators are dropped
          # rather than reused so no partial state (a stale NTLM challenge, a half-finished Kerberos exchange, an old
          # session key) can survive into the next negotiation.
          #
          def reset!
            super
            @authenticators&.each_value(&:reset!)
            @authenticators.clear
            @selected = nil
            @selected_provider = nil
          end

          def process(request_buffer=nil)
            # the advertisement, listing every mechanism the server is willing to accept
            return Result.new(Gss.gss_neg_token_init(@provider.mech_types), WindowsError::NTStatus::STATUS_SUCCESS) if request_buffer.nil?

            begin
              gss_api = OpenSSL::ASN1.decode(request_buffer)
            rescue OpenSSL::ASN1::ASN1Error => e
              logger.error("Failed to parse the ASN1-encoded authentication request (#{e.message})")
              return
            end

            if negotiation_init?(gss_api)
              select_mechanism(gss_api, request_buffer)
            else
              route_continuation(request_buffer)
            end
          end

          # @return [Provider::Base, nil] the provider whose mechanism the client selected, or nil before a selection.
          attr_reader :selected_provider

          # The session key belongs to whichever mechanism actually authenticated the client.
          def session_key
            @selected&.session_key
          end

          def session_key=(value)
            @selected&.session_key = value
          end

          private

          # Whether the token is a NegTokenInit, which is the only token that names a mechanism.
          def negotiation_init?(gss_api)
            gss_api&.tag == 0 && gss_api&.tag_class == :APPLICATION
          end

          #
          # Handle a NegTokenInit, the only token that names a mechanism and therefore the only point at which the
          # routing decision can change.
          #
          # A second NegTokenInit means the client is starting a new exchange (for example after a failed attempt). The
          # previous exchange is reset first, so switching mechanisms can never leave one mechanism's partial state
          # reachable through another. A continuation token can never trigger this path.
          #
          def select_mechanism(gss_api, request_buffer)
            mech_type = Gss.asn1dig(gss_api, 1, 0, 0, 0, 0)
            provider = @provider.provider_for(mech_type)
            if provider.nil?
              logger.warn("Client selected an unsupported GSS mechanism (#{mech_type&.oid || 'unknown'})")
              return
            end

            reset! unless @selected_provider.nil?
            @selected_provider = provider
            @selected = authenticator_for(provider)
            @selected.process(request_buffer)
          end

          #
          # Route a NegTokenResp continuation. Such a token carries no mechanism OID, so it is always delivered to the
          # mechanism already selected by an earlier NegTokenInit - it is never retried against every provider and its
          # contents cannot change the routing. Before any mechanism has been selected there is nothing to route to.
          #
          def route_continuation(request_buffer)
            if @selected.nil?
              logger.warn('Received a GSS continuation token before any mechanism was selected')
              return
            end

            @selected.process(request_buffer)
          end

          def authenticator_for(provider)
            @authenticators[provider] ||= provider.new_authenticator(@server_client)
          end
        end
      end
    end
  end
end
