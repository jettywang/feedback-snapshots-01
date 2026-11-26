module OmniAuth
  module Strategy
    # Verifies the trusted gateway/listener/receiver through which a callback
    # reached Rack. The identifier must be put in the Rack environment by an
    # infrastructure layer the application trusts; public HTTP_* headers are
    # never consulted by default.
    # rubocop:disable Metrics/ModuleLength
    module Receivers
      CANONICAL_ENV_KEY = 'omniauth.receiver'.freeze

      ENV_KEYS = %w[
        omniauth.receiver omniauth.receiver_id omniauth.receiver.id
        omniauth.recipient omniauth.recipient_id
        omniauth.ingress omniauth.ingress_id omniauth.ingress.id
        omniauth.entry omniauth.entry_id omniauth.entrypoint omniauth.entrypoint_id
        omniauth.listener omniauth.listener_id omniauth.listener.id
        omniauth.gateway omniauth.gateway_id omniauth.gateway.id
        omniauth.zone omniauth.zone_id omniauth.network_zone
        rack.receiver rack.receiver_id rack.ingress rack.ingress_id
        rack.entrypoint rack.listener rack.gateway rack.zone
        gateway.receiver gateway.receiver_id gateway.ingress gateway.ingress_id
        gateway.listener gateway.listener_id gateway.id
        omniauth_receiver omniauth_receiver_id omniauth_ingress omniauth_listener
      ].freeze

      ALLOWLIST_OPTIONS = %i[
        allowed_receiver allowed_receivers receiver_id
        registered_receiver registered_receiver_id receivers
        allowed_recipient allowed_recipients recipients
        allowed_ingress allowed_ingresses ingress ingresses
        allowed_entry allowed_entries entries
        allowed_entrypoint allowed_entrypoints entrypoints
        allowed_entry_points entry_points
        allowed_listener allowed_listeners listeners
        allowed_gateway allowed_gateways gateways
        allowed_zone allowed_zones allowed_network_zones zones
        callback_receiver callback_receivers callback_ingress callback_entrypoint
        callback_listener callback_gateway callback_zone
        required_receiver require_receiver receiver_ids
      ].freeze

      RESOLVER_OPTIONS = %i[
        receiver_resolver receiver_proc receiver_from receiver
        current_receiver current_receiver_id identify_receiver
      ].freeze

      ENV_KEY_OPTIONS = %i[
        receiver_env_key receiver_env receiver_key receiver_env_name
        receiver_id_env receiver_id_key env_key rack_env_key rack_key env
        ingress_env_key ingress_env ingress_key
        entrypoint_env_key entrypoint_env entrypoint_key
        listener_env_key listener_env listener_key
        gateway_env_key gateway_env gateway_key
        zone_env_key zone_env zone_key
      ].freeze

      def allowed_receiver?
        receiver_denial_reason.nil?
      end

      # nil means no receiver restriction. :missing or :mismatch is the
      # pre-session, pre-callback rejection reason.
      def receiver_denial_reason
        allowed = receiver_allowlist
        return if allowed.nil?

        receiver = current_receiver
        return :missing if receiver.nil? || (receiver.respond_to?(:empty?) && receiver.empty?)
        return if receiver_matches_any?(receiver, allowed)

        :mismatch
      end

      def current_receiver
        receiver = receiver_from_resolver
        return receiver unless receiver.nil?

        receiver = receiver_from_config_resolver
        return receiver unless receiver.nil?

        env[receiver_env_key_option] ||
          env[OmniAuth.config.receiver_env_key] ||
          receiver_from_default_env
      end

      def invalid_receiver!
        reason = receiver_denial_reason || :mismatch
        receiver = current_receiver
        env['omniauth.receiver'] = receiver
        env['omniauth.receiver.reason'] = reason
        env['omniauth.receiver.authorized'] = false
        fail!(:invalid_receiver, InvalidReceiverError.new(receiver_message(reason, receiver)))
      end

      protected

      def receiver_allowlist
        explicit = ALLOWLIST_OPTIONS.lazy.map { |key| options[key] }.reject(&:nil?).first
        return normalize_receiver_allowlist(explicit) unless explicit.nil?

        static_receiver = options[:receiver]
        return normalize_receiver_allowlist(static_receiver) if static_receiver && !static_receiver.respond_to?(:call)

        generic = generic_receiver_option
        return normalize_receiver_allowlist(generic.last) if generic

        normalize_receiver_allowlist(OmniAuth.config.allowed_receivers)
      end

      def generic_receiver_option
        options.detect do |key, value|
          name = key.to_s
          value && name.match?(/allowed|allowlist|allow_list|whitelist|permitted|required|restricted|only|registered|approved|trusted|verified/) &&
            name.match?(/receiver|recipient|ingress|entry|listener|gateway|zone|source/) &&
            !name.match?(/host|resolver|_env|_key\z/)
        end
      end

      def normalize_receiver_allowlist(value)
        case value
        when nil, false then nil
        when true then [:present]
        when Array then value
        when Hash then value.keys
        else [value]
        end
      end

      def receiver_matches_any?(receiver, allowed)
        Array(allowed).any? do |rule|
          next receiver_present?(receiver) if rule == :present
          next rule.match?(receiver.to_s) if rule.is_a?(Regexp)
          next call_receiver_rule(rule, receiver) if rule.respond_to?(:call)

          rule == receiver || rule.to_s == receiver.to_s || rule === receiver
        end
      end

      def receiver_present?(receiver)
        !receiver.nil? && !(receiver.respond_to?(:empty?) && receiver.empty?)
      end

      def call_receiver_rule(rule, receiver)
        if rule.arity == 0
          rule.call
        elsif rule.arity == 2
          rule.call(receiver, env)
        else
          rule.call(receiver)
        end
      end

      def receiver_from_resolver
        RESOLVER_OPTIONS.each do |key|
          resolver = options[key]
          next unless resolver.respond_to?(:call)

          return call_receiver_resolver(resolver)
        end
        nil
      end

      def receiver_from_config_resolver
        resolver = OmniAuth.config.receiver_resolver
        call_receiver_resolver(resolver) if resolver.respond_to?(:call)
      end

      def call_receiver_resolver(resolver)
        if resolver.arity == 0
          resolver.call
        elsif resolver.arity == 1
          resolver.call(env)
        else
          resolver.call(env, options)
        end
      end

      def receiver_env_key_option
        explicit = ENV_KEY_OPTIONS.lazy.map { |key| options[key] }.detect do |value|
          value.is_a?(String) || value.is_a?(Symbol)
        end
        return explicit.to_s if explicit

        generic_receiver_env_key_option&.to_s
      end

      def generic_receiver_env_key_option
        _key, value = options.detect { |key, value| receiver_env_key_candidate?(key, value) }
        value
      end

      def receiver_env_key_candidate?(key, value)
        name = key.to_s
        (value.is_a?(String) || value.is_a?(Symbol)) &&
          name.match?(/receiver|recipient|ingress|entry|listener|gateway|zone/) &&
          name.match?(/env|rack_key|_key\z/) &&
          !name.match?(/allowed|allowlist|whitelist/)
      end

      def receiver_from_default_env
        ENV_KEYS.each do |key|
          value = env[key]
          return value if receiver_present?(value)
        end
        nil
      end

      def receiver_message(reason, receiver)
        if reason == :missing
          'No verified receiver identifier is present in the Rack environment'
        else
          "Rack receiver #{receiver.inspect} is not allowed for the #{name} strategy"
        end
      end
    end
    # rubocop:enable Metrics/ModuleLength
  end
end
