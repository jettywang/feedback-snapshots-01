module OmniAuth
  module Strategy
    # Opt-in provider-registration pinning for migration periods. Strategies
    # and applications without an identity contract keep their existing
    # session and omniauth.auth behavior unchanged.
    module IdentityPinning
      INITIATION_KEY = 'omniauth.identity_initiation'.freeze
      INITIATIONS_KEY = 'omniauth.identity_initiations'.freeze
      INITIATION_ENV_KEY = 'omniauth.identity_initiation'.freeze
      CONTEXT_ENV_KEY = 'omniauth.identity'.freeze
      CONTEXT_ALT_ENV_KEY = 'omniauth.identity_context'.freeze
      RECEIPT_ENV_KEY = 'omniauth.migration_receipt'.freeze
      MIGRATION_ENV_KEY = 'omniauth.migration'.freeze
      IDENTITY_MIGRATION_ENV_KEY = 'omniauth.identity_migration'.freeze
      MIGRATION_RESULT_ENV_KEY = 'omniauth.migration_result'.freeze
      CONTRACT_ENV_KEY = 'omniauth.identity_contract'.freeze
      PRINCIPAL_ENV_KEY = 'omniauth.principal'.freeze
      SOURCE_PRINCIPAL_ENV_KEY = 'omniauth.source_principal'.freeze
      ATTRIBUTED_PRINCIPAL_ENV_KEY = 'omniauth.attributed_principal'.freeze
      REGISTRATION_ENV_KEY = 'omniauth.registration'.freeze
      MAPPING_ENV_KEY = 'omniauth.mapping'.freeze

      def identity_contract
        options[:identity_contract] ||
          options[:identity_migration_contract] ||
          options[:migration_contract] ||
          options[:identity_callback_contract] ||
          options[:callback_contract] ||
          options[:provider_migration_contract] ||
          OmniAuth.config.identity_contract ||
          OmniAuth.config.identity_migration_contract ||
          OmniAuth.config.migration_contract ||
          OmniAuth.config.callback_contract
      end

      def pin_identity_initiation!
        contract = identity_contract
        return unless contract

        payload = build_identity_initiation(contract)
        session[INITIATION_KEY] = payload
        initiations = identity_initiations.dup
        initiations[name.to_s] = payload
        session[INITIATIONS_KEY] = initiations
        payload
      end

      def remember_identity(key = nil, data = nil)
        return unless identity_contract
        return pin_identity_initiation! if key.nil?

        identity_data = (data || {}).dup
        identity_data['identity'] ||= build_identity_initiation(identity_contract)
        remember_sign_in(key, identity_data)
      end
      alias pin_identity remember_identity

      def remember_sign_in(key, data = nil)
        if identity_contract
          data = (data || {}).dup
          data['identity'] ||= build_identity_initiation(identity_contract)
        end
        super
      end

      def identity_initiation_from_sign_in(sign_in)
        value = sign_in.is_a?(Hash) ? (sign_in['identity'] || sign_in[:identity]) : nil
        value if value.is_a?(Hash)
      end

      def apply_identity_contract!
        contract = identity_contract
        return unless contract

        initiation = current_identity_initiation
        env[INITIATION_ENV_KEY] = initiation if initiation
        env[CONTRACT_ENV_KEY] = contract
        result = call_identity_contract(contract, initiation)
        receipt = identity_receipt(result)
        return unless receipt

        write_identity_result(receipt)
        receipt
      end

      private

      def current_identity_initiation
        initiations = identity_initiations.dup
        provider_payload = initiations.delete(name.to_s)
        session[INITIATIONS_KEY] = initiations if provider_payload

        return env[INITIATION_ENV_KEY] if env[INITIATION_ENV_KEY].is_a?(Hash)

        provider_payload if provider_payload.is_a?(Hash)
      end

      def identity_initiations
        value = session[INITIATIONS_KEY]
        value.is_a?(Hash) ? value : {}
      end

      def build_identity_initiation(contract)
        if contract.respond_to?(:pin_initiation)
          return contract.pin_initiation(
            name,
            :registration => options[:identity_registration] || options[:registration],
            :mapping_version => options[:identity_mapping_version] || options[:mapping_version]
          )
        end

        registration = options[:identity_registration] || options[:registration] || name
        version = options[:identity_mapping_version] || options[:mapping_version]
        {
          'registration' => registration.to_s,
          'provider' => name.to_s,
          'mapping_version' => version&.to_s
        }
      end

      def call_identity_contract(contract, initiation)
        auth = env['omniauth.auth']
        if contract.respond_to?(:call)
          arity = contract.is_a?(Proc) ? contract.arity : contract.method(:call).arity
          if arity == 1
            contract.call(env)
          elsif arity == -1
            contract.call(env)
          else
            contract.call(auth, initiation)
          end
        elsif contract.respond_to?(:evaluate)
          contract.evaluate(auth, initiation)
        elsif contract.respond_to?(:resolve)
          contract.resolve(auth, initiation)
        end
      end

      def identity_receipt(result)
        return result if result.is_a?(OmniAuth::IdentityMigration::Receipt)
        return OmniAuth::IdentityMigration::Receipt.new(result) if result.is_a?(Hash)

        nil
      end

      def write_identity_result(receipt)
        source = receipt.principal
        attributed = receipt.attributed_principal || source
        context_attributes = receipt.to_h
        if source
          context_attributes['registration_record'] = context_attributes['registration']
          context_attributes['registration'] = source.registration
        end
        context = OmniAuth::KeyStore.new(context_attributes.merge('principal' => attributed&.to_h))
        env[CONTEXT_ENV_KEY] = context
        env[CONTEXT_ALT_ENV_KEY] = context
        env[RECEIPT_ENV_KEY] = receipt
        env[MIGRATION_ENV_KEY] = receipt
        env[IDENTITY_MIGRATION_ENV_KEY] = receipt
        env[MIGRATION_RESULT_ENV_KEY] = receipt.migration_result
        env[MAPPING_ENV_KEY] = receipt.mapping if receipt.mapping
        return unless source

        env[PRINCIPAL_ENV_KEY] = attributed
        env[SOURCE_PRINCIPAL_ENV_KEY] = source
        env[ATTRIBUTED_PRINCIPAL_ENV_KEY] = attributed
        env[REGISTRATION_ENV_KEY] = source.registration
        decorate_auth_hash(source, attributed, receipt)
      end

      def decorate_auth_hash(source, attributed, receipt)
        auth = env['omniauth.auth']
        return unless auth.respond_to?(:[]=)

        auth['identity'] = OmniAuth::KeyStore.new(
          'registration' => source.registration,
          'principal' => source.qualified_uid,
          'attributed_principal' => attributed.qualified_uid,
          'mapping_version' => source.mapping_version,
          'status' => receipt.status
        )
        auth['registration'] = source.registration
        auth['identity_registration'] = source.registration
        auth['identity_principal'] = source.qualified_uid
        auth['mapping_version'] = source.mapping_version
        auth['migration_status'] = receipt.status
      end
    end
  end
end
