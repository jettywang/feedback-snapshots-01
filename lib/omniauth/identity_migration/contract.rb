module OmniAuth
  module IdentityMigration
    # Application-owned registry and mapping book. It never treats equal uids
    # as approval; it only reports that pair as pending review until the app
    # adds an approved bilateral Mapping.
    class Contract
      attr_reader :registrations, :mappings, :subjects, :ledger
      attr_accessor :preferred_provider, :mapping_version

      def initialize(attributes = nil, **keywords)
        options = Hash(attributes).merge(keywords)
        @ledger = options[:ledger] || options['ledger'] || Ledger.new
        @registrations = {}
        @mappings = []
        @subjects = {}
        Array(option(options, :registrations)).each { |registration| register(registration) }
        Array(option(options, :mappings)).each { |mapping| add_mapping(mapping) }
        @preferred_provider = string_or_nil(option(options, :preferred_provider, :default_provider))
        @mapping_version = string_or_nil(option(options, :mapping_version, :version))
      end

      alias default_provider preferred_provider
      alias default_provider= preferred_provider=

      def register(attributes)
        registration = attributes.is_a?(Registration) ? attributes : Registration.new(attributes)
        registrations[registration.name] = registration
        registrations[registration.provider] = registration
        registration
      end

      def registration_for(provider_or_name)
        return if provider_or_name.nil?

        registrations[provider_or_name.to_s]
      end

      def add_mapping(attributes)
        mapping = attributes.is_a?(Mapping) ? attributes : Mapping.new(attributes)
        mappings << mapping
        mapping
      end

      def approve_mapping!(left = nil, right = nil, attributes = nil, **keywords)
        mapping_attributes = mapping_arguments(left, right, attributes, keywords)
        mapping_attributes[:approved] = true
        add_mapping(mapping_attributes)
      end
      alias approve_mapping approve_mapping!

      def pin_initiation(provider, attributes = nil, **keywords)
        options = Hash(attributes).merge(keywords)
        registration = registration_from_option(options) || registration_for(provider)
        raise UnknownRegistration, "No identity registration for #{provider.inspect}" unless registration

        version = option(options, :mapping_version, :version) || registration.mapping_version || mapping_version
        {
          'registration' => registration.name,
          'provider' => provider.to_s,
          'mapping_version' => string_or_nil(version),
          'preferred_provider' => preferred_provider
        }
      end

      def call(environment, initiation = nil)
        if rack_environment?(environment)
          evaluate(environment['omniauth.auth'], initiation || environment['omniauth.identity_initiation'])
        else
          evaluate(environment, initiation)
        end
      end
      alias callback call
      alias resolve call

      def evaluate(authentication, initiation = nil)
        initiation = normalize_initiation(initiation)
        provider = authentication_provider(authentication)
        uid = authentication_uid(authentication)
        registration = registration_for(initiation['registration']) || registration_for(provider)
        principal = principal_from(authentication, initiation, registration, provider, uid)
        mapping = approved_mapping_for(principal, initiation['mapping_version'])
        status, reasons, attributed = classify(principal, mapping, initiation['mapping_version'], registration)
        remember_subject(principal) if registration&.valid?
        ledger.record(
          :kind => 'login', :status => status, :reasons => reasons,
          :principal => principal, :attributed_principal => attributed || principal,
          :target_principal => mapping&.counterpart(principal), :mapping => mapping,
          :registration => registration, :auth_provider => provider, :auth_uid => uid
        )
      end

      def convert!(source = nil, target = nil, attributes = nil, **keywords)
        options = conversion_arguments(source, target, attributes, keywords)
        source_principal = coerce_principal(option(options, :source, :principal))
        target_principal = coerce_principal(option(options, :target, :target_principal))
        version = option(options, :mapping_version, :version) || source_principal&.mapping_version
        mapping = approved_mapping_for(source_principal, version)
        validate_conversion!(source_principal, mapping, target_principal)
        target_principal ||= mapping.counterpart(source_principal)
        ledger.record(
          :kind => 'conversion', :status => 'converted', :principal => source_principal,
          :attributed_principal => target_principal, :target_principal => target_principal,
          :mapping => mapping, :reference => option(options, :reference)
        )
      end
      alias convert convert!

      def approved_mapping_for(principal, version = nil)
        mappings.reverse.detect { |mapping| mapping.matches?(principal, version) }
      end
      alias mapping_for approved_mapping_for
      alias find_mapping approved_mapping_for
      alias approve approve_mapping!

      private

      def classify(principal, approved, version, registration)
        return ['mapped', [], approved.counterpart(principal)] if approved
        return ['unregistered', ['registration_not_found'], principal] unless registration
        return ['registration_inactive', ['registration_inactive'], principal] unless registration.valid?

        related = mappings.reverse.detect { |mapping| mapping.bilateral? && mapping.involves?(principal) }
        if related
          if related.approved? && !version.nil? && related.version != version.to_s
            return ['pending_review', ['mapping_version_mismatch'], principal]
          end

          return ['pending_review', ["mapping_#{related.status}"], principal]
        end

        return ['pending_review', ['same_uid_unapproved'], principal] if same_uid_counterpart?(principal)

        ['ordinary', [], principal]
      end

      def validate_conversion!(source, mapping, target)
        raise UnknownRegistration, 'A source principal is required' unless source.is_a?(Principal)
        raise UnapprovedMapping, "No approved mapping for #{source.qualified_uid}" unless mapping
        return if target.nil? || mapping.counterpart(source) == target

        raise UnapprovedMapping, 'Approved mapping does not match the requested target'
      end

      def same_uid_counterpart?(principal)
        subjects.any? do |_key, other|
          other.uid == principal.uid && other.registration != principal.registration
        end
      end

      def remember_subject(principal)
        subjects[principal.key] = principal
      end

      def principal_from(authentication, initiation, registration, provider, uid)
        return authentication if authentication.is_a?(Principal)

        registration_name = registration&.name || initiation['registration'] || provider || 'unregistered'
        Principal.new(
          :registration => registration_name, :uid => uid, :provider => provider,
          :mapping_version => initiation['mapping_version'] || registration&.mapping_version || mapping_version
        )
      end

      def registration_from_option(options)
        value = option(options, :registration, :identity_registration)
        return value if value.is_a?(Registration)
        return registration_for(value) if value

        nil
      end

      def mapping_arguments(left, right, attributes, keywords)
        if left.is_a?(Mapping)
          left.to_h.merge(keywords)
        elsif left.is_a?(Hash) && right.nil? && attributes.nil?
          left.merge(keywords)
        else
          {:left => left, :right => right}.merge(Hash(attributes)).merge(keywords)
        end
      end

      def conversion_arguments(source, target, attributes, keywords)
        if source.is_a?(Receipt)
          {:source => source.principal, :target => target || source.target_principal}.merge(Hash(attributes)).merge(keywords)
        elsif source.is_a?(Hash) && target.nil? && attributes.nil?
          source.merge(keywords)
        else
          {:source => source, :target => target}.merge(Hash(attributes)).merge(keywords)
        end
      end

      def coerce_principal(value)
        return if value.nil?
        return value if value.is_a?(Principal)

        Principal.new(value)
      end

      def normalize_initiation(value)
        hash = value.is_a?(Hash) ? value : {}
        {
          'registration' => option(hash, :registration),
          'mapping_version' => string_or_nil(option(hash, :mapping_version, :version))
        }
      end

      def rack_environment?(value)
        value.is_a?(Hash) && value.key?('omniauth.auth')
      end

      def authentication_provider(authentication)
        read_attribute(authentication, :provider) || read_attribute(authentication, 'provider')
      end

      def authentication_uid(authentication)
        read_attribute(authentication, :uid) || read_attribute(authentication, 'uid')
      end

      def read_attribute(object, key)
        return object[key] if object.respond_to?(:key?) && object.key?(key)
        return object.public_send(key) if object.respond_to?(key)

        nil
      end

      def option(hash, *names)
        names.each do |name|
          if hash.key?(name) && !hash[name].nil?
            return hash[name]
          end

          string_name = name.to_s
          if hash.key?(string_name) && !hash[string_name].nil?
            return hash[string_name]
          end
        end
        nil
      end

      def string_or_nil(value)
        value.nil? ? nil : value.to_s
      end
    end
  end
end
