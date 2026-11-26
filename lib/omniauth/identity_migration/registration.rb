module OmniAuth
  module IdentityMigration
    # One employee-identity registration, usually backed by an OmniAuth
    # provider entry. A preferred provider switch does not invalidate an
    # older registration for a flow that started against it.
    class Registration
      attr_reader :name, :provider, :mapping_version, :status, :metadata

      def initialize(attributes = nil, **keywords)
        attributes = Hash(attributes).merge(keywords)
        @name = required_attribute(attributes, :name)
        @provider = optional_attribute(attributes, :provider) || @name
        @mapping_version = optional_attribute(attributes, :mapping_version, :version) || 'unversioned'
        @status = (optional_attribute(attributes, :status) || 'active').to_s
        valid = optional_attribute(attributes, :valid)
        active = optional_attribute(attributes, :active)
        @valid = if valid.nil?
                   active.nil? ? @status == 'active' : !!active
                 else
                   !!valid
                 end
        @metadata = metadata_hash(optional_attribute(attributes, :metadata))
      end

      def valid?
        @valid
      end

      def active?
        status == 'active' && valid?
      end

      def to_h
        {
          'name' => name,
          'provider' => provider,
          'mapping_version' => mapping_version,
          'status' => status,
          'valid' => valid?,
          'active' => active?,
          'metadata' => metadata
        }
      end
      alias to_hash to_h

      private

      def metadata_hash(value)
        return {} if value.nil?
        return value.to_h if value.respond_to?(:to_h)

        {}
      end

      def required_attribute(attributes, name)
        value = optional_attribute(attributes, name)
        raise ArgumentError, "#{name} is required" if value.nil?

        value.to_s
      end

      def optional_attribute(attributes, *names)
        names.each do |name|
          return attributes[name] if attributes.key?(name)

          string_name = name.to_s
          return attributes[string_name] if attributes.key?(string_name)
        end
        nil
      end
    end
  end
end
