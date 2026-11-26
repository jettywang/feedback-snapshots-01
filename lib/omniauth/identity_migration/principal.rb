module OmniAuth
  module IdentityMigration
    # A uid inside one provider registration/namespace. Two registrations can
    # each contain the same uid without referring to the same subject.
    class Principal
      attr_reader :registration, :uid, :provider, :mapping_version

      alias namespace registration

      def initialize(attributes = nil, **keywords)
        attributes = Hash(attributes).merge(keywords)
        @registration = required_attribute(attributes, :registration)
        @uid = required_attribute(attributes, :uid)
        @provider = optional_attribute(attributes, :provider)
        @mapping_version = optional_attribute(attributes, :mapping_version, :version)
      end

      def key
        [registration, uid]
      end

      def qualified_uid
        "#{registration}:#{uid}"
      end
      alias to_s qualified_uid

      def ==(other)
        other.is_a?(Principal) && other.key == key
      end
      alias eql? ==

      def hash
        key.hash
      end

      def to_h
        {
          'registration' => registration,
          'uid' => uid,
          'provider' => provider,
          'mapping_version' => mapping_version,
          'qualified_uid' => qualified_uid
        }
      end
      alias to_hash to_h

      private

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
