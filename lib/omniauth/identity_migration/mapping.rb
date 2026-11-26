module OmniAuth
  module IdentityMigration
    # An application-recognized link between the two sides of a provider
    # migration. Equal uids alone never make a Mapping approved.
    class Mapping
      attr_reader :left, :right, :version, :status, :approved_by, :reference

      def initialize(attributes = nil, **keywords)
        attributes = Hash(attributes).merge(keywords)
        @left = principal_attribute(attributes, :left, :source)
        @right = principal_attribute(attributes, :right, :target)
        @version = string_attribute(optional_attribute(attributes, :version, :mapping_version))
        @status = initial_status(attributes)
        @approved_by = string_attribute(optional_attribute(attributes, :approved_by, :approver))
        @reference = string_attribute(optional_attribute(attributes, :reference, :id))
      end

      def approved?
        status == 'approved'
      end

      def bilateral?
        left.is_a?(Principal) && right.is_a?(Principal)
      end

      def involves?(principal)
        endpoint?(left, principal) || endpoint?(right, principal)
      end

      def counterpart(principal)
        return right if endpoint?(left, principal)
        return left if endpoint?(right, principal)

        nil
      end

      def matches?(principal, expected_version = nil)
        bilateral? && approved? && involves?(principal) && version_accepted?(expected_version)
      end

      def to_h
        {
          'left' => left&.to_h,
          'right' => right&.to_h,
          'version' => version,
          'status' => status,
          'approved' => approved?,
          'approved_by' => approved_by,
          'reference' => reference
        }
      end
      alias to_hash to_h

      private

      def initial_status(attributes)
        explicit_approval = optional_attribute(attributes, :approved)
        return 'approved' if explicit_approval == true
        return 'pending' if explicit_approval == false

        (optional_attribute(attributes, :status) || 'pending').to_s
      end

      def version_accepted?(expected_version)
        return true if expected_version.nil?
        return false if version.nil?

        version == expected_version.to_s
      end

      def endpoint?(endpoint, principal)
        principal.is_a?(Principal) && endpoint == principal
      end

      def principal_attribute(attributes, *names)
        value = optional_attribute(attributes, *names)
        return if value.nil?
        return value if value.is_a?(Principal)

        Principal.new(value)
      end

      def string_attribute(value)
        value.nil? ? nil : value.to_s
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
