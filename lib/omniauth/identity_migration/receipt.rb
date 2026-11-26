module OmniAuth
  module IdentityMigration
    # The reviewable result of a callback evaluation or explicit conversion.
    class Receipt
      attr_reader :sequence, :kind, :status, :reasons, :principal,
                  :attributed_principal, :target_principal, :mapping,
                  :registration, :auth_provider, :auth_uid, :reference

      def initialize(attributes = nil, **keywords)
        attributes = Hash(attributes).merge(keywords)
        @sequence = integer_attribute(optional_attribute(attributes, :sequence))
        @kind = (optional_attribute(attributes, :kind) || 'event').to_s
        @status = (optional_attribute(attributes, :status) || 'ordinary').to_s
        @reasons = Array(optional_attribute(attributes, :reasons)).collect(&:to_s)
        @principal = object_attribute(attributes, :principal)
        @attributed_principal = object_attribute(attributes, :attributed_principal) || @principal
        @target_principal = object_attribute(attributes, :target_principal)
        @mapping = object_attribute(attributes, :mapping, Mapping)
        @registration = object_attribute(attributes, :registration, Registration)
        @auth_provider = string_attribute(optional_attribute(attributes, :auth_provider, :provider))
        @auth_uid = string_attribute(optional_attribute(attributes, :auth_uid, :uid))
        @reference = string_attribute(optional_attribute(attributes, :reference))
      end

      def ordinary?
        status == 'ordinary'
      end

      def mapped?
        status == 'mapped'
      end

      def pending_review?
        status == 'pending_review'
      end
      alias pending? pending_review?
      alias pending_verification? pending_review?
      alias unverified? pending_review?
      alias needs_review? pending_review?

      def subject
        attributed_principal
      end

      def verification_status
        pending_review? ? 'pending_verification' : status
      end

      def converted?
        status == 'converted'
      end

      def approved_mapping?
        mapping.is_a?(Mapping) && mapping.approved?
      end

      def migration_result
        {
          'status' => status,
          'reference' => reference,
          'source' => principal&.to_h,
          'target' => (target_principal || (mapped? ? attributed_principal : nil))&.to_h,
          'attributed_principal' => attributed_principal&.to_h,
          'mapping' => mapping&.to_h,
          'reasons' => reasons
        }
      end

      def to_h
        {
          'sequence' => sequence,
          'kind' => kind,
          'status' => status,
          'reasons' => reasons,
          'principal' => principal&.to_h,
          'attributed_principal' => attributed_principal&.to_h,
          'target_principal' => target_principal&.to_h,
          'mapping' => mapping&.to_h,
          'registration' => registration.respond_to?(:to_h) ? registration.to_h : registration,
          'auth' => {'provider' => auth_provider, 'uid' => auth_uid},
          'reference' => reference,
          'migration_result' => migration_result
        }
      end
      alias to_hash to_h

      private

      def object_attribute(attributes, name, klass = nil)
        value = optional_attribute(attributes, name)
        return if value.nil?
        return value unless klass
        return value if value.is_a?(klass)
        return value unless value.is_a?(Hash)

        klass.new(value)
      end

      def integer_attribute(value)
        value.nil? ? nil : value.to_i
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
