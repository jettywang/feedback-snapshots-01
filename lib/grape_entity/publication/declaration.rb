# frozen_string_literal: true

module Grape
  class Entity
    module Publication
      # Opt-in contract describing which fields may be published, which are
      # mandatory, and how optional fields degrade when their formatter fails.
      #
      #   class Review < Grape::Entity
      #     publication do
      #       mandatory :id
      #       allow :id, :name, :details
      #       on_optional_failure :omit
      #     end
      #   end
      class Declaration
        DEFAULT_OPTIONAL_POLICY = :omit
        OPTIONAL_POLICIES = %i[omit null abort].freeze

        attr_reader :mandatory_fields, :allowed_fields, :optional_policy

        def initialize
          @mandatory_fields = []
          @allowed_fields = nil
          @optional_policy = DEFAULT_OPTIONAL_POLICY
          @retain = true
        end

        def initialize_copy(other)
          super
          @mandatory_fields = other.mandatory_fields.map(&:dup)
          @allowed_fields = other.allowed_fields&.map(&:dup)
        end

        # Declare fields that must be present for a result to be delivered.
        # Accepts symbols, strings with dotted paths ("nested.field"), or arrays.
        def mandatory(*fields)
          @mandatory_fields |= normalize_paths(fields)
          self
        end
        alias require_fields mandatory

        # Restrict delivery to an allowlist. When omitted, every exposed field
        # is permitted.
        def allow(*fields)
          @allowed_fields ||= []
          @allowed_fields |= normalize_paths(fields)
          self
        end
        alias permit allow

        def on_optional_failure(policy)
          policy = policy.to_sym
          unless OPTIONAL_POLICIES.include?(policy)
            raise ArgumentError, "Unknown optional failure policy: #{policy.inspect}"
          end

          @optional_policy = policy
          self
        end

        # Whether a failed publication should keep the previous stable
        # representation available to callers.
        def retain(value = true)
          @retain = value
          self
        end

        def retain?
          @retain
        end

        def mandatory?(field)
          mandatory_fields.any? { |candidate| candidate == Array(field) }
        end

        def allowlist?
          !@allowed_fields.nil?
        end

        # A field is allowed when it is on the allowlist or when it is the
        # parent of an allowlisted nested path. Parent traversal lets nested
        # declarations filter their own children instead of dropping the whole
        # branch.
        def allowed?(field)
          return true unless allowlist?

          path = Array(field)
          allowed_fields.any? do |allowed|
            allowed == path ||
              prefix?(path, allowed) ||
              prefix?(allowed, path)
          end
        end

        # Called by `expose mandatory: true`. The field is registered by its
        # public key, which is the key reviewers see.
        def register_mandatory_key(key)
          path = Array(key).map { |part| part.to_sym }
          @mandatory_fields |= [path]
          self
        end

        def to_h
          {
            mandatory: mandatory_fields,
            allowed: allowed_fields,
            optional_policy: optional_policy,
            retain: retain?
          }
        end

        private

        def prefix?(prefix, path)
          path[0, prefix.length] == prefix
        end

        def normalize_paths(fields)
          fields.flatten.map do |field|
            case field
            when Array
              field.map(&:to_sym)
            when String
              field.split('.').map(&:to_sym)
            else
              [field.to_sym]
            end
          end
        end
      end
    end
  end
end
