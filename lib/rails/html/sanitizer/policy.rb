# frozen_string_literal: true

require "digest"

require_relative "../scrubbers"

module Rails
  module HTML
    class Sanitizer
      # A marker module included in every error raised by the policy machinery.
      # It is deliberately a module so the concrete errors can also inherit
      # from the exception classes callers naturally rescue (ArgumentError,
      # KeyError) without giving up a single catch-all.
      module PolicyError
      end

      class InvalidPolicyError < ArgumentError
        include PolicyError
      end

      class PolicyConflictError < ArgumentError
        include PolicyError
      end

      class PolicyNotFoundError < KeyError
        include PolicyError
      end

      # An immutable, versioned description of the permissions used to sanitize
      # one piece of content.
      #
      # A policy is a value object. Every collection it exposes is copied and
      # frozen, so changing the arrays an application used to build it, or
      # publishing a newer version, cannot change a policy that is already in
      # use by an in-flight email.
      class Policy
        # Tags which cannot be safely allowed by PermitScrubber, or which turn
        # an email fragment into an active document. Publishing any of these is
        # an error rather than silently producing a policy whose declared
        # permissions differ from the effective ones.
        UNSAFE_ALLOWED_TAGS = %w[
          applet base basefont bgsound embed frame frameset iframe link meta
          malignmark mglyph noframes noscript object param script style
        ].freeze

        # Event-handler attributes execute script and are never valid rich-text
        # permissions. Namespace declarations are also rejected because they
        # make namespace-confusion attacks easier to construct.
        UNSAFE_ALLOWED_ATTRIBUTES = /\A(?:on|xmlns(?:\z|:))/i

        NAME_PATTERN = /\A[^\s@]+\z/
        TOKEN_PATTERN = /\A[^\s<>"'\/=]+\z/

        attr_reader :name, :version, :allowed_tags, :allowed_attributes, :digest

        def initialize(name:, version:, allowed_tags: nil, allowed_attributes: nil, tags: nil, attributes: nil, prune: false, **unknown)
          unless unknown.empty?
            raise InvalidPolicyError, "invalid sanitization policy: unknown option(s) #{unknown.keys.map(&:inspect).join(", ")}"
          end

          @name = normalize_name(name)
          @version = normalize_version(version)
          @allowed_tags = normalize_tokens(allowed_tags.nil? ? tags : allowed_tags, :allowed_tags, default_allowed_tags)
          @allowed_attributes = normalize_tokens(
            allowed_attributes.nil? ? attributes : allowed_attributes,
            :allowed_attributes,
            default_allowed_attributes,
          )
          @prune = prune ? true : false
          @digest = compute_digest
          freeze
        end

        def tags
          @allowed_tags
        end

        def attributes
          @allowed_attributes
        end

        def prune
          @prune
        end

        def prune?
          @prune
        end

        # Stable, human-readable marker for this exact policy version.
        def reference
          "#{name}@#{version}"
        end
        alias id reference
        alias marker reference
        alias to_s reference

        def key
          [name, version.to_s].freeze
        end

        def version_key
          version.to_s
        end

        def ==(other)
          other.is_a?(Policy) && reference == other.reference && digest == other.digest
        end
        alias eql? ==

        def hash
          [reference, digest].hash
        end

        # Build a new policy version from this one. Any permission omitted
        # from +overrides+ is inherited, which makes gradual tenant rollouts
        # explicit and reviewable.
        #
        #   policy.v2(tags: policy.allowed_tags + %w[u])
        def derive(version:, **overrides)
          overrides = overrides.dup
          overrides[:allowed_tags] = overrides.delete(:tags) if overrides.key?(:tags)
          overrides[:allowed_attributes] = overrides.delete(:attributes) if overrides.key?(:attributes)
          unknown = overrides.keys - %i[allowed_tags allowed_attributes prune]
          unless unknown.empty?
            raise InvalidPolicyError,
              "invalid sanitization policy derivation: unknown override(s) #{unknown.map(&:inspect).join(", ")}"
          end

          self.class.new(
            name: name,
            version: version,
            allowed_tags: overrides.fetch(:allowed_tags, allowed_tags),
            allowed_attributes: overrides.fetch(:allowed_attributes, allowed_attributes),
            prune: overrides.fetch(:prune, prune?),
          )
        end
        alias with derive

        def to_h
          {
            name: name,
            version: version,
            reference: reference,
            digest: digest,
            allowed_tags: allowed_tags,
            allowed_attributes: allowed_attributes,
            prune: prune?,
          }.freeze
        end

        def inspect
          "#<#{self.class.name} #{reference} tags=#{allowed_tags.inspect} attributes=#{allowed_attributes.inspect} prune=#{prune?}>"
        end

        private
          def normalize_name(value)
            name = value.to_s.dup
            if name.empty? || !NAME_PATTERN.match?(name)
              raise InvalidPolicyError, "invalid sanitization policy name #{value.inspect}: expected a non-empty string without whitespace"
            end
            name.freeze
          end

          def normalize_version(value)
            if value.nil?
              raise InvalidPolicyError, "invalid sanitization policy: version is required"
            end
            version = value.is_a?(String) ? value.dup : value
            if version.to_s.empty? || version.to_s.include?("@")
              raise InvalidPolicyError,
                "invalid sanitization policy: version must be non-empty and must not contain '@' (got #{value.inspect})"
            end
            version.freeze if version.is_a?(String)
            version
          end

          def normalize_tokens(value, field, fallback)
            value = fallback if value.nil?
            unless value.is_a?(Enumerable) && !value.is_a?(String) && !value.is_a?(Hash)
              raise InvalidPolicyError,
                "invalid sanitization policy: #{field} must be an Enumerable of names (got #{value.class})"
            end

            seen = {}
            value.each_with_object([]) do |token, result|
              normalized = token.to_s.downcase
              if normalized.empty? || !TOKEN_PATTERN.match?(normalized)
                raise InvalidPolicyError,
                  "invalid sanitization policy: #{field} contains an invalid name #{token.inspect}"
              end

              if field == :allowed_tags && UNSAFE_ALLOWED_TAGS.include?(normalized)
                raise InvalidPolicyError,
                  "invalid sanitization policy: #{field} cannot allow #{normalized.inspect}"
              end

              if field == :allowed_attributes && UNSAFE_ALLOWED_ATTRIBUTES.match?(normalized)
                raise InvalidPolicyError,
                  "invalid sanitization policy: #{field} cannot allow #{normalized.inspect}"
              end

              next if seen[normalized]
              seen[normalized] = true
              result << normalized.freeze
            end.freeze
          end

          def default_allowed_tags
            Rails::HTML::Concern::Scrubber::SafeList::DEFAULT_ALLOWED_TAGS
          end

          def default_allowed_attributes
            Rails::HTML::Concern::Scrubber::SafeList::DEFAULT_ALLOWED_ATTRIBUTES
          end

          def compute_digest
            material = [
              name,
              version.to_s,
              prune? ? "1" : "0",
              allowed_tags.sort.join(","),
              allowed_attributes.sort.join(","),
            ].join("\u0000")
            Digest::SHA256.hexdigest(material)
          end
      end

      # Aliases kept for callers who prefer the explicit names.
      SanitizationPolicy = Policy
      VersionedPolicy = Policy
      Error = PolicyError
    end
  end
end
