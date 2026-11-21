# frozen_string_literal: true

require "thread"
require_relative "policy"
require_relative "policy_registry"

module Rails
  module HTML
    class Sanitizer
      # The result of a managed sanitization.
      #
      # It behaves like the sanitized String (so existing call sites that treat
      # the return value as text keep working) and carries the exact policy that
      # was used, so an operator can locate which permission set produced a
      # given email.
      class ManagedResult < String
        attr_reader :policy, :policy_reference, :policy_version, :policy_digest

        def initialize(value, policy)
          super(value.to_s)
          @policy = policy
          @policy_reference = policy.reference
          @policy_version = policy.version
          @policy_digest = policy.digest
          freeze
        end

        def policy_name
          policy.name
        end

        def tags
          policy.allowed_tags
        end

        def attributes
          policy.allowed_attributes
        end

        def prune?
          policy.prune?
        end

        def to_s
          String.new(self)
        end

        def to_h
          {
            reference: policy_reference,
            name: policy_name,
            version: policy_version,
            digest: policy_digest,
            policy: policy.to_h,
          }.freeze
        end

        def inspect
          "#<#{self.class.name} #{policy_reference} #{String.new(self).inspect}>"
        end

        # Whether another result was produced by the same policy version.
        # Text equality deliberately remains plain String equality so legacy
        # callers are not surprised when two versions render identical output.
        def same_policy?(other)
          other.respond_to?(:policy_digest) && policy_digest == other.policy_digest
        end
      end

      # A policy captured for the lifetime of one piece of content.
      #
      # Resolve a session once at the start of a mail job and use it for every
      # fragment of that message. The session keeps the same immutable policy
      # even if the registry later publishes a newer version.
      #
      #   session = managed.with_policy("tenant-a@3")
      #   session.sanitize(header_html).policy_reference # => "tenant-a@3"
      #   session.sanitize(body_html).policy_reference   # => "tenant-a@3"
      class PolicySession
        attr_reader :managed_sanitizer, :policy

        def initialize(managed_sanitizer, policy)
          @managed_sanitizer = managed_sanitizer
          @policy = policy
        end

        def reference
          policy.reference
        end
        alias policy_reference reference

        def version
          policy.version
        end
        alias policy_version version

        def digest
          policy.digest
        end
        alias policy_digest digest

        def name
          policy.name
        end
        alias policy_name name

        def sanitize(html, **options)
          managed_sanitizer.sanitize(html, policy: policy, **options)
        end
        alias sanitize_with_policy sanitize

        def to_h
          policy.to_h
        end

        def inspect
          "#<#{self.class.name} #{reference}>"
        end
      end

      # A sanitizer bound to a registry. Each call resolves a policy exactly
      # once, then uses that same immutable object for the entire operation.
      # Any later publication changes only what future calls resolve; it cannot
      # alter an in-flight message.
      #
      #   managed = Rails::HTML5::SafeListSanitizer.managed(registry)
      #   result = managed.sanitize(html, policy: "tenant-a@3")
      #   result.include?("<u>")        # => true
      #   result.policy_reference       # => "tenant-a@3"
      #
      # The underlying sanitizer keeps the caller's original class-level
      # configuration, so applications that never touch the policy API behave
      # exactly as before.
      class ManagedSanitizer
        attr_reader :sanitizer, :registry

        def initialize(sanitizer, registry)
          unless sanitizer.respond_to?(:sanitize)
            raise ArgumentError, "managed sanitizer requires a sanitizer that responds to sanitize"
          end
          unless registry.respond_to?(:resolve) && registry.respond_to?(:fetch)
            raise ArgumentError, "managed sanitizer requires a PolicyRegistry"
          end

          @sanitizer = sanitizer
          @registry = registry
          @prune_sanitizers = {}
          @prune_mutex = Mutex.new
        end

        # Sanitize +html+ with a versioned policy.
        #
        # +policy+ may be a Policy, "name@version", [name, version], a Hash, or
        # a bare name for the current version. When omitted, +policy_name:+ is
        # required.
        #
        # Options that change the permission set (tags:, attributes:,
        # scrubber:, allowed_tags:, allowed_attributes:, prune:) are rejected so
        # the recorded policy is always the permission set that was applied.
        # Non-permission options are passed through.
        def sanitize(html, policy: nil, policy_name: nil, policy_version: nil, **options)
          rejection = permission_options(options)
          unless rejection.empty?
            raise InvalidPolicyError,
              "managed sanitization cannot override the resolved policy with #{rejection.map(&:inspect).join(", ")}; " \
              "publish a new policy version instead"
          end

          resolved = resolve_policy(policy, policy_name, policy_version)
          output = sanitizer_for(resolved).sanitize(
            html,
            tags: resolved.allowed_tags,
            attributes: resolved.allowed_attributes,
            **options,
          )
          return nil if output.nil?

          ManagedResult.new(output, resolved)
        end
        alias sanitize_with_policy sanitize

        # Capture one policy for repeated use by a single message/job.
        #
        # Accepts the same references as +sanitize+. The returned session does
        # not consult the registry again, so later publications cannot change
        # the permissions used by an in-flight email.
        def with_policy(reference = nil, version: nil, name: nil)
          session = PolicySession.new(self, resolve_policy(reference, name, version))
          return session unless block_given?

          yield session
        end
        alias bind_policy with_policy
        alias session with_policy

        # Resolve a policy without sanitizing. Raises the same errors, which is
        # useful for failing a mail job early when the wrong version was
        # requested.
        def policy(reference = nil, version: nil, name: nil)
          resolve_policy(reference, name, version)
        end
        alias resolve_policy_ref policy

        # The definition of the policy that would be used.
        def explain(reference = nil, version: nil, name: nil)
          policy(reference, version: version, name: name).to_h
        end

        private
          PERMISSION_OPTIONS = %i[tags attributes allowed_tags allowed_attributes scrubber prune].freeze

          def permission_options(options)
            options.keys.select { |key| PERMISSION_OPTIONS.include?(key.to_sym) }
          end

          def resolve_policy(reference, name, version)
            if reference.nil? && name.nil?
              raise InvalidPolicyError,
                "managed sanitization requires a policy (pass policy: or policy_name:)"
            end

            if reference
              if name || version
                raise InvalidPolicyError,
                  "managed sanitization: pass either policy: or policy_name:/policy_version:, not both"
              end
              registry.resolve(reference)
            else
              registry.fetch(name, version)
            end
          end

          # Safe-list sanitizers capture +prune+ at construction. When a policy
          # selects the other mode, keep a small per-mode cache rather than
          # mutating the caller's sanitizer.
          def sanitizer_for(policy)
            return sanitizer unless sanitizer.respond_to?(:prune?)

            return sanitizer if sanitizer.prune? == policy.prune?

            @prune_mutex.synchronize do
              @prune_sanitizers[policy.prune?] ||= sanitizer.class.new(prune: policy.prune?)
            end
          end
      end

      # Adds versioned-policy entry points to the safe-list sanitizer classes.
      #
      #   registry = PolicyRegistry.new
      #   registry.publish(name: "tenant-a", version: 1, tags: %w[p b])
      #   Rails::HTML5::SafeListSanitizer.managed(registry).sanitize(html, policy: "tenant-a@1")
      #
      # Legacy callers that never use these methods continue to use the class
      # level +allowed_tags+ / +allowed_attributes+ configuration.
      module PolicyManaged
        def self.included(base)
          base.extend(ClassMethods)
        end

        module ClassMethods
          def policy_registry
            Rails::HTML::Sanitizer.policy_registry
          end

          def publish_policy(policy = nil, **attributes)
            policy_registry.publish(policy, **attributes)
          end

          def managed(registry = policy_registry, prune: false)
            ManagedSanitizer.new(new(prune: prune), registry)
          end
        end

        def managed(registry = self.class.policy_registry)
          ManagedSanitizer.new(self, registry)
        end

        # Legacy-compatible instance entry point. The signature is unchanged;
        # passing +policy:+ or +policy_name:+ in the options Hash switches to
        # the managed path for that call.
        #
        #   Rails::HTML5::SafeListSanitizer.new.sanitize(html, policy: "tenant-a@3")
        def sanitize(html, options = {})
          unless options.is_a?(Hash) && (options.key?(:policy) || options.key?(:policy_name))
            return super
          end

          options = options.dup
          registry = options.delete(:registry) || self.class.policy_registry
          ManagedSanitizer.new(self, registry).sanitize(html, **options)
        end

        def sanitize_with_policy(html, **options)
          managed.sanitize(html, **options)
        end
      end
    end

    # Convenience aliases.
    ManagedResult = Sanitizer::ManagedResult
    ManagedSanitizer = Sanitizer::ManagedSanitizer
    PolicySession = Sanitizer::PolicySession
  end
end
