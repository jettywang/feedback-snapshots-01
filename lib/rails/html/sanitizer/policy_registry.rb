# frozen_string_literal: true

require "thread"
require_relative "policy"

module Rails
  module HTML
    class Sanitizer
      # A thread-safe, copy-on-write collection of immutable sanitization
      # policies.
      #
      # Publication is atomic: readers either see the registry before or after
      # a publication, never a half-updated set of versions. A policy that has
      # been handed to an in-flight message is a value object and is unaffected
      # by later publications.
      #
      #   registry = Rails::HTML::Sanitizer::PolicyRegistry.new
      #   registry.publish(name: "tenant-a", version: 1, tags: %w[p b])
      #   registry.publish(name: "tenant-a", version: 2, tags: %w[p b a])
      #
      #   registry.fetch("tenant-a", 1)      # => tenant-a@1
      #   registry.current("tenant-a")       # => tenant-a@2
      #   registry.resolve("tenant-a@1")     # => tenant-a@1
      class PolicyRegistry
        EMPTY_ENTRY = { versions: {}.freeze, current: nil }.freeze

        def initialize(policies = [])
          @mutex = Mutex.new
          @state = {}.freeze
          Array(policies).each { |policy| publish(policy) }
        end

        # Publish one immutable version. Publishing the exact same content is
        # idempotent; publishing different content under an existing version is
        # a conflict and leaves the registry untouched.
        #
        # The newly published version becomes current unless +current:+ is
        # false. Versions may be published in any order, which supports
        # backfilling historical policies without changing what is current.
        def publish(policy = nil, current: true, **attributes)
          policy = coerce_policy(policy, attributes)

          @mutex.synchronize do
            state = @state
            name = policy.name
            version_key = policy.version_key
            entry = state.fetch(name, EMPTY_ENTRY)
            versions = entry[:versions]
            existing = versions[version_key]

            if existing
              if existing.digest == policy.digest
                return existing
              end

              raise PolicyConflictError,
                "sanitization policy #{policy.reference} is already published with different content " \
                "(existing digest #{existing.digest[0, 12]}, new digest #{policy.digest[0, 12]})"
            end

            new_versions = versions.merge(version_key => policy).freeze
            current_policy = current ? policy : entry[:current]
            new_entry = { versions: new_versions, current: current_policy }.freeze

            # One assignment publishes the whole entry, so concurrent readers
            # see either all of the old state or all of the new state.
            @state = state.merge(name => new_entry).freeze
            policy
          end
        end
        alias register publish
        alias add publish
        alias define publish

        # Make an already-published version current again, which is the
        # rollback path when a rollout needs to be reverted. The version must
        # already exist; this never invents a new policy.
        def promote(name, version)
          policy_name = normalize_name(name)
          version_key = normalize_version(version)

          @mutex.synchronize do
            state = @state
            entry = state[policy_name]
            unless entry
              raise PolicyNotFoundError,
                "unknown sanitization policy #{policy_name.inspect}; published policies: #{published_names_message}"
            end

            policy = entry[:versions][version_key]
            unless policy
              raise PolicyNotFoundError,
                "unknown version #{version.inspect} for sanitization policy #{policy_name.inspect}; " \
                "published versions: #{entry[:versions].keys.inspect}"
            end

            @state = state.merge(policy_name => { versions: entry[:versions], current: policy }.freeze).freeze
            policy
          end
        end
        alias rollback promote
        alias activate promote

        # Fetch an exact version, or the current version when +version+ is nil.
        def fetch(name, version = nil)
          name = normalize_name(name)
          entry = @state[name]

          unless entry
            raise PolicyNotFoundError,
              "unknown sanitization policy #{name.inspect}; published policies: #{published_names_message}"
          end

          if version.nil?
            entry[:current] || raise_policy_not_found(name, nil, entry[:versions])
          else
            entry[:versions][normalize_version(version)] || raise_policy_not_found(name, version, entry[:versions])
          end
        end
        alias [] fetch
        alias get fetch

        def current(name)
          fetch(name)
        end
        alias current_policy current

        def current_version(name)
          fetch(name).version
        end

        # Resolve a Policy, a "name@version" reference, a versioned Hash, or a
        # bare name (symbol or string) for the current version.
        def resolve(reference)
          case reference
          when Policy
            reference
          when Array
            unless reference.length == 2
              raise InvalidPolicyError, "invalid sanitization policy reference #{reference.inspect}"
            end
            fetch(reference[0], reference[1])
          when Hash
            name = reference.key?(:name) ? reference[:name] : reference["name"]
            version = reference.key?(:version) ? reference[:version] : reference["version"]
            fetch(name, version)
          when Symbol
            fetch(reference.to_s)
          when String
            if reference.include?("@")
              name, _, version = reference.rpartition("@")
              fetch(name, version)
            else
              fetch(reference)
            end
          else
            raise InvalidPolicyError,
              "invalid sanitization policy reference #{reference.inspect}: expected a Policy, name, or name@version"
          end
        end
        alias find resolve

        # Derive the next version from the current one and publish it. Useful
        # for the common "add one tag for one tenant" rollout. The caller may
        # still pass an explicit +version:+.
        def publish_next(name, version: nil, **overrides)
          base = current(name)
          version ||= next_version_number(base.version)
          publish_policy = base.derive(version: version, **overrides)
          publish(publish_policy)
        end
        alias next_version publish_next

        def published?(name, version = nil)
          fetch(name, version)
          true
        rescue PolicyNotFoundError
          false
        end
        alias key? published?

        # Version strings for +name+, in publication order.
        def versions(name)
          entry_for(name)[:versions].keys.freeze
        end

        # Immutable Policy objects for +name+, in publication order.
        def policies(name)
          entry_for(name)[:versions].values.freeze
        end

        def names
          @state.keys.freeze
        end

        def size
          @state.values.sum { |entry| entry[:versions].size }
        end

        # A frozen point-in-time copy of the registry. Useful when a caller
        # needs to show exactly which policies were available at a moment.
        def snapshot
          @state.each_with_object({}) do |(name, entry), result|
            result[name] = entry[:versions].dup.freeze
          end.freeze
        end

        def inspect
          "#<#{self.class.name} names=#{names.inspect} size=#{size}>"
        end

        private
          def coerce_policy(policy, attributes)
            if policy.nil?
              Policy.new(**attributes)
            elsif policy.is_a?(Policy)
              unless attributes.empty?
                raise InvalidPolicyError,
                  "invalid sanitization policy publication: cannot combine a Policy with #{attributes.keys.map(&:inspect).join(", ")}"
              end
              policy
            elsif policy.is_a?(Hash)
              unless attributes.empty?
                raise InvalidPolicyError,
                  "invalid sanitization policy publication: pass either a Hash or keyword arguments, not both"
              end
              Policy.new(**policy)
            else
              raise InvalidPolicyError,
                "invalid sanitization policy publication #{policy.inspect}: expected a Policy or a Hash of attributes"
            end
          end

          def entry_for(name)
            name = normalize_name(name)
            @state[name] || raise(PolicyNotFoundError,
              "unknown sanitization policy #{name.inspect}; published policies: #{published_names_message}")
          end

          def next_version_number(version)
            if version.is_a?(Integer)
              version + 1
            elsif version.to_s.match?(/\A\d+\z/)
              version.to_i + 1
            else
              raise InvalidPolicyError,
                "cannot infer the next version from #{version.inspect}; pass version: explicitly"
            end
          end

          def normalize_name(name)
            name.to_s
          end

          def normalize_version(version)
            version.to_s
          end

          def raise_policy_not_found(name, version, versions)
            if version.nil?
              raise PolicyNotFoundError,
                "sanitization policy #{name.inspect} has no current version; published versions: #{versions.keys.inspect}"
            else
              raise PolicyNotFoundError,
                "unknown version #{version.inspect} for sanitization policy #{name.inspect}; " \
                "published versions: #{versions.keys.inspect}"
            end
          end

          def published_names_message
            names.empty? ? "(none)" : names.inspect
          end
      end
    end

    # Convenience alias for callers who treat the registry as part of the
    # general HTML namespace rather than the Sanitizer class.
    PolicyRegistry = Sanitizer::PolicyRegistry
  end
end
