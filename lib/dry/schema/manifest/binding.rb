# frozen_string_literal: true

module Dry
  module Schema
    module Manifest
      # The callable bound to a predicate occurrence in the compiled rule
      #
      # A binding is "builtin" only when it resolves to the canonical
      # `Dry::Logic::Predicates` implementation shipped by the `dry-logic` gem
      # and its body can be read. Its identity is the gem-relative source path
      # plus a digest of the method body, so it can be rechecked offline against
      # the installed gem without executing anything. A gem upgrade that leaves
      # the body untouched keeps the same identity.
      #
      # Every other binding (custom predicate modules, methods redefined at
      # runtime, dynamic `define_method` predicates, C methods, non-gem code) is
      # recorded with kind "runtime": its behaviour can be confirmed only at
      # runtime, which this manifest deliberately does not do. Those entries
      # remain approval-required even when their offline signature matches.
      #
      # @api private
      class Binding
        # @return [Symbol] predicate name as compiled (`:min_size?`)
        attr_reader :name

        # @return [String, nil] gem-relative source path, absolute otherwise
        attr_reader :source_path

        # @return [Integer, nil] source line, recorded as evidence
        attr_reader :source_line

        # @return [String, nil] owner module name, or attached module name
        attr_reader :owner

        # @return [String] "builtin" or "runtime"
        attr_reader :kind

        # @api private
        def initialize(name:, method:, registry:)
          @name = name
          @method = method
          @registry = registry
          @raw_source_path, @source_line = method.source_location
          @source_path = Source.gem_relative(@raw_source_path) ||
            Source.app_relative(@raw_source_path)
          @owner = owner_name(method)
          @kind = classify
        end

        # @return [Boolean]
        # @api private
        def builtin?
          kind == "builtin"
        end

        # @api private
        def gem
          gem_spec&.first
        end

        # @api private
        def gem_version
          gem_spec&.last
        end

        # @api private
        def body_digest
          return @body_digest if defined?(@body_digest)

          body = Source.body(@method)
          @body_digest = body && ::Digest::SHA256.hexdigest(body)
        end

        # @api private
        def registry_name
          predicates = @registry.predicates
          custom = predicates.respond_to?(:name) && predicates.name
          custom || @registry.class.name || @registry.class.inspect
        end

        # Stable identifier for an approvable built-in rule occurrence
        #
        # Covers the predicate name, arguments, canonical owner, gem-relative
        # source path, and body digest. It excludes the gem version and line
        # number on purpose: a patch upgrade that leaves the implementation
        # byte-identical must not force re-approval.
        #
        # @api private
        def stable_id(args:)
          return unless builtin?

          "dry-schema-predicate/v1:#{Canonical.digest(identity(args))}"
        end

        # Identity of the code that will actually run
        #
        # Built-in bindings use the stable id. Runtime bindings use owner, source
        # location and registry, the strongest offline statement available; they
        # stay approval-required because equal metadata does not prove equal
        # behaviour.
        #
        # @api private
        def signature(args:)
          if builtin?
            stable_id(args: args)
          else
            "runtime:#{Canonical.digest(identity(args))}"
          end
        end

        # @api private
        def identity(args)
          {
            "predicate" => name.to_s,
            "args" => args,
            "owner" => owner,
            "gem" => gem,
            "source_path" => source_path,
            "body_sha256" => body_digest,
            "runtime_registry" => builtin? ? nil : registry_name
          }
        end

        # @api private
        def evidence_gap
          if owner == BUILTIN_PREDICATE_OWNER
            "The bound method is #{BUILTIN_PREDICATE_OWNER}, but #{BUILTIN_PREDICATE_GEM} " \
              "does not ship its source or the source is unreadable, so the implementation " \
              "cannot be verified offline."
          else
            "Predicate is bound to #{owner.inspect} (registry #{registry_name.inspect}), not to " \
              "#{BUILTIN_PREDICATE_OWNER}. Its implementation cannot be verified offline; " \
              "confirm it at runtime in an isolated check."
          end
        end

        # @api private
        def notes
          return [] if builtin? || registry_name == BUILTIN_REGISTRY

          ["Resolved through custom predicate registry #{registry_name.inspect}"]
        end

        # @api private
        def to_h(args:)
          if builtin?
            {
              "kind" => "builtin",
              "stable_id" => stable_id(args: args),
              "signature" => signature(args: args),
              "predicate" => name.to_s,
              "args" => args,
              "owner" => owner,
              "gem" => gem,
              "gem_version" => gem_version,
              "source" => source_path && {"path" => source_path, "line" => source_line},
              "body_sha256" => body_digest,
              "registry" => registry_name
            }
          else
            {
              "kind" => "runtime",
              "stable_id" => nil,
              "signature" => signature(args: args),
              "predicate" => name.to_s,
              "args" => args,
              "owner" => owner,
              "source" => @raw_source_path && {"path" => source_path, "line" => source_line},
              "registry" => registry_name,
              "evidence_gap" => evidence_gap,
              "notes" => notes
            }
          end
        end

        private

        # @api private
        def gem_spec
          return @gem_spec if defined?(@gem_spec)

          @gem_spec = Source.gem_for(@raw_source_path)
        end

        # @api private
        def classify
          return "runtime" unless owner == BUILTIN_PREDICATE_OWNER
          return "runtime" unless gem_spec&.first == BUILTIN_PREDICATE_GEM
          return "runtime" if body_digest.nil?

          "builtin"
        end

        # @api private
        def owner_name(method)
          owner = method.owner

          if owner.singleton_class?
            attached = owner.respond_to?(:attached_object) ? owner.attached_object : nil
            (attached.respond_to?(:name) && attached.name) || method.receiver.inspect
          else
            owner.name || owner.inspect
          end
        end
      end
    end
  end
end
