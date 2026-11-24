# frozen_string_literal: true

module Dry
  module Schema
    # Tracks the approved field that supplied a coerced key value.
    #
    # @api public
    module KeyAttribution
      # A single approved/registered source occurrence.
      Source = ::Struct.new(
        :canonical_path,
        :source_path,
        :raw_source_path,
        :canonical_key,
        :source_key,
        :raw_value,
        :value,
        :alias,
        :permitted,
        :selected,
        :decision,
        keyword_init: true
      ) do
        def alias?
          self.alias
        end

        def permitted?
          permitted
        end

        def selected?
          selected
        end

        def origin_path
          canonical_path
        end

        def input_path
          source_path
        end
      end

      # A collision between two spellings of one approved field.
      Conflict = ::Struct.new(
        :canonical_path,
        :sources,
        :strategy,
        :decision,
        keyword_init: true
      ) do
        def source_paths
          sources.map(&:source_path)
        end

        def error_path
          sources.last&.source_path || canonical_path
        end
      end

      # A policy rejection that should be reported before business rules run.
      Violation = ::Struct.new(:code, :path, :canonical_path, :source, keyword_init: true)

      # Configurable attribution policy.
      class Policy
        STRATEGIES = %i[reject first last merge allow].freeze

        attr_reader :aliases, :conflict_strategy, :allow_aliases, :on_conflict

        def initialize(
          aliases: nil,
          registered_aliases: nil,
          key_aliases: nil,
          approved_fields: nil,
          allow_aliases: true,
          permitted: nil,
          permit_aliases: nil,
          alias_permission: nil,
          conflict: :reject,
          conflict_policy: nil,
          on_conflict: nil,
          **
        )
          alias_map = aliases || registered_aliases || key_aliases || EMPTY_HASH
          permission = alias_permission
          permission = permitted if permission.nil?
          permission = permit_aliases if permission.nil?
          permission = allow_aliases if permission.nil?
          permission = false if permission == :denied || permission == "denied"
          permission = true if permission == :allowed || permission == "allowed"

          @aliases = self.class.normalize_aliases(alias_map)
          @approved_fields = approved_fields
          @allow_aliases = permission
          @conflict_strategy = normalize_strategy(conflict_policy || conflict)
          @on_conflict = on_conflict
        end

        def allow_aliases?
          @allow_aliases
        end

        def resolve_conflict(conflict)
          return on_conflict.call(conflict) if on_conflict

          conflict_strategy
        end

        def self.normalize(config)
          case config
          when Policy then config
          when true then new
          when false, nil then NullPolicy.new
          when ::Symbol then new(conflict: config == :permissive ? :merge : :reject)
          when ::Hash then new(**config.transform_keys(&:to_sym))
          else
            raise ::ArgumentError, "invalid key attribution policy: #{config.inspect}"
          end
        end

        def self.normalize_aliases(value)
          return EMPTY_HASH if value.nil? || value.empty?

          expanded = value.each_with_object({}) do |(key, child), hash|
            if path_key?(key)
              deep_merge!(hash, expand_path(key, child))
            else
              hash[key] = child
            end
          end

          normalize_nested(expanded)
        end

        def self.path_key?(key)
          text = key.to_s
          text.include?(DOT) || text.include?("[]") || text =~ /\[\d+\]/
        end

        def self.expand_path(path, aliases)
          segments = path.to_s.scan(/[^.\[\]]+/)
          segments.reject! { |segment| segment == "[]" || segment =~ /\A\d+\z/ }
          leaf = segments.pop

          segments.reverse.reduce(leaf => aliases) do |child, segment|
            {segment.to_sym => child}
          end
        end

        def self.deep_merge!(left, right)
          right.each do |key, value|
            left[key] = if left[key].is_a?(::Hash) && value.is_a?(::Hash)
                          deep_merge!(left[key], value)
                        elsif left[key].is_a?(::Array) && value.is_a?(::Array)
                          left[key] + value
                        else
                          value
                        end
          end
          left
        end

        def self.normalize_nested(value)
          value.each_with_object({}) do |(key, child), hash|
            normalized_key = key.is_a?(::String) ? key.to_sym : key

            hash[normalized_key] =
              case child
              when ::Array
                child.map { |item| normalize_alias_entry(item) }
              when ::Hash
                if child.key?(:aliases) || child.key?("aliases")
                  child.transform_keys(&:to_sym).then do |opts|
                    aliases = Array(opts[:aliases]).map do |item|
                      normalize_alias_entry(item)
                    end
                    opts.merge(aliases: aliases)
                  end
                else
                  normalize_nested(child)
                end
              else
                [normalize_alias_entry(child)]
              end
          end
        end

        def self.normalize_alias_entry(entry)
          case entry
          when ::Hash
            entry.transform_keys(&:to_sym).tap do |options|
              options[:name] = relative_key(options[:name] || options[:as] || options[:key])
            end
          when ::Symbol, ::String
            {name: relative_key(entry)}
          else
            entry
          end
        end

        def self.relative_key(key)
          text = key.to_s
          last_dot = text.rindex(DOT)
          text = text[(last_dot + 1)..] if last_dot
          text = text[/[^\[\]]+\z/] if text.include?("[")
          text.to_sym
        end

        private

        def normalize_strategy(strategy)
          name = strategy == :allow ? :merge : strategy
          name = :last if name == :merge

          unless STRATEGIES.include?(name)
            raise ::ArgumentError, "unknown key conflict strategy: #{strategy.inspect}"
          end

          name
        end
      end

      # Policy used when attribution was not enabled.
      class NullPolicy < Policy
        def initialize
          super(aliases: EMPTY_HASH, allow_aliases: false, conflict: :reject)
        end
      end

      # Mutable attribution report accumulated while keys are written.
      class Report
        attr_reader :policy, :sources, :conflicts, :violations, :decisions

        def initialize(policy = Policy.new)
          @policy = policy
          @sources = []
          @conflicts = []
          @violations = []
          @decisions = {}
          @origins = {}
          @enforced = false
        end

        def self.null
          @null ||= new(NullPolicy.new).freeze
        end

        def enabled?
          !policy.is_a?(NullPolicy)
        end

        def record(key:, value:, path:, destination:, source_name:)
          canonical_path = [*path, destination]
          source_path = [*path, diagnostic_key(source_name)]
          raw_source_path = [*path, source_name]

          Source.new(
            canonical_path: canonical_path,
            source_path: source_path,
            raw_source_path: raw_source_path,
            canonical_key: destination,
            source_key: source_name,
            raw_value: value,
            alias: key.alias?,
            permitted: key.permitted?,
            selected: false
          ).tap { |source| sources << source }
        end

        def finalize!(output)
          refresh_values!(output)
          groups.each { |canonical_path, entries| evaluate_group(canonical_path, entries, output) }
          build_origins
          self
        end

        def pending_violations
          return [] if @enforced

          @enforced = true
          violations
        end

        def enforced?
          @enforced
        end

        def refresh_values!(output)
          sources.each do |source|
            source.value = dig(output, source.canonical_path)
          end
          self
        end

        def origins
          @origins
        end

        def origin_for(path)
          @origins[Path[path].keys] || @origins[path]
        end

        def source_path_for(path)
          origin_for(path)&.source_path
        end

        def conflict_for(path)
          conflicts.find { |conflict| conflict.canonical_path == Path[path].keys }
        end

        def conflict_paths
          conflicts.map(&:canonical_path)
        end

        def error_paths
          violations.map(&:path)
        end

        def failure?
          violations.any?
        end

        def blocks_rule?(path)
          rule_path = Path[path]
          violations.any? { |violation| Path[violation.canonical_path].include?(rule_path) }
        end

        def success?
          !failure?
        end

        def to_h
          {
            origins: origins.transform_values(&:source_path),
            conflicts: conflicts.map { |conflict|
              {
                path: conflict.canonical_path,
                sources: conflict.source_paths,
                decision: conflict.decision
              }
            },
            violations: violations.map { |violation|
              {
                code: violation.code,
                path: violation.path,
                canonical_path: violation.canonical_path
              }
            }
          }
        end

        private

        def groups
          sources
            .uniq { |source| source.source_path }
            .group_by(&:canonical_path)
        end

        def evaluate_group(canonical_path, entries, output)
          permissions = evaluate_permissions(canonical_path, entries)
          return if permissions

          if entries.size > 1
            conflict = Conflict.new(
              canonical_path: canonical_path,
              sources: entries,
              strategy: policy.conflict_strategy,
              decision: nil
            )
            decision = policy.resolve_conflict(conflict)
            apply_conflict_decision(conflict, decision, output)
            conflicts << conflict
          else
            select(entries.first, :approved)
          end
        end

        def evaluate_permissions(canonical_path, entries)
          denied = entries.select do |source|
            source.alias? && (!policy.allow_aliases? || !source.permitted?)
          end
          return false if denied.empty?

          denied.each do |source|
            decision = :alias_denied
            select(source, decision, selected: false)
            violations << Violation.new(
              code: :alias_not_permitted,
              path: source.source_path,
              canonical_path: canonical_path,
              source: source
            )
          end

          true
        end

        def apply_conflict_decision(conflict, decision, output)
          entries = conflict.sources

          case decision
          when :reject
            conflict.decision = :reject
            entries.each { |source| select(source, :conflict_rejected, selected: false) }
            source = entries.last
            violations << Violation.new(
              code: :conflicting_keys,
              path: source.source_path,
              canonical_path: conflict.canonical_path,
              source: source
            )
          when :first, :first_wins
            conflict.decision = :first
            select(entries.first, :conflict_first)
            set_deep_value(output, conflict.canonical_path, entries.first.raw_value)
          when :last, :last_wins, :merge
            conflict.decision = :merge
            select(entries.last, :conflict_merged)
          else
            selected = entries.find { |source| source == decision } || entries.last
            conflict.decision = :custom
            select(selected, :conflict_custom)
          end
        end

        def select(source, decision, selected: true)
          source.decision = decision
          source.selected = selected
          decisions[source.canonical_path] = decision
        end

        def build_origins
          sources.select(&:selected?).each do |source|
            @origins[source.canonical_path] = source
            @origins[format_path(source.canonical_path)] = source
          end
        end

        def diagnostic_key(key)
          case key
          when ::Integer, ::Symbol then key
          when ::String then key.to_sym
          else
            key
          end
        end

        def format_path(path)
          path.each_with_object(+"") do |segment, string|
            if segment.is_a?(::Integer)
              string << "[#{segment}]"
            else
              string << DOT unless string.empty?
              string << segment.to_s
            end
          end
        end

        def dig(output, path)
          path.reduce(output) do |value, key|
            case value
            when ::Hash
              value[key]
            when ::Array
              value[key] if key.is_a?(::Integer)
            end
          end
        end

        def set_deep_value(output, path, value)
          parent_path = path[0...-1]
          key = path.last
          parent = parent_path.empty? ? output : dig(output, parent_path)
          parent[key] = value if parent.respond_to?(:[]=)
        end
      end

      # Adds registered alias keys to a runtime KeyMap.
      module AliasMap
        module_function

        def apply(key_map, aliases, root_aliases = aliases)
          aliases ||= EMPTY_HASH
          root_aliases ||= EMPTY_HASH
          return key_map if aliases.empty? && root_aliases.empty?

          ::Dry::Schema::KeyMap.new(apply_to_keys(key_map.keys, aliases, root_aliases))
        end

        def apply_to_keys(keys, aliases, root_aliases = aliases)
          keys.flat_map do |key|
            spec = aliases[key.id] || aliases[key.id.to_s] ||
                   root_aliases[key.id] || root_aliases[key.id.to_s]
            transformed = transform_key(key, spec, root_aliases)
            alias_entries = alias_entries_for(spec)

            [transformed] + alias_entries.map { |entry| build_alias_key(key, entry) }
          end
        end

        def transform_key(key, spec, root_aliases)
          child_aliases = child_aliases_for(spec)

          case key
          when ::Dry::Schema::Key::Hash
            key.new(members: apply(key.members, child_aliases || EMPTY_HASH, root_aliases))
          when ::Dry::Schema::Key::Array
            key.new(member: apply(key.member, child_aliases || EMPTY_HASH, root_aliases))
          else
            key
          end
        end

        def build_alias_key(canonical_key, entry)
          options = entry.is_a?(::Hash) ? entry : {name: entry}
          name = options[:name] || options[:as] || options[:key]
          permitted = options.fetch(:permitted, options.fetch(:allow, true))

          canonical_key.new(
            name: name,
            target: canonical_key.target,
            alias_source: true,
            permitted: permitted
          )
        end

        def alias_entries_for(spec)
          case spec
          when ::Array then spec
          when ::Hash then spec[:aliases] || spec["aliases"] || []
          else
            []
          end
        end

        def child_aliases_for(spec)
          return unless spec.is_a?(::Hash)

          spec.reject { |key, _| %i[aliases permitted allow conflict name as].include?(key.to_sym) }
        end
      end
    end
  end
end
