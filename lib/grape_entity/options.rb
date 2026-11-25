# frozen_string_literal: true

require 'forwardable'

module Grape
  class Entity
    class Options
      extend Forwardable

      attr_reader :opts_hash

      def_delegators :opts_hash, :dig, :key?, :fetch, :[], :empty?

      def initialize(opts_hash = {})
        @opts_hash = opts_hash
        @has_only = !opts_hash[:only].nil?
        @has_except = !opts_hash[:except].nil?
        @for_nesting_cache = {}
        @should_return_key_cache = {}
      end

      def merge(new_opts)
        return self if new_opts.empty?

        merged = if new_opts.instance_of? Options
                   @opts_hash.merge(new_opts.opts_hash)
                 else
                   @opts_hash.merge(new_opts)
                 end

        Options.new(merged)
      end

      def reverse_merge(new_opts)
        return self if new_opts.empty?

        merged = if new_opts.instance_of? Options
                   new_opts.opts_hash.merge(@opts_hash)
                 else
                   new_opts.merge(@opts_hash)
                 end

        Options.new(merged)
      end

      def ==(other)
        other_hash = other.is_a?(Options) ? other.opts_hash : other
        @opts_hash == other_hash
      end

      def should_return_key?(key)
        return true unless @has_only || @has_except

        only = only_fields.nil? ||
               only_fields.key?(key)
        except = except_fields&.key?(key) &&
                 except_fields[key] == true
        only && !except
      end

      def for_nesting(key)
        @for_nesting_cache[key] ||= build_for_nesting(key)
      end

      def only_fields(for_key = nil)
        return nil unless @has_only

        @only_fields ||= @opts_hash[:only].each_with_object({}) do |attribute, allowed_fields|
          build_symbolized_hash(attribute, allowed_fields)
        end

        only_for_given(for_key, @only_fields)
      end

      def except_fields(for_key = nil)
        return nil unless @has_except

        @except_fields ||= @opts_hash[:except].each_with_object({}) do |attribute, allowed_fields|
          build_symbolized_hash(attribute, allowed_fields)
        end

        only_for_given(for_key, @except_fields)
      end

      def with_attr_path(part)
        return yield unless part

        stack = (opts_hash[:attr_path] ||= [])
        stack.push part
        result = yield
        stack.pop
        result
      end

      # The disclosure scope that applies to the entity rendering with these
      # options. Only present when the caller opted into a disclosure policy.
      def disclosure_scope
        opts_hash[:disclosure_scope]
      end

      def disclosure_context
        opts_hash[:disclosure_context]
      end

      # The output position of the entity rendering with these options.
      def disclosure_occurrence
        opts_hash[:disclosure_occurrence]
      end

      private

      def build_for_nesting(key)
        skipped_keys = %i[collection disclosure_skip_entry disclosure_rollup]
        nested_opts = opts_hash.dup.reject { |current_key| skipped_keys.include?(current_key) }.merge(
          root: nil,
          only: only_fields(key),
          except: except_fields(key),
          attr_path: opts_hash[:attr_path]
        )
        nested_opts[:disclosure_occurrence] = nested_occurrence(key) if opts_hash.key?(:disclosure_occurrence)

        Options.new(nested_opts)
      end

      # Advance the output path by one key without deciding yet whether the
      # nested value is a collection; the represent call adds the index.
      def nested_occurrence(key)
        occurrence = opts_hash[:disclosure_occurrence]
        return unless occurrence

        Grape::Entity::Disclosure::Occurrence.new(path: occurrence.path + [key], collection: false)
      end

      def build_symbolized_hash(attribute, hash)
        case attribute
        when Hash
          attribute.each do |attr, nested_attrs|
            hash[attr.to_sym] = build_symbolized_hash(nested_attrs, {})
          end
        when Array
          return attribute.each { |x| build_symbolized_hash(x, {}) }
        else
          hash[attribute.to_sym] = true
        end

        hash
      end

      def only_for_given(key, fields)
        if key && fields[key].is_a?(Array)
          fields[key]
        elsif key.nil?
          fields
        end
      end
    end
  end
end
