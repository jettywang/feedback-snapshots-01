# frozen_string_literal: true

require "dry/core/equalizer"
require "dry/schema/constants"
require_relative "path"

module Dry
  module Schema
    # Redacted message representation safe to share with external partners
    #
    # Unlike {Message}, this object never exposes rendered templates,
    # predicate arguments, metadata except an explicit code, or the input
    # sample. Field paths retain nested keys and original array indexes.
    #
    # @api public
    class ShareableMessage
      include ::Dry::Equalizer(:path, :category, :code, :origin)

      ERROR = "error"
      HINT = "hint"
      ORIGINS = [ERROR, HINT].freeze

      # @return [Array<Symbol, Integer>]
      attr_reader :path

      # Stable predicate/category identifier, independent of locale
      #
      # @return [Symbol]
      attr_reader :category

      # Explicit message code when provided, otherwise the category
      #
      # @return [Symbol, String, Numeric]
      attr_reader :code

      # Either `"error"` or `"hint"`
      #
      # @return [String]
      attr_reader :origin

      # @return [Symbol, nil]
      attr_reader :locale

      alias_method :field, :path
      alias_method :predicate, :category
      alias_method :kind, :origin
      alias_method :type, :origin

      def path=(value)
        @path = self.class.coerce_path(value).freeze
      end

      alias_method :field=, :path=

      def category=(value)
        @category = value.to_sym
      end

      alias_method :predicate=, :category=

      attr_writer :code

      def origin=(value)
        @origin = normalize_origin(value)
      end

      alias_method :kind=, :origin=
      alias_method :type=, :origin=

      # Coerce a path specification while preserving array indexes
      #
      # @api public
      def self.coerce_path(value)
        case value
        when Path
          value.keys.dup
        when ::Array
          value.map { |segment| coerce_segment(segment) }
        when ::Symbol, ::Integer
          [coerce_segment(value)]
        when ::String
          if value.start_with?("/")
            value.split("/")[1..].map do |segment|
              coerce_segment(unescape_pointer(segment))
            end
          else
            value.split(DOT).map { |segment| coerce_segment(segment) }
          end
        when ::Hash
          Path.keys_from_hash(value).map { |segment| coerce_segment(segment) }
        when nil
          EMPTY_ARRAY.dup
        else
          [value]
        end
      end

      # @api private
      def self.coerce_segment(segment)
        case segment
        when ::Integer, :*, :**
          segment
        when ::Symbol
          segment
        when ::String
          if segment.match?(/\A(?:0|[1-9]\d*)\z/)
            segment.to_i
          else
            segment.to_sym
          end
        else
          segment
        end
      end

      # @api private
      def self.unescape_pointer(segment)
        segment.gsub("~1", "/").gsub("~0", "~")
      end

      # @param source [Message, ShareableMessage, nil]
      # @api public
      def self.from_message(source, **options)
        new(source, **options)
      end

      # @param source [Message, ShareableMessage, nil]
      # @api public
      def initialize(
        source = nil,
        path: nil,
        field: nil,
        category: nil,
        predicate: nil,
        code: nil,
        origin: nil,
        kind: nil,
        type: nil,
        locale: nil
      )
        path_value = path || field || source_path(source)
        @path = self.class.coerce_path(path_value).freeze

        category_value = category || predicate || source_predicate(source) || :unknown
        @category = category_value.to_sym

        explicit_code = code.nil? ? safe_meta_code(source) : code
        @code = explicit_code.nil? ? @category : explicit_code
        origin_value = origin || kind || type || source_origin(source)
        @origin = normalize_origin(origin_value)
        @locale = locale&.to_sym
      end

      # JSON Pointer location, including original array indexes
      #
      # @return [String]
      # @api public
      def pointer
        return "" if path.empty?

        "/" + path.map { |segment| escape_pointer(segment.to_s) }.join("/")
      end

      # Dot-separated location
      #
      # @return [String]
      # @api public
      def location
        path.map(&:to_s).join(DOT)
      end

      # @return [Boolean]
      # @api public
      def error?
        origin == ERROR
      end

      # @return [Boolean]
      # @api public
      def hint?
        origin == HINT
      end

      # Return an adjusted copy
      #
      # @return [ShareableMessage]
      # @api public
      def with(**changes)
        self.class.new(
          nil,
          path: changes.fetch(:path, path),
          category: changes.fetch(:category, category),
          code: changes.fetch(:code, code),
          origin: changes.fetch(:origin, origin),
          locale: changes.fetch(:locale, locale)
        )
      end

      # Plain Ruby representation
      #
      # @return [Hash]
      # @api public
      def to_h
        {
          field: field,
          path: path,
          pointer: pointer,
          location: location,
          category: category,
          predicate: predicate,
          code: code,
          origin: origin,
          kind: kind,
          type: type
        }
      end
      alias_method :to_hash, :to_h

      # JSON-friendly representation
      #
      # @return [Hash]
      # @api public
      def as_json(*)
        {
          "field" => json_path,
          "path" => json_path,
          "pointer" => pointer,
          "location" => location,
          "category" => category.name,
          "predicate" => predicate.name,
          "code" => json_code,
          "origin" => origin,
          "kind" => kind,
          "type" => type
        }
      end

      # @api public
      def to_json(options = nil)
        require "json" unless defined?(::JSON)
        as_json.to_json(options)
      end

      # @api public
      def inspect
        "#<#{self.class} field=#{path.inspect} category=#{category.inspect} " \
          "code=#{code.inspect} origin=#{origin.inspect}>"
      end

      private

      def source_path(source)
        source.path if source.respond_to?(:path)
      end

      def source_predicate(source)
        source.predicate if source.respond_to?(:predicate)
      end

      def source_origin(source)
        if source.is_a?(ShareableMessage)
          source.origin
        elsif source.respond_to?(:hint?) && source.hint?
          HINT
        else
          ERROR
        end
      end

      def normalize_origin(value)
        value = value.to_s
        case value
        when HINT then HINT
        when ERROR, "failure" then ERROR
        else ERROR
        end
      end

      def safe_meta_code(source)
        return unless source.respond_to?(:meta)

        meta = source.meta
        return unless meta.is_a?(::Hash)

        code = meta.key?(:code) ? meta[:code] : meta["code"]
        return if code.nil?

        code if code.is_a?(::String) || code.is_a?(::Symbol) || code.is_a?(::Numeric)
      end

      def escape_pointer(segment)
        segment.gsub("~", "~0").gsub("/", "~1")
      end

      def json_path
        path.map do |segment|
          segment.is_a?(::Symbol) ? segment.name : segment
        end
      end

      def json_code
        code.is_a?(::Symbol) ? code.name : code
      end

      # Allow-list and optional location/category rewriting policy
      #
      # @api public
      class Policy
        WILDCARD = :*
        GLOB = :**

        # @api private
        attr_reader :allowed_paths, :denied_paths, :categories, :codes,
                    :origins, :field_map, :category_map

        def initialize(**options)
          @allowed_paths = prepare_paths(first_option(
            options, :allow, :fields, :allow_fields, :allowed_fields,
            :allowed_paths, :paths, :only, :visible_fields, :public_fields,
            :shareable_fields, :allowed_locations, :locations, :field_allowlist
          ))
          @denied_paths = prepare_paths(first_option(
            options, :deny, :except, :exclude, :fields_deny,
            :deny_fields, :blocked_fields, :private_fields,
            :hidden_fields, :sensitive_fields, :deny_paths, :blocklist
          )) || EMPTY_ARRAY.dup
          @categories = prepare_symbols(first_option(
            options, :categories, :category, :allowed_categories
          ))
          @codes = prepare_values(first_option(options, :codes, :allowed_codes))
          @origins = prepare_origins(first_option(options, :origins, :kinds, :types))
          @field_map = options[:field_map] || options[:map_field] || options[:location_map]
          @category_map = options[:category_map] || options[:map_category]
        end

        # @api public
        def allow?(message)
          path = message.path

          return false if denied_paths.any? { |pattern| path_match?(pattern, path) }

          if allowed_paths && allowed_paths.none? { |pattern| path_match?(pattern, path) }
            return false
          end

          return false if categories && !categories.include?(message.category)
          return false if codes && !codes.include?(message.code)
          return false if origins && !origins.include?(message.origin)

          true
        end

        # @api public
        def apply(message)
          message = map_field(message)
          map_category(message)
        end

        private

        def first_option(options, *names)
          names.each do |name|
            return options[name] if options.key?(name)
          end
          nil
        end

        def prepare_paths(value)
          return if value.nil?
          return if value == :all || value == "all"

          Array(value).map { |path| ShareableMessage.coerce_path(path) }
        end

        def prepare_symbols(value)
          return if value.nil?

          Array(value).map(&:to_sym)
        end

        def prepare_values(value)
          return if value.nil?

          Array(value)
        end

        def prepare_origins(value)
          return if value.nil?

          Array(value).map { |origin| origin.to_s == "failure" ? ERROR : origin.to_s }
        end

        def path_match?(pattern, path)
          match_segments?(pattern, path)
        end

        def match_segments?(pattern, path)
          return pattern.empty? if pattern.empty?

          head, *tail = pattern

          if head == GLOB
            return true if match_segments?(tail, path)
            return false if path.empty?

            match_segments?(pattern, path[1..])
          else
            return false if path.empty?

            segment, *remaining_path = path
            return false unless head == WILDCARD || head == segment

            match_segments?(tail, remaining_path)
          end
        end

        def map_field(message)
          mapped_path =
            if field_map.respond_to?(:call)
              field_map.call(message.path.dup)
            elsif field_map.is_a?(::Hash)
              map_hash_path(field_map, message.path)
            end

          mapped_path ? message.with(path: ShareableMessage.coerce_path(mapped_path)) : message
        end

        def map_hash_path(mapping, path)
          normalized = mapping.map do |key, value|
            [ShareableMessage.coerce_path(key), value]
          end

          key, replacement = normalized
            .select { |pattern, _| prefix_match?(pattern, path) }
            .max_by { |pattern, _| pattern.length }

          return unless key

          ShareableMessage.coerce_path(replacement) + path[key.length..]
        end

        def prefix_match?(prefix, path)
          return false if prefix.length > path.length

          prefix.each_with_index.all? do |segment, index|
            segment == WILDCARD || segment == path[index]
          end
        end

        def map_category(message)
          return message unless category_map

          category =
            if category_map.respond_to?(:call)
              category_map.call(message.category)
            else
              category_map[message.category] || category_map[message.category.to_s]
            end

          category ? message.with(category: category.to_sym) : message
        end
      end
    end
  end
end
