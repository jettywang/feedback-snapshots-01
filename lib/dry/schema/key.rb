# frozen_string_literal: true

module Dry
  module Schema
    # Key objects used by key maps
    #
    # @api public
    class Key
      extend ::Dry::Core::Cache

      DEFAULT_COERCER = :itself.to_proc.freeze

      include ::Dry.Equalizer(:name, :coercer)

      # @return [Symbol] The key identifier
      attr_reader :id

      # @return [Symbol, String, Object] The actual key name expected in an input hash
      attr_reader :name

      # @return [Proc, #call] A key name coercer function
      attr_reader :coercer

      # @return [Symbol] The approved canonical key that receives the value
      attr_reader :target

      # @return [Boolean] Whether this key represents a registered alias
      def alias?
        @alias_source
      end

      # @api private
      def self.[](name, **opts)
        new(name, **opts)
      end

      # @api private
      def self.new(*args, **kwargs)
        fetch_or_store(args, kwargs) { super }
      end

      # @api private
      def initialize(
        id,
        name: id,
        target: id,
        alias_source: false,
        permitted: true,
        coercer: DEFAULT_COERCER
      )
        @id = id
        @name = name
        @target = target
        @alias_source = alias_source
        @permitted = permitted
        @coercer = coercer
      end

      # @api private
      def permitted?
        @permitted
      end

      # @api private
      def read(source)
        return unless source.is_a?(::Hash)

        if source.key?(name)
          yield(source[name], name)
        elsif source.key?(coerced_name)
          yield(source[coerced_name], coerced_name)
        end
      end

      # @api private
      def write(source, target_hash, context = EMPTY_HASH)
        tracker = context[:tracker]
        path = context[:path] || EMPTY_ARRAY

        read(source) do |value, source_name|
          destination = target_name
          target_hash[destination] = value

          tracker&.record(
            key: self,
            value: value,
            path: path,
            destination: destination,
            source_name: source_name
          )
        end
      end

      # @api private
      def coercible(&coercer)
        new(coercer: coercer)
      end

      # @api private
      def stringified
        new(name: name.to_s)
      end

      # @api private
      def to_dot_notation
        [name.to_s]
      end

      # @api private
      def new(**new_opts)
        self.class.new(
          id,
          name: name,
          target: target,
          alias_source: alias?,
          permitted: permitted?,
          coercer: coercer,
          **new_opts
        )
      end

      # @api private
      def dump
        name
      end

      # @api private
      def target_name
        @__target_name__ ||= coercer[target]
      end

      private

      # @api private
      def coerced_name
        @__coerced_name__ ||= coercer[name]
      end

      # A specialized key type which handles nested hashes
      #
      # @api private
      class Hash < self
        include ::Dry.Equalizer(:name, :members, :coercer)

        # @api private
        attr_reader :members

        # @api private
        def initialize(id, members:, **opts)
          super(id, **opts)
          @members = members
        end

        # @api private
        def read(source)
          super if source.is_a?(::Hash)
        end

        def write(source, target_hash, context = EMPTY_HASH)
          tracker = context[:tracker]
          path = context[:path] || EMPTY_ARRAY

          read(source) do |value, source_name|
            destination = target_name
            field_path = path + [destination]

            target_hash[destination] =
              if value.is_a?(::Hash)
                members.write(
                  value,
                  EMPTY_HASH.dup,
                  {tracker: tracker, path: field_path}
                )
              else
                value
              end

            tracker&.record(
              key: self,
              value: value,
              path: path,
              destination: destination,
              source_name: source_name
            )
          end
        end

        # @api private
        def coercible(&coercer)
          new(coercer: coercer, members: members.coercible(&coercer))
        end

        # @api private
        def stringified
          new(name: name.to_s, members: members.stringified)
        end

        # @api private
        def to_dot_notation
          [name].product(members.flat_map(&:to_dot_notation)).map { |e| e.join(DOT) }
        end

        # @api private
        def dump
          {name => members.map(&:dump)}
        end
      end

      # A specialized key type which handles nested arrays
      #
      # @api private
      class Array < self
        include ::Dry.Equalizer(:name, :member, :coercer)

        attr_reader :member

        # @api private
        def initialize(id, member:, **opts)
          super(id, **opts)
          @member = member
        end

        # @api private
        def write(source, target_hash, context = EMPTY_HASH)
          tracker = context[:tracker]
          path = context[:path] || EMPTY_ARRAY

          read(source) do |value, source_name|
            destination = target_name
            field_path = path + [destination]

            target_hash[destination] =
              if value.is_a?(::Array)
                value.each_with_index.map do |element, index|
                  if element.is_a?(::Hash)
                    member.write(
                      element,
                      EMPTY_HASH.dup,
                      {tracker: tracker, path: field_path + [index]}
                    )
                  else
                    element
                  end
                end
              else
                value
              end

            tracker&.record(
              key: self,
              value: value,
              path: path,
              destination: destination,
              source_name: source_name
            )
          end
        end

        # @api private
        def coercible(&coercer)
          new(coercer: coercer, member: member.coercible(&coercer))
        end

        # @api private
        def stringified
          new(name: name.to_s, member: member.stringified)
        end

        # @api private
        def to_dot_notation
          [:"#{name}[]"].product(member.to_dot_notation).map { |el| el.join(DOT) }
        end

        # @api private
        def dump
          [name, member.dump]
        end
      end
    end
  end
end
