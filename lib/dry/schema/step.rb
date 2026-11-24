# frozen_string_literal: true

require "dry/schema/constants"
require "dry/schema/phase"

module Dry
  module Schema
    # @api private
    class Step
      # @api private
      attr_reader :name

      # @api private
      attr_reader :type

      # @api private
      attr_reader :executor

      # @api private
      attr_reader :path

      # Phase in which this step runs
      #
      # @return [Symbol]
      #
      # @api public
      attr_reader :phase

      # Phase required for this step to run, or nil when it always runs
      #
      # @return [Symbol, nil]
      #
      # @api public
      attr_reader :permit

      # @api private
      def initialize(type:, name:, executor:, path: Path::EMPTY, permit: nil)
        validate_name(name)

        @type = type
        @name = name
        @executor = executor
        @path = path
        @phase = Phase.for(type: type, name: name)
        @permit = validate_permit(permit)
      end

      # Check if running this step requires a permit
      #
      # @return [Boolean]
      #
      # @api public
      def sensitive?
        !permit.nil?
      end

      # @api private
      def call(result)
        scoped_result = path.equal?(Path::EMPTY) ? result : result.at(path)

        output = executor.(scoped_result)
        scoped_result.replace(output) if output.is_a?(Hash)
        output
      end

      # @api private
      def scoped(parent_path)
        self.class.new(
          type: type,
          name: name,
          executor: executor,
          path: Path.new([*parent_path, *path]),
          permit: permit
        )
      end

      private

      # @api private
      def validate_name(name)
        return if STEPS_IN_ORDER.include?(name)

        raise ArgumentError, "Undefined step name #{name}. Available names: #{STEPS_IN_ORDER}"
      end

      # @api private
      def validate_permit(permit)
        return if permit.nil?

        Phase.fetch!(permit)
      end
    end
  end
end
