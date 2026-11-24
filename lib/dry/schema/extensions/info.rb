# frozen_string_literal: true

require "dry/schema/extensions/info/schema_compiler"
require "dry/schema/extensions/info/visibility"

module Dry
  module Schema
    # Info extension
    #
    # @api public
    module Info
      module SchemaMethods
        # Return information about keys and types
        #
        # With `visibility: :internal` (the default) the full info hash is
        # returned, including declared examples and `included_in?` value sets.
        #
        # With `visibility: :public` the info hash is redacted according to the
        # `config.info_visibility` policy: internal-only keys are removed,
        # internal-only enum members are filtered out of value sets, and error
        # examples are dropped. This only affects documentation export; actual
        # input validation is not affected by the documentation policy.
        #
        # @param visibility [:internal, :public] documentation visibility
        #
        # @return [Hash<Symbol=>Hash>]
        #
        # @api public
        def info(visibility: :internal)
          unless %i[internal public].include?(visibility)
            raise ArgumentError, "unknown info visibility: #{visibility.inspect}"
          end

          compiler = SchemaCompiler.new(examples: config.info_examples)
          compiler.call(to_ast)
          exported = compiler.to_h

          return exported if visibility.equal?(:internal)

          Visibility.new(**config.info_visibility).call(exported)
        end
      end
    end

    # Documentation metadata declarations used by the info export
    #
    # `info_examples` maps key paths (dot-separated, e.g. "address.room") to
    # example values. A plain value is a valid (public) example; a hash of
    # `{value:, valid: false}` declares an error example, which is
    # internal-only by default.
    #
    # `info_visibility` declares the redaction policy applied by
    # `info(visibility: :public)`. See Info::Visibility.
    #
    # @api public
    Config.setting(:info_examples, default: EMPTY_HASH)
    Config.setting(:info_visibility, default: EMPTY_HASH)

    Processor.include(Info::SchemaMethods)
  end
end
