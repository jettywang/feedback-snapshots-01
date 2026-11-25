# frozen_string_literal: true

module Grape
  module ServeStream
    # The fields one streamed response may disclose, settled when the response
    # is set up. A record is projected through this representation as each line
    # is rendered, so a policy or record changed while the body is being read
    # cannot add a field to a line that was already approved, nor take one away
    # from a line that was promised.
    #
    # Three ways to name the disclosure:
    #
    #   # a declared list of fields, fixed at setup
    #   Representation.new(fields: %i[id name])
    #
    #   # the fields of the first record, locked before its line is sent
    #   Representation.new(fields: :first)
    #
    #   # a callable answering the projected record itself
    #   Representation.new(represent: ->(row) { row.slice(:id, :name) })
    #
    # +fields: nil+ with no +represent+ serves each record unchanged, which is
    # what an API that streams records it already controls wants.
    class Representation
      # The default for +jsonl+: the first record's fields decide what all the
      # rest may disclose.
      FIRST = :first

      attr_reader :version, :name

      def initialize(fields: nil, represent: nil, version: nil, name: nil)
        raise ArgumentError, 'give either :fields or :represent, not both' if fields && represent

        @declared_fields = fields.is_a?(Array) ? fields.map { |field| field.to_sym.freeze }.uniq.freeze : nil
        @field_mode = fields.is_a?(Array) ? :declared : fields
        @represent = represent
        @version = version&.to_s&.freeze
        @name = name&.to_s&.freeze
        @locked_fields = nil
        @lock = Mutex.new
      end

      # The record as this response may disclose it. A record is projected
      # through its Hash form: a Hash answers itself, and an object is expected
      # to answer +to_h+ (a Struct, a model's attributes, a value object);
      # anything else is a programming error worth naming.
      #
      # @param record [Hash, #to_h, nil]
      # @return [Hash, Object, nil]
      def project(record)
        return @represent.call(record) if @represent
        return record if @field_mode.nil?
        return if record.nil?

        source = projection_source(record)
        fields_for(source).each_with_object({}) do |field, projected|
          key = source.key?(field) ? field : field.to_s
          projected[field] = source[key] if source.key?(key)
        end
      end

      # The fields this representation has settled on. +nil+ until the first
      # record arrives, for +fields: :first+.
      def fields
        return @declared_fields unless @field_mode == FIRST

        @locked_fields
      end

      # The disclosure this response was approved under, for a ledger.
      #
      # @return [Hash]
      def to_h
        { fields:, mode: @field_mode, version:, name: }.freeze
      end

      private

      def fields_for(source)
        return @declared_fields if @field_mode == :declared

        @lock.synchronize do
          @locked_fields ||= source.keys.map { |key| key.to_sym.freeze }.freeze
        end
      end

      def projection_source(record)
        return record if record.is_a?(Hash)

        if record.respond_to?(:to_h)
          hash = record.to_h
          return hash if hash.is_a?(Hash)
        end

        raise ArgumentError, "cannot project #{record.class} into a declared field set: it responds to no #to_h"
      end
    end
  end
end
