# frozen_string_literal: true

module Grape
  class Entity
    module Publication
      # A single observable step in the publication pipeline. Events never
      # carry field values or exception messages: only the stable code, the
      # field path, and whether the field was mandatory.
      class Event
        attr_reader :code, :field, :mandatory, :object_key

        def initialize(code, field: nil, mandatory: false, object_key: nil)
          @code = code
          @field = field
          @mandatory = mandatory
          @object_key = object_key
        end

        def to_h
          { code: code, field: field, mandatory: mandatory, object_key: object_key }
        end

        def ==(other)
          other.is_a?(Event) && to_h == other.to_h
        end

        def inspect
          "#<#{self.class.name} #{to_h.map { |k, v| "#{k}=#{v.inspect}" }.join(' ')}>"
        end
      end
    end
  end
end
