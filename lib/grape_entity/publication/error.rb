# frozen_string_literal: true

module Grape
  class Entity
    module Publication
      # Describes why a field could not be published. The public message only
      # contains a stable code and the field path; the original exception is
      # kept out of the message but remains reachable for operators via
      # #original (also exposed as #cause).
      class Error < StandardError
        attr_reader :code, :field, :original

        def initialize(code, field: nil, mandatory: false, original: nil)
          @code = code
          @field = field
          @mandatory = mandatory
          @original = original
          label = code.to_s
          label = "#{label} (#{Array(field).join('.')})" unless field.nil?
          super(label)
        end

        def mandatory?
          @mandatory ? true : false
        end

        def internal_reason
          @original
        end

        # Keep the internal exception reachable through the conventional
        # Exception#cause accessor without putting it in the message.
        def cause
          @original
        end

        def to_h
          { code: code, field: field, mandatory: mandatory? }
        end

        def inspect
          "#<#{self.class.name} #{to_h.map { |k, v| "#{k}=#{v.inspect}" }.join(' ')}>"
        end
      end
    end
  end
end
