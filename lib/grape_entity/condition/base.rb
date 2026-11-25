# frozen_string_literal: true

module Grape
  class Entity
    module Condition
      class Base
        attr_accessor :source_location

        def self.new(inverse, ...)
          super(inverse).tap { |e| e.setup(...) }
        end

        def initialize(inverse = false)
          @inverse = inverse
          @source_location = Grape::Entity.declaration_location(caller_locations)
        end

        def ==(other)
          (self.class == other.class) && (inversed? == other.inversed?)
        end

        def inversed?
          @inverse
        end

        def met?(entity, options)
          @inverse ? unless_value(entity, options) : if_value(entity, options)
        end

        def if_value(_entity, _options)
          raise NotImplementedError
        end

        def unless_value(entity, options)
          !if_value(entity, options)
        end
      end
    end
  end
end
