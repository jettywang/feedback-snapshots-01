module Flipper
  module Policy
    # Public: A single member of the employee roster used to answer "who would
    # this gate combination open up to?". Wraps a flipper id plus the properties
    # an expression gate may read (plan, team, region, etc.). An Employee is also
    # a valid Flipper actor, so it can be passed straight to Feature#enabled?.
    class Employee
      attr_reader :flipper_id, :flipper_properties

      def initialize(flipper_id, properties = {})
        raise ArgumentError, "flipper_id cannot be nil" if flipper_id.nil?
        raise ArgumentError, "properties must be a Hash" unless properties.is_a?(Hash)

        @flipper_id = flipper_id.to_s
        @flipper_properties = properties.transform_keys(&:to_s)
      end

      # Public: Build an Employee from anything the preflight accepts: an
      # existing Employee, a Flipper::Actor, a two-tuple of [id, properties],
      # or a Hash containing an id/properties pair.
      def self.wrap(object, properties = {})
        case object
        when Employee
          object
        when Flipper::Actor
          new(object.flipper_id, object.flipper_properties.merge(properties))
        when Hash
          id = object[:flipper_id] || object["flipper_id"] || object[:id] || object["id"]
          props = object[:properties] || object[:flipper_properties] || {}
          new(id, props.merge(properties))
        else
          new(object, properties)
        end
      end

      def [](property)
        @flipper_properties[property.to_s]
      end

      def eql?(other)
        other.is_a?(self.class) &&
          flipper_id == other.flipper_id &&
          flipper_properties == other.flipper_properties
      end
      alias_method :==, :eql?

      def hash
        [self.class, flipper_id].hash
      end

      def inspect
        "#<#{self.class.name} id=#{flipper_id.inspect} properties=#{flipper_properties.inspect}>"
      end
      alias_method :to_s, :inspect
    end
  end
end
