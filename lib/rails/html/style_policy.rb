# frozen_string_literal: true

require "crass"

module Rails
  module HTML
    # == Rails::HTML::StylePolicy
    #
    # An immutable description of the inline CSS a caller is willing to accept.
    # The same policy can be used to sanitize a standalone style string with
    # +SafeListSanitizer#sanitize_css+ and to sanitize +style+ attributes while
    # scrubbing an HTML fragment with +SafeListSanitizer#sanitize+.
    #
    # A policy can only narrow the declarations that Loofah already considers
    # safe. It never makes an unsafe property or value acceptable; the CSS is
    # always passed through Loofah's CSS scrubber before the policy is applied.
    #
    #   policy = Rails::HTML::StylePolicy.new(
    #     properties: %w(color width),
    #     values: {
    #       "color" => %w(#0b57d0),
    #       "width" => %w(600px 100%),
    #     },
    #   )
    #
    #   sanitizer = Rails::HTML5::SafeListSanitizer.new
    #   sanitizer.sanitize_css("color: #0b57d0; width: 600px; cursor: pointer;", style_policy: policy)
    #   # => "color:#0b57d0;width:600px;"
    #
    #   sanitizer.sanitize(
    #     %(<p style="color: #0b57d0; width: 600px; cursor: pointer;">Hi</p>),
    #     attributes: %w(style),
    #     style_policy: policy,
    #   )
    #   # => %(<p style="color:#0b57d0;width:600px;">Hi</p>)
    #
    # === Options
    #
    # +properties:+ (also accepted as +allowed_properties:+)
    #   An Enumerable of property names to keep, or +nil+ to keep Loofah's
    #   default set. An empty enumerable removes every declaration.
    #
    # +values:+ (also accepted as +allowed_values:+)
    #   A Hash mapping property names to the values allowed for that property.
    #   Each value may be a String, Regexp, Proc, or an Enumerable of those.
    #   Strings are compared case-insensitively after whitespace is collapsed.
    #   Regexps are matched against that normalized value, and Procs are called
    #   with it. Properties without an entry are not constrained by value.
    #   The +!important+ flag is preserved but is not part of the value match.
    #
    # Invalid configuration raises ArgumentError when the policy is built.
    class StylePolicy
      # Reason codes recorded in a Report. They deliberately describe only the
      # property and the rule that rejected it, never the value.
      PROPERTY_NOT_ALLOWED = :property_not_allowed
      VALUE_NOT_ALLOWED = :value_not_allowed

      # A diagnostic sink for the properties a StylePolicy removed.
      #
      # Entries contain the property name, the disposition (+:removed+), and
      # one of the reason codes above. They never contain the original style
      # string or the property value.
      #
      #   report = Rails::HTML::StylePolicy::Report.new
      #   sanitizer.sanitize_css(style, style_policy: policy, style_report: report)
      #   report.entries
      #   # => [{ property: "cursor", disposition: :removed, reason: :property_not_allowed }]
      class Report
        class Entry < Hash
          def initialize(property:, reason:, disposition: :removed)
            super()

            self[:property] = property.to_s.downcase.freeze
            self[:disposition] = disposition
            self[:reason] = reason
            freeze
          end

          def property
            self[:property]
          end

          def disposition
            self[:disposition]
          end

          def reason
            self[:reason]
          end
        end

        include Enumerable

        attr_reader :entries

        def initialize
          @entries = []
        end

        def each(&block)
          entries.each(&block)
        end

        def <<(entry)
          entries << entry
          self
        end

        def size
          entries.size
        end
        alias length size

        def empty?
          entries.empty?
        end

        def clear
          entries.clear
          self
        end

        def to_a
          entries.dup
        end

        def properties
          entries.map { |entry| entry[:property] }.uniq
        end

        def reasons
          entries.map { |entry| entry[:reason] }.uniq
        end

        # Accepts a Report, an Array, or any other object that responds to
        # +<<+ (except a String). Returns nil when diagnostics are disabled.
        def self.sink(report)
          case report
          when nil, false
            nil
          when Report, Array
            report
          else
            if report.respond_to?(:<<) && !report.is_a?(String)
              report
            else
              raise ArgumentError, "style_report should be a StylePolicy::Report, an Array, or an object that responds to <<"
            end
          end
        end
      end

      PROPERTY_NAME = /\A-?[a-z][a-z0-9-]*\z/

      # Turns a Hash of options into a policy, passes a policy (or any object
      # that responds to +sanitize+) through unchanged, and returns nil for nil.
      def self.coerce(value)
        case value
        when nil
          nil
        when StylePolicy
          value
        when Hash
          new(**value)
        else
          if value.respond_to?(:sanitize)
            value
          else
            raise ArgumentError, "style_policy should be a Rails::HTML::StylePolicy, a Hash of options, or an object that responds to #sanitize"
          end
        end
      end

      attr_reader :allowed_properties, :allowed_values

      def initialize(properties: nil, values: nil, allowed_properties: nil, allowed_values: nil)
        properties = allowed_properties unless allowed_properties.nil?
        values = allowed_values unless allowed_values.nil?

        @allowed_properties = normalize_properties(properties)
        @allowed_values = normalize_values(values)
        freeze
      end

      def properties
        allowed_properties
      end

      def values
        allowed_values
      end

      def allows_property?(property)
        return true if @allowed_properties.nil?

        @allowed_properties.include?(normalize_property_name(property))
      end

      def allows_value?(property, value)
        constraints = @allowed_values[normalize_property_name(property)]
        return true if constraints.nil?

        normalized = normalize_value(value)
        constraints.any? { |constraint| matches?(constraint, normalized) }
      end

      # Returns the safely-sanitized subset of +style+ that satisfies this
      # policy. Rejected property names are recorded in +report+ without their
      # values.
      def sanitize(style, report: nil)
        sink = Report.sink(report)
        baseline = Loofah::HTML5::Scrub.scrub_css(style)

        return baseline if no_constraints?

        sanitized = []

        Crass.parse_properties(baseline).each do |node|
          next unless node[:node] == :property

          property = node[:name].downcase
          unless allows_property?(property)
            record(sink, property, PROPERTY_NOT_ALLOWED)
            next
          end

          unless allows_value?(property, node[:value])
            record(sink, property, VALUE_NOT_ALLOWED)
            next
          end

          sanitized << Crass::Parser.stringify(node) << ";"
        end

        sanitized.join
      end
      alias call sanitize

      def inspect
        "#<#{self.class.name} properties=#{@allowed_properties.inspect} values=#{@allowed_values.keys.inspect}>"
      end

      private
        def no_constraints?
          @allowed_properties.nil? && @allowed_values.empty?
        end

        def normalize_properties(value)
          return nil if value.nil?

          unless enumerable?(value)
            raise ArgumentError, "StylePolicy :properties should be an Enumerable of property names"
          end

          value.map { |property| normalize_property_name(property) }
            .uniq
            .sort
            .map(&:freeze)
            .freeze
        end

        def normalize_values(value)
          return {}.freeze if value.nil?

          unless value.is_a?(Hash)
            raise ArgumentError, "StylePolicy :values should be a Hash mapping property names to allowed values"
          end

          value.each_with_object({}) do |(property, constraints), result|
            name = normalize_property_name(property)
            result[name] = normalize_constraints(constraints, name)
          end.freeze
        end

        def normalize_property_name(property)
          name = property.to_s.strip.downcase

          unless PROPERTY_NAME.match?(name)
            raise ArgumentError, "StylePolicy contains an invalid property name #{property.inspect}"
          end

          name.freeze
        end

        def normalize_constraints(constraints, property)
          constraints = [constraints] unless enumerable?(constraints)

          unless enumerable?(constraints)
            raise ArgumentError, "StylePolicy values for #{property.inspect} should be a String, Regexp, Proc, or an Enumerable of those"
          end

          constraints = constraints.map { |constraint| normalize_constraint(constraint, property) }
          constraints.freeze
        end

        def normalize_constraint(constraint, property)
          case constraint
          when String
            normalize_value(constraint).freeze
          when Regexp, Proc
            constraint
          else
            raise ArgumentError, "StylePolicy values for #{property.inspect} contain an invalid constraint #{constraint.inspect}"
          end
        end

        def normalize_value(value)
          value.to_s.strip.gsub(/\s+/, " ").downcase
        end

        def matches?(constraint, normalized_value)
          case constraint
          when String
            constraint == normalized_value
          when Regexp
            constraint.match?(normalized_value)
          else
            !!constraint.call(normalized_value)
          end
        end

        def enumerable?(value)
          value.is_a?(Enumerable) && !value.is_a?(String) && !value.is_a?(Hash)
        end

        def record(sink, property, reason)
          return unless sink

          sink << Report::Entry.new(property: property, reason: reason)
        end
    end
  end
end
