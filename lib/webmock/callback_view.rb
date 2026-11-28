# frozen_string_literal: true

module WebMock
  # The limited request/response projections that callbacks registered with
  # +shared_view+ receive. Each callback gets its own copy, built from only
  # the fields it is allowed to see, so a change made by one observer cannot
  # reach the request registry, the stub registry or another callback.
  module CallbackView
    REQUEST_FIELDS = %i[method uri body headers].freeze
    RESPONSE_FIELDS = %i[status headers body].freeze

    class Base
      attr_reader :fields

      def initialize(fields, values)
        @fields = fields
        @values = values
        fields.each do |field|
          define_singleton_method(field) { @values[field] }
        end
        freeze
      end

      def [](field)
        field = field.to_sym
        @values[field] if @fields.include?(field)
      end

      def to_h
        @values.dup
      end

      def to_s
        "#<#{self.class.name} #{@values.inspect}>"
      end
      alias_method :inspect, :to_s
    end

    class Request < Base
    end

    class Response < Base
    end

    class << self
      def request_fields(request_signature, fields)
        values = {}
        fields.each do |field|
          values[field] = request_value(request_signature, field)
        end
        Request.new(fields, values)
      end

      def response_fields(response, fields)
        return nil if response.nil?

        values = {}
        fields.each do |field|
          values[field] = response_value(response, field)
        end
        Response.new(fields, values)
      end

      private

      def request_value(request_signature, field)
        case field
        when :method then request_signature.method
        when :uri then copy_string(request_signature.uri)
        when :body then copy_string(request_signature.body)
        when :headers then copy_headers(request_signature.headers)
        end
      end

      def response_value(response, field)
        case field
        when :status then copy_status(response.status)
        when :headers then copy_headers(response.headers)
        when :body then copy_string(response.body)
        end
      end

      def copy_string(value)
        value.nil? ? nil : value.to_s.dup
      end

      def copy_status(status)
        [*status].map { |part| part.is_a?(String) ? part.dup : part }
      end

      def copy_headers(headers)
        return nil if headers.nil?

        headers.each_with_object({}) do |(name, value), copy|
          copy[name.to_s.dup] = copy_header_value(value)
        end
      end

      def copy_header_value(value)
        case value
        when Array then value.map { |item| item.is_a?(String) ? item.dup : item }
        when String then value.dup
        else value
        end
      end
    end
  end
end
