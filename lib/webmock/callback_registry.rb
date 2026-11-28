# frozen_string_literal: true

module WebMock
  class CallbackRegistry
    @@callbacks = []

    def self.add_callback(options, block)
      options = validate_options(options)
      @@callbacks << {options: options, block: block}
    end

    def self.callbacks
      @@callbacks
    end

    def self.invoke_callbacks(options, request_signature, response)
      return if @@callbacks.empty?
      CallbackRegistry.callbacks.each do |callback|
        begin
          invoke_callback(callback, options, request_signature, response)
        rescue StandardError
          raise unless callback[:options][:shared_view]
        end
      end
    end

    def self.reset
      @@callbacks = []
    end

    def self.any_callbacks?
      !@@callbacks.empty?
    end

    def self.validate_options(options)
      options = options.dup
      shared_view = options[:shared_view]
      return options if shared_view.nil?

      unless shared_view.is_a?(Hash)
        raise ArgumentError, 'shared_view must be a Hash with request: and response: field lists'
      end

      unknown = shared_view.keys - [:request, :response]
      if !unknown.empty?
        raise ArgumentError, "shared_view accepts only request: and response:, got: #{unknown.inspect}"
      end

      [:request, :response].each do |side|
        next unless shared_view[side]
        validate_fields(side, shared_view[side], allowed_fields(side))
      end

      options[:shared_view] = {
        request: shared_view.key?(:request) ? Array(shared_view[:request]).map(&:to_sym).freeze : nil,
        response: shared_view.key?(:response) ? Array(shared_view[:response]).map(&:to_sym).freeze : nil
      }
      options
    end

    def self.validate_fields(side, fields, allowed)
      unless fields.is_a?(Array) || fields.is_a?(Symbol)
        raise ArgumentError, "shared_view[:#{side}] must be a list of fields"
      end

      invalid = Array(fields).map(&:to_sym) - allowed
      unless invalid.empty?
        raise ArgumentError, "shared_view[:#{side}] has unsupported fields: #{invalid.inspect}; allowed: #{allowed.inspect}"
      end
    end

    def self.allowed_fields(side)
      case side
      when :request then WebMock::CallbackView::REQUEST_FIELDS
      when :response then WebMock::CallbackView::RESPONSE_FIELDS
      end
    end

    def self.invoke_callback(callback, options, request_signature, response)
      except = callback[:options][:except]
      real_only = callback[:options][:real_requests_only]
      unless except && except.include?(options[:lib])
        if !real_only || options[:real_request]
          if (shared_view = callback[:options][:shared_view])
            request_view = nil
            response_view = nil
            if shared_view[:request]
              request_view = WebMock::CallbackView.request_fields(
                request_signature, shared_view[:request])
            end
            if shared_view[:response] && !response.nil?
              response_view = WebMock::CallbackView.response_fields(
                response, shared_view[:response])
            end
            callback[:block].call(request_view, response_view)
          else
            callback[:block].call(request_signature, response)
          end
        end
      end
    end
  end
end
