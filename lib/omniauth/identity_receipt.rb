module OmniAuth
  # Sanitized outcome and internal exception for one identity callback.
  class IdentityReceipt
    attr_reader :name, :correlation_id, :view, :error, :returned_value, :public_message

    # rubocop:disable Metrics/ParameterLists
    def initialize(name:, correlation_id:, view:, error: nil, returned_value: nil, public_message: nil)
      @name = name.to_sym
      @correlation_id = correlation_id
      @view = view
      @error = error
      @returned_value = returned_value
      @public_message = public_message || error&.message
    end
    # rubocop:enable Metrics/ParameterLists

    def callback_name
      name
    end
    alias callback name

    def status
      error ? :error : :success
    end

    def failed?
      !error.nil?
    end
    alias error? failed?

    def error_class
      error&.class&.name
    end

    def to_h
      {
        'callback' => name,
        'correlation_id' => correlation_id,
        'status' => status,
        'auth' => view.to_hash,
        'error_class' => error_class,
        'error_message' => public_message
      }.reject { |_key, value| value.nil? }
    end
    alias to_hash to_h
    alias public_details to_h

    def material
      OmniAuth::AuthHash.new(to_h)
    end

    def failure_material
      material
    end
  end
end
