module OmniAuth
  # Delivers isolated auth views in registration order and records failures.
  class IdentityDispatcher
    RECEIPTS_KEY = 'omniauth.identity_receipts'.freeze
    FAILURE_MATERIAL_KEY = 'omniauth.failure_material'.freeze

    def initialize(registry, env, correlation_id, strategy = nil)
      @registry = registry
      @env = env
      @correlation_id = correlation_id
      @strategy = strategy
    end

    def call
      receipts = registry.callbacks.values.collect { |registration| deliver(registration) }
      publish(receipts)
      receipts
    end

    private

    attr_reader :registry, :env, :correlation_id, :strategy

    def deliver(registration)
      view = registration.view.project(auth, :correlation_id => correlation_id)
      error, returned_value = invoke(registration, view)
      material_view = registration.view.project(auth, :correlation_id => correlation_id)
      safe_message = IdentityRedactor.new(auth, material_view).scrub(error&.message)
      receipt = IdentityReceipt.new(
        :name => registration.name,
        :correlation_id => correlation_id,
        :view => material_view,
        :error => error,
        :returned_value => returned_value,
        :public_message => safe_message
      )
      handle_failure(registration, receipt) if receipt.failed?
      receipt
    end

    def invoke(registration, view)
      [nil, registration.deliver(view, env)]
    rescue StandardError => error
      [error, nil]
    end

    def handle_failure(registration, receipt)
      log_failure(receipt)
      registration.failure_handler&.call(receipt, env)
    rescue StandardError => error
      safe_message = IdentityRedactor.new(auth, receipt.view).scrub(error.message)
      log_failure_handler_error(registration.name, error.class, safe_message)
    end

    def publish(receipts)
      failures = receipts.select(&:failed?)
      env[RECEIPTS_KEY] = receipts
      env['omniauth.callback_receipts'] = receipts
      env['omniauth.identity_failures'] = failures
      env['omniauth.failure_materials'] = failures
      env[FAILURE_MATERIAL_KEY] = failures.last
    end

    def auth
      env['omniauth.auth']
    end

    def log_failure(receipt)
      message = safe_log_message(receipt)
      if strategy
        strategy.log(:error, message)
      else
        OmniAuth.logger.error(message)
      end
    end

    def log_failure_handler_error(name, error_class, safe_message)
      OmniAuth.logger.error(
        "(identity-callbacks) failure handler for #{name} raised #{error_class}: #{safe_message}"
      )
    end

    def safe_log_message(receipt)
      '[identity_callback] ' \
        "callback=#{receipt.name} correlation_id=#{receipt.correlation_id} " \
        "status=#{receipt.status} error_class=#{receipt.error_class} " \
        "error_message=#{receipt.public_message.inspect} view=#{receipt.view.to_hash.inspect}"
    end
  end
end
