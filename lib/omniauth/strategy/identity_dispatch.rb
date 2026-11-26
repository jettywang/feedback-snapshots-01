require 'securerandom'

module OmniAuth
  module Strategy
    # Hands detached auth views to configured callbacks immediately before app.
    module IdentityDispatch
      CORRELATION_KEY = 'omniauth.correlation_id'.freeze

      private

      def attach_failure_material!(message_key, exception)
        correlation_id = env[CORRELATION_KEY] ||= SecureRandom.uuid
        view = failure_view_policy.project(env['omniauth.auth'], :correlation_id => correlation_id)
        safe_message = IdentityRedactor.new(env['omniauth.auth'], view).scrub(exception&.message)
        receipt = IdentityReceipt.new(
          :name => message_key,
          :correlation_id => correlation_id,
          :view => view,
          :error => exception,
          :public_message => safe_message
        )
        env['omniauth.failure_material'] = receipt
        env['omniauth.failure_materials'] = [receipt]
        receipt
      end

      def failure_view_policy
        views = OmniAuth.config.auth_views
        return views[:failure] if views.key?(:failure)

        AuthView.new(:fields => OmniAuth.config.failure_auth_fields || [])
      end

      def dispatch_identity_callbacks!(app_env)
        return unless app_env['omniauth.auth']

        views = OmniAuth.config.auth_views
        callbacks = OmniAuth.config.identity_callbacks
        callbacks_empty = callbacks.nil? || callbacks.empty?
        return if views.names.empty? && callbacks_empty

        correlation_id = app_env[CORRELATION_KEY] ||= SecureRandom.uuid
        app_env['omniauth.auth_views'] = views.project_all(
          app_env['omniauth.auth'],
          :correlation_id => correlation_id
        ) unless views.names.empty?

        callbacks.dispatch(
          app_env,
          :correlation_id => correlation_id,
          :strategy => self
        ) unless callbacks_empty
      end
    end
  end
end
