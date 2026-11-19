Rails.application.configure do
  # Brakeman only evaluates config/environments/production.rb, so this
  # environment configuration must not be treated as the current state.
  config.action_dispatch.cookies_serializer = :marshal
end
