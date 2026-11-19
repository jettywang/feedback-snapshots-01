require "rails"
require "action_controller/railtie"

module MyApp
  class Application < Rails::Application
    config.load_defaults 6.1

    # Legacy format. Overridden by config/initializers/cookies_serializer.rb,
    # so this is not the current state of the application.
    config.action_dispatch.cookies_serializer = :marshal
  end
end
