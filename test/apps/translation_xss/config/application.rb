require_relative "boot"

require "rails"
require "action_controller/railtie"

module TranslationXss
  class Application < Rails::Application
    config.load_defaults 7.0
    config.eager_load = false
  end
end
