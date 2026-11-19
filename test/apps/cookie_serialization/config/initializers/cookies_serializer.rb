# Pure data format: only JSON primitives can be instantiated.
# Overridden below, so this is not the current state of the application.
Rails.application.config.action_dispatch.cookies_serializer = :json

module MyApp
  module CookieSerializer
  end
end

# Unknown serializer: Brakeman cannot determine its behavior.
# Overridden below, so this is not the current state of the application either.
Rails.application.config.action_dispatch.cookies_serializer = MyApp::CookieSerializer

# Dual-read migration: writes JSON, but still reads Marshal-serialized cookies.
# This is the effective setting.
Rails.application.config.action_dispatch.cookies_serializer = :hybrid
