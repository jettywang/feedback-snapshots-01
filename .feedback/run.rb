require "rbconfig"
ENV["PATH"] = File.dirname(RbConfig.ruby) + File::PATH_SEPARATOR + ENV.fetch("PATH")
ENV["BUNDLE_GEMFILE"] = File.expand_path("Gemfile", __dir__)
ENV["BUNDLE_PATH"] = File.expand_path("vendor", __dir__)
ENV["BUNDLE_APP_CONFIG"] = File.expand_path("vendor/config", __dir__)
load Gem.bin_path("bundler", "bundle")
