module Flipper
  # Top level error that all other errors inherit from.
  class Error < StandardError; end

  # Raised when gate can not be found for an actor.
  class GateNotFound < Error
    def initialize(actor)
      super "Could not find gate for #{actor.inspect}"
    end
  end

  # Raised when writing a feature whose key starts with
  # Flipper::RESERVED_KEY_PREFIX. An ArgumentError, like the adapters' other
  # reserved name errors.
  class ReservedKeyError < ArgumentError
    attr_reader :key

    def initialize(key)
      @key = key.to_s
      super "#{@key.inspect} is reserved for Flipper's internal use and cannot be used as a feature name"
    end
  end

  # Raised when attempting to declare a group name that has already been used.
  class DuplicateGroup < Error; end

  # Raised when an invalid value is set to a configuration property
  class InvalidConfigurationValue < Flipper::Error
    def initialize(message = nil)
      default = "Configuration value is not valid."
      super(message || default)
    end
  end

  # Raised when an actor grant asks for an expiry but the configured adapter
  # cannot enforce it. Failing loudly is safer than silently granting access
  # forever.
  class ActorExpirationNotSupported < Error
    def initialize(message = nil)
      default = "Actor expiration is not supported by this adapter. Wrap it with Flipper::Adapters::ActorExpiration or use Flipper::Managed."
      super(message || default)
    end
  end
end
