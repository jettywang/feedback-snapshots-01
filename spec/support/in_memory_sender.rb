# A sender that keeps every payload it receives in process memory. It is a
# stand-in for a real destination egress (the external Rollbar API or the
# internal on-call desk) and lets acceptance specs compare the exact payloads
# each destination receives without any network I/O.
module Rollbar
  class InMemorySender
    attr_reader :name, :received

    def initialize(name = nil)
      @name = name
      @received = []
    end

    # Destination senders are called as +#call(payload, destination)+.
    def call(payload, destination = nil)
      @received << Rollbar::Util.deep_copy(payload)

      payload
    end

    def last_payload
      @received.last
    end

    def reset!
      @received.clear
    end

    def count
      @received.size
    end
  end
end
