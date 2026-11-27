module Rollbar
  # Tracks the versioned state of the scrub (masking) policy so delayed
  # (async) payloads can be validated against the policy that is current
  # at transmission time, not only against the one that was current when
  # they were enqueued.
  #
  # Payloads scheduled for async delivery are stamped with the policy
  # version active at enqueue time. Before a delayed payload is
  # transmitted, the stamped version is compared with the current policy.
  # When a newer strict policy is in place, the payload is either
  # re-processed (scrubbed again and re-stamped) or deferred, depending
  # on Configuration#async_stale_policy. Payloads that are sent keep the
  # policy version they were sent under inside the payload data.
  class ScrubPolicy
    POLICY_VERSION_KEY = 'policy_version'

    attr_reader :version, :updated_at

    def initialize
      @version = 0
      @strict = false
      @updated_at = nil
    end

    def strict?
      @strict
    end

    def update(options = {})
      @version += 1
      @strict = options.fetch(:strict, true)
      @updated_at = Time.now

      self
    end

    # Stamps the payload data with the current policy version.
    def stamp(payload)
      data = payload_data(payload)
      return payload unless data

      data[POLICY_VERSION_KEY] = version

      payload
    end

    # Returns the policy version the payload was stamped with, or nil
    # when the payload carries no policy state.
    def version_of(payload)
      data = payload_data(payload)
      return unless data

      data[POLICY_VERSION_KEY] || data[POLICY_VERSION_KEY.to_sym]
    end

    private

    def payload_data(payload)
      return unless payload.is_a?(Hash)

      data = payload['data'] || payload[:data]
      data.is_a?(Hash) ? data : nil
    end
  end
end
