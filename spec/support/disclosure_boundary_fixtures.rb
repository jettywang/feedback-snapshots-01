# frozen_string_literal: true

# Fixtures for the disclosure-boundary integration spec. They live in a
# separate file so the secret literals never appear on the source lines of the
# exception frames: with send_extra_frame_data == :all the formatter emits the
# :code/:context source lines (which are not scrubbed), while frame :locals and
# request params are scrubbed. Confining the literals here keeps each secret in
# a channel that is actually subject to redaction.
module DisclosureBoundaryFixtures
  REQUEST_SENTINEL = 'request-secret-sentinel-value'.freeze
  OUTER_SENTINEL = 'outer-frame-secret-sentinel-value'.freeze
  INNER_SENTINEL = 'inner-cause-secret-sentinel-value'.freeze

  SHAREABLE_REQUEST_KEY = 'shareable_category'.freeze
  SHAREABLE_REQUEST_VALUE = 'billing-webhook'.freeze
  SCRUB_MARKER = '*' * 6

  class InnerCauseError < StandardError; end
  class OuterError < StandardError; end

  # Raises a genuine Exception#cause chain. Both locals use scrubbed variable
  # names (:*_password) and read their values from the secret holder so no
  # literal secret is present on the frame's own source line.
  class RaisingRackApp
    def call(_env)
      outer_password = DisclosureBoundaryFixtures.outer_sentinel
      begin
        raise_inner_cause
      rescue InnerCauseError
        raise OuterError, 'outer failure while handling request'
      end
    ensure
      outer_password
    end

    def raise_inner_cause
      inner_password = DisclosureBoundaryFixtures.inner_sentinel
      raise InnerCauseError, 'inner root cause'
    ensure
      inner_password
    end
  end

  # Holds the queued representation handed to the async handler without
  # serializing or transmitting it.
  class CapturingAsyncHandler
    attr_reader :queued_payload

    def call(payload)
      @queued_payload = payload
    end
  end

  # A deliberately defective formatter double: it delegates to the real
  # Backtrace formatter and then drops a single field (:message) from the
  # second level of the chain (the inner cause).
  class BrokenInnerCauseBacktrace
    def initialize(backtrace)
      @backtrace = backtrace
    end

    def to_h
      hash = @backtrace.to_h
      chain = hash[:trace_chain]
      chain[1][:exception].delete(:message) if chain && chain[1]
      hash
    end
  end

  def self.outer_sentinel
    OUTER_SENTINEL
  end

  def self.inner_sentinel
    INNER_SENTINEL
  end
end
