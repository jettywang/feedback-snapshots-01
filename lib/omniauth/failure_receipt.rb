require 'securerandom'

module OmniAuth
  # A server-side record of one authentication failure.
  #
  # The browser only ever learns the approved message key and this
  # receipt's id, which the user can quote to support. The receipt itself
  # keeps the original exception (with its backtrace), the phase the
  # failure happened in, and the strategy's name, and is handed to
  # OmniAuth.config.on_failure_receipt for controlled monitoring.
  class FailureReceipt
    # The message key exposed to the browser when the reported one is not
    # a developer-chosen Symbol, such as free text from an exception
    # message, which may contain private details.
    PUBLIC_FALLBACK_KEY = :internal_error

    attr_reader :id, :message_key, :error, :phase, :strategy_name

    def initialize(message_key:, error:, phase:, strategy_name:)
      @id = SecureRandom.hex(8)
      @message_key = message_key
      @error = error
      @phase = phase
      @strategy_name = strategy_name
    end

    # The failure category that may leave the server. A Symbol key is a
    # constant the strategy chose; anything else is treated as private
    # text and replaced with PUBLIC_FALLBACK_KEY.
    def public_message_key
      message_key.is_a?(Symbol) ? message_key : PUBLIC_FALLBACK_KEY
    end
  end
end
