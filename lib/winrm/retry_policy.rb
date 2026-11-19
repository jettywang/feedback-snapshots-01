# Copyright 2016 Shawn Neal <sneal@sneal.net>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'httpclient'
require_relative 'exceptions'

module WinRM
  # A bounded retry budget shared by every layer (HTTP transport errors,
  # WSMan faults and shell resets) of a single command execution.
  #
  # One policy instance is created per Shells::Base#run call and threaded
  # through shell open, command send and output receive so that retries at
  # different layers draw from the same budget instead of multiplying
  # against each other.
  #
  # The clock and sleeper are injectable so tests can simulate the passage
  # of time without real sleeps.
  class RetryPolicy
    # Failures that prove the request never reached the server. Retrying a
    # non-idempotent operation (e.g. starting a remote command) is safe.
    PRE_SEND_EXCEPTIONS = [
      Errno::EACCES, Errno::EADDRINUSE, Errno::ECONNREFUSED, Errno::ETIMEDOUT,
      Errno::ENETUNREACH, Errno::EHOSTUNREACH, HTTPClient::ConnectTimeoutError
    ].freeze

    # Failures where the request may have reached the server before the
    # connection dropped or the read timed out. The outcome of a
    # non-idempotent operation is unknown and must not be replayed.
    AMBIGUOUS_EXCEPTIONS = [
      Errno::ECONNRESET, Errno::EPIPE,
      HTTPClient::ReceiveTimeoutError, HTTPClient::KeepAliveDisconnected
    ].freeze

    # The server produced a definitive response (fault or HTTP error), so
    # retrying cannot double-execute anything.
    DEFINITIVE_EXCEPTIONS = [
      ::WinRM::WinRMWSManFault, ::WinRM::WinRMHTTPTransportError,
      ::WinRM::WinRMAuthorizationError
    ].freeze

    RETRYABLE_EXCEPTIONS = (
      PRE_SEND_EXCEPTIONS + AMBIGUOUS_EXCEPTIONS + DEFINITIVE_EXCEPTIONS
    ).freeze

    DEFAULT_CLOCK = -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
    DEFAULT_SLEEPER = ->(seconds) { sleep(seconds) }

    # @return [Integer] maximum number of retries after the initial attempt
    attr_reader :limit

    # @return [Integer] seconds to wait between retries
    attr_reader :delay

    # @return [Integer] retries consumed so far across all layers
    attr_reader :retries_used

    def initialize(limit:, delay:, clock: DEFAULT_CLOCK, sleeper: DEFAULT_SLEEPER)
      @limit = limit
      @delay = delay
      @clock = clock
      @sleeper = sleeper
      @retries_used = 0
    end

    # @return [Integer] retries still available to any layer
    def retries_remaining
      limit - retries_used
    end

    # @return [Boolean] true while at least one retry remains in the budget
    def retry?
      retries_remaining > 0
    end

    # Consumes one retry from the shared budget without waiting. Used by
    # layers that historically did not pause between attempts (shell reset).
    def consume_retry
      @retries_used += 1
    end

    # Consumes one retry from the shared budget and waits the configured
    # delay through the injectable sleeper.
    def wait_for_retry
      consume_retry
      @sleeper.call(delay)
    end

    # @return [Numeric] current time of the injectable clock
    def now
      @clock.call
    end
  end
end
