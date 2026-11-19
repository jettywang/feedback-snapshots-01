# Copyright 2010 Dan Wanek <dan.wanek@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

module WinRM
  # WinRM base class for errors
  class WinRMError < StandardError; end

  # Authorization Error
  class WinRMAuthorizationError < WinRMError; end

  # Mixed into an exception raised by the caller's own output callback. Shell
  # retry logic checks this marker so a callback error is never mistaken for a
  # transport fault that would cause the remote command to be sent again.
  module OutputCallbackError; end

  # Details attached to the primary execution error so callers can still see
  # what happened while the command/shell was being released. The original
  # error is never replaced by a cleanup failure.
  module FailureDetails
    # @return [WinRM::Output, nil] output collected before the failure
    attr_accessor :output

    # @return [Array<WinRM::CleanupStatus>] cleanup attempts tied to this error
    attr_accessor :cleanup_statuses

    # @return [Array<Exception>] cleanup errors that did not replace the primary
    def cleanup_errors
      Array(cleanup_statuses).map(&:error).compact
    end

    # Attaches failure details to any exception without hiding it. Exceptions
    # that are frozen cannot be extended; the original exception is returned
    # unchanged in that case.
    def self.attach(error, output: nil, cleanup_statuses: nil)
      return error unless error.is_a?(Exception)
      return error if error.frozen?

      error.extend(self) unless error.is_a?(self)
      error.output = output if error.output.nil? && !output.nil?
      if cleanup_statuses
        existing = Array(error.cleanup_statuses)
        error.cleanup_statuses = existing + Array(cleanup_statuses)
      end
      error
    end

    # Tags an exception raised by the caller's output callback so it is never
    # treated as a retryable transport fault.
    def self.mark_output_callback(error)
      return error unless error.is_a?(Exception)
      return error if error.frozen?

      error.extend(OutputCallbackError) unless error.is_a?(OutputCallbackError)
      error
    end

    # Attaches only partial output, used by response readers that observe the
    # exception before the shell layer adds cleanup information.
    def self.attach_output(error, output)
      attach(error, output: output)
    end
  end

  # Raised when releasing a command or shell fails in a way that is not a
  # protocol-defined "already gone" condition. It always carries the original
  # low level error.
  class CleanupError < WinRMError
    attr_reader :action
    attr_reader :shell_id
    attr_reader :command_id
    attr_reader :original_error

    def initialize(message, action:, shell_id:, command_id: nil, original_error: nil)
      @action = action
      @shell_id = shell_id
      @command_id = command_id
      @original_error = original_error
      super(message)
    end

    # @return [Exception, nil] the transport/protocol error that caused this
    def cause
      @original_error || super
    end
  end

  # The outcome of one cleanup request (Signal or Delete). A tolerated fault is
  # recorded as :ignored instead of being silently dropped.
  class CleanupStatus
    attr_reader :action
    attr_reader :shell_id
    attr_reader :command_id
    attr_reader :error
    attr_reader :outcome

    def initialize(action:, shell_id:, command_id: nil, error: nil, outcome: nil)
      @action = action
      @shell_id = shell_id
      @command_id = command_id
      @error = error
      @outcome = outcome || (error ? :failed : :ok)
    end

    def ok?
      @outcome == :ok
    end

    def failed?
      @outcome == :failed
    end

    def ignored?
      @outcome == :ignored
    end

    def skipped?
      @outcome == :skipped
    end

    def to_s
      details = [@action, @shell_id, @command_id].compact.join(' ')
      "#{details} #{@outcome}"
    end
  end

  # Shell creation error
  class InvalidShellError < WinRMError; end

  # Exitcode error
  class InvalidExitCode < WinRMError; end

  # Shell creation error
  class InvalidTransportError < WinRMError
    attr_reader :invalid_transport

    def initialize(invalid_transport, valid_transports)
      @invalid_transport = invalid_transport
      super(
        "Invalid transport '#{invalid_transport}' specified" \
        ", expected: #{valid_transports.join(', ')}."
      )
    end
  end

  # A Fault returned in the SOAP response. The XML node is a WSManFault
  class WinRMWSManFault < WinRMError
    attr_reader :fault_code
    attr_reader :fault_description

    def initialize(fault_description, fault_code)
      @fault_description = fault_description
      @fault_code = fault_code
      super("[WSMAN ERROR CODE: #{fault_code}]: #{fault_description}")
    end
  end

  # A Fault returned in the SOAP response. The XML node contains Code, SubCode and Reason
  class WinRMSoapFault < WinRMError
    attr_reader :code
    attr_reader :subcode
    attr_reader :reason

    def initialize(code, subcode, reason)
      @code = code
      @subcode = subcode
      @reason = reason
      super("[SOAP ERROR CODE: #{code} (#{subcode})]: #{reason}")
    end
  end

  # A Fault returned in the SOAP response. The XML node is a MSFT_WmiError
  class WinRMWMIError < WinRMError
    attr_reader :error_code
    attr_reader :error

    def initialize(error, error_code)
      @error = error
      @error_code = error_code
      super("[WMI ERROR CODE: #{error_code}]: #{error}")
    end
  end

  # non-200 response without a SOAP fault
  class WinRMHTTPTransportError < WinRMError
    attr_reader :status_code

    def initialize(msg, status_code = nil)
      @status_code = status_code
      super(msg + " (#{status_code}).")
    end
  end
end
