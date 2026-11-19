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

  # Raised when a command request may have reached the remote host but the
  # response was lost (e.g. the connection dropped or the read timed out
  # after the request was sent). The remote command may or may not have
  # executed, so the gem does NOT replay it automatically: remote execution
  # is not idempotent. Callers can rescue this specific error to detect the
  # ambiguous state and reconcile manually (e.g. poll for side effects).
  class WinRMCommandDeliveryUnknownError < WinRMError
    attr_reader :command, :shell_id

    def initialize(command, shell_id)
      @command = command
      @shell_id = shell_id
      super(
        'The command may or may not have been executed on the remote host: ' \
        'the connection failed after the request was sent. The command was ' \
        'not retried because remote execution is not idempotent. ' \
        "Command: #{command}, shell_id: #{shell_id}"
      )
    end
  end

  # Raised when a Receive loop cannot finish within the configured bounds
  # (the shared retry budget is exhausted or the receive wait limit is
  # exceeded). Any output received before the failure is preserved on
  # #output so callers do not lose partial results.
  class WinRMReceiveRetriesExhausted < WinRMError
    attr_accessor :output

    def initialize(message, output: nil)
      @output = output
      super(message)
    end
  end
end
