module Net; module SFTP

  # The base exception class for the SFTP system.
  class Exception < RuntimeError; end

  # Raised when the SFTP channel closes while requests are pending or before
  # the session is open, and when sending on a closed session.
  class SessionClosedError < Net::SFTP::Exception
    def initialize(message = "SFTP session closed")
      super
    end
  end

  # Raised when a response packet cannot be parsed, or when its type or
  # status code does not satisfy the contract of the request it answers.
  # A matching request id is not enough: an FXP_OPEN, for instance, is only
  # answered by FXP_HANDLE (or an error FXP_STATUS), so a bare FXP_STATUS
  # with FX_OK cannot stand in for a handle. The offending request is failed
  # with this error and no success response or callback is delivered.
  class MalformedPacketError < Net::SFTP::Exception
  end

  # A exception class for reporting a non-success result of an operation.
  class StatusException < Net::SFTP::Exception

    # The response object that caused the exception.
    attr_reader :response

    # The error code (numeric)
    attr_reader :code

    # The description of the error
    attr_reader :description

    # Any incident-specific text given when the exception was raised
    attr_reader :text

    # Create a new status exception that reports the given code and
    # description.
    def initialize(response, text=nil)
      @response, @text = response, text
      @code = response.code
      @description = response.message
      @description = Response::MAP[@code] if @description.nil? || @description.empty?
    end

    # Override the default message format, to include the code and
    # description.
    def message
      m = super.dup
      m << " #{text}" if text
      m << " (#{code}, #{description.inspect})"
    end

  end
end; end
