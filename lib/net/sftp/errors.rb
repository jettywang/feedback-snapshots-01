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

  # Raised when a request cannot be expressed with a link-safe ("do not
  # follow symbolic links") semantic on the negotiated protocol version and
  # server extensions. The request is refused before any packet is sent, so
  # the link target is never modified by a fallback that follows links.
  class UnsupportedOperation < Net::SFTP::Exception; end

  # Raised when a handle-based, link-safe operation is asked to use a handle
  # that was not opened with the no-follow flag. Such a handle refers to the
  # link's target, so changing its attributes would modify the target rather
  # than the link itself; the request is refused before any packet is sent.
  class UnknownHandle < Net::SFTP::Exception; end

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
