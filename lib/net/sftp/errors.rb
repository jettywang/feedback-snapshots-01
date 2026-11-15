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

  # Raised when the declared length of an SFTP packet falls outside the
  # framing bounds. Unlike a malformed payload inside a complete frame, an
  # unusable length means the packet boundaries cannot be trusted, so all of
  # the requests still pending at that point fail with this error and the
  # session discards its buffered input.
  class FramingError < Net::SFTP::Exception
    # The length field of the offending packet.
    attr_reader :length

    def initialize(length, message = "invalid SFTP packet length #{length}")
      @length = length
      super(message)
    end
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
