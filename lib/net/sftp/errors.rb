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

  # Raised when a response ends before a field that the packet's own flags or
  # counts require, or when a nested count claims more items than its enclosing
  # structure can hold.
  class TruncatedPacketError < Net::SFTP::Exception; end

  # Raised when an attribute flags value contains bits this protocol version
  # does not define. The length and order of the fields that follow such bits
  # are unknown, so the attributes cannot be parsed safely.
  class UnsupportedAttributeFlagsError < Net::SFTP::Exception; end

  # Raised when a response has bytes left over after the structure that its
  # count or flags describe has been parsed.
  class MalformedPacketError < Net::SFTP::Exception; end

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
