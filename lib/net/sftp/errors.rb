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

  # Raised when the version handshake with the server cannot be completed
  # because its FXP_VERSION packet is invalid: a second FXP_VERSION after the
  # handshake finished, a protocol version neither side supports, or an
  # extension advertised twice with conflicting values. The negotiated
  # protocol and extensions are left untouched when this is raised.
  class NegotiationError < Net::SFTP::Exception; end

  # Raised when an extension operation is requested that the server did not
  # advertise for the current handshake, or when an extension operation is
  # attempted before the FXP_VERSION handshake has completed. The client never
  # falls back to a weaker plain request on its own: an unsupported extension
  # is an explicit failure.
  class ExtensionNotSupportedError < Net::SFTP::Exception; end

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
