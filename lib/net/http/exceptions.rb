# frozen_string_literal: true
module Net
  # Net::HTTP exception class.
  # You cannot use Net::HTTPExceptions directly; instead, you must use
  # its subclasses.
  module HTTPExceptions # :nodoc:
    def initialize(msg, res)   #:nodoc:
      super msg
      @response = res
    end
    attr_reader :response
    alias data response    #:nodoc: obsolete
  end

  # :stopdoc:
  class HTTPError < ProtocolError
    include HTTPExceptions
  end

  class HTTPRetriableError < ProtoRetriableError
    include HTTPExceptions
  end

  class HTTPClientException < ProtoServerError
    include HTTPExceptions
  end

  class HTTPFatalError < ProtoFatalError
    include HTTPExceptions
  end

  # We cannot use the name "HTTPServerError", it is the name of the response.
  HTTPServerException = HTTPClientException # :nodoc:
  deprecate_constant(:HTTPServerException)

  # Raised when the decompressed response body exceeds the limit set by
  # Net::HTTP#max_decompressed_body_size.
  #
  # This error is not retried; the connection is closed before it is
  # propagated to the caller.
  class HTTPDecompressedBodyTooLarge < HTTPError
    def initialize(msg)   #:nodoc:
      super(msg, nil)
    end
  end
end
