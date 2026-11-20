# frozen_string_literal: true

# This class is the base class for \Net::HTTP response classes.
#
# == About the Examples
#
# :include: doc/net-http/examples.rdoc
#
# == Returned Responses
#
# \Method Net::HTTP.get_response returns
# an instance of one of the subclasses of \Net::HTTPResponse:
#
#   Net::HTTP.get_response(uri)
#   # => #<Net::HTTPOK 200 OK readbody=true>
#   Net::HTTP.get_response(hostname, '/nosuch')
#   # => #<Net::HTTPNotFound 404 Not Found readbody=true>
#
# As does method Net::HTTP#request:
#
#   req = Net::HTTP::Get.new(uri)
#   Net::HTTP.start(hostname) do |http|
#     http.request(req)
#   end # => #<Net::HTTPOK 200 OK readbody=true>
#
# \Class \Net::HTTPResponse includes module Net::HTTPHeader,
# which provides access to response header values via (among others):
#
# - \Hash-like method <tt>[]</tt>.
# - Specific reader methods, such as +content_type+.
#
# Examples:
#
#   res = Net::HTTP.get_response(uri) # => #<Net::HTTPOK 200 OK readbody=true>
#   res['Content-Type']               # => "text/html; charset=UTF-8"
#   res.content_type                  # => "text/html"
#
# == Response Subclasses
#
# \Class \Net::HTTPResponse has a subclass for each
# {HTTP status code}[https://en.wikipedia.org/wiki/List_of_HTTP_status_codes].
# You can look up the response class for a given code:
#
#   Net::HTTPResponse::CODE_TO_OBJ['200'] # => Net::HTTPOK
#   Net::HTTPResponse::CODE_TO_OBJ['400'] # => Net::HTTPBadRequest
#   Net::HTTPResponse::CODE_TO_OBJ['404'] # => Net::HTTPNotFound
#
# And you can retrieve the status code for a response object:
#
#   Net::HTTP.get_response(uri).code                 # => "200"
#   Net::HTTP.get_response(hostname, '/nosuch').code # => "404"
#
# The response subclasses (indentation shows class hierarchy):
#
# - Net::HTTPUnknownResponse (for unhandled \HTTP extensions).
#
# - Net::HTTPInformation:
#
#   - Net::HTTPContinue (100)
#   - Net::HTTPSwitchProtocol (101)
#   - Net::HTTPProcessing (102)
#   - Net::HTTPEarlyHints (103)
#
# - Net::HTTPSuccess:
#
#   - Net::HTTPOK (200)
#   - Net::HTTPCreated (201)
#   - Net::HTTPAccepted (202)
#   - Net::HTTPNonAuthoritativeInformation (203)
#   - Net::HTTPNoContent (204)
#   - Net::HTTPResetContent (205)
#   - Net::HTTPPartialContent (206)
#   - Net::HTTPMultiStatus (207)
#   - Net::HTTPAlreadyReported (208)
#   - Net::HTTPIMUsed (226)
#
# - Net::HTTPRedirection:
#
#   - Net::HTTPMultipleChoices (300)
#   - Net::HTTPMovedPermanently (301)
#   - Net::HTTPFound (302)
#   - Net::HTTPSeeOther (303)
#   - Net::HTTPNotModified (304)
#   - Net::HTTPUseProxy (305)
#   - Net::HTTPTemporaryRedirect (307)
#   - Net::HTTPPermanentRedirect (308)
#
# - Net::HTTPClientError:
#
#   - Net::HTTPBadRequest (400)
#   - Net::HTTPUnauthorized (401)
#   - Net::HTTPPaymentRequired (402)
#   - Net::HTTPForbidden (403)
#   - Net::HTTPNotFound (404)
#   - Net::HTTPMethodNotAllowed (405)
#   - Net::HTTPNotAcceptable (406)
#   - Net::HTTPProxyAuthenticationRequired (407)
#   - Net::HTTPRequestTimeOut (408)
#   - Net::HTTPConflict (409)
#   - Net::HTTPGone (410)
#   - Net::HTTPLengthRequired (411)
#   - Net::HTTPPreconditionFailed (412)
#   - Net::HTTPRequestEntityTooLarge (413)
#   - Net::HTTPRequestURITooLong (414)
#   - Net::HTTPUnsupportedMediaType (415)
#   - Net::HTTPRequestedRangeNotSatisfiable (416)
#   - Net::HTTPExpectationFailed (417)
#   - Net::HTTPMisdirectedRequest (421)
#   - Net::HTTPUnprocessableEntity (422)
#   - Net::HTTPLocked (423)
#   - Net::HTTPFailedDependency (424)
#   - Net::HTTPUpgradeRequired (426)
#   - Net::HTTPPreconditionRequired (428)
#   - Net::HTTPTooManyRequests (429)
#   - Net::HTTPRequestHeaderFieldsTooLarge (431)
#   - Net::HTTPUnavailableForLegalReasons (451)
#
# - Net::HTTPServerError:
#
#   - Net::HTTPInternalServerError (500)
#   - Net::HTTPNotImplemented (501)
#   - Net::HTTPBadGateway (502)
#   - Net::HTTPServiceUnavailable (503)
#   - Net::HTTPGatewayTimeOut (504)
#   - Net::HTTPVersionNotSupported (505)
#   - Net::HTTPVariantAlsoNegotiates (506)
#   - Net::HTTPInsufficientStorage (507)
#   - Net::HTTPLoopDetected (508)
#   - Net::HTTPNotExtended (510)
#   - Net::HTTPNetworkAuthenticationRequired (511)
#
# There is also the Net::HTTPBadResponse exception which is raised when
# there is a protocol error.
#
class Net::HTTPResponse
  # The maximum total size in bytes of the response header.
  MAX_RESPONSE_HEADER_LENGTH = 1024 * 1024 # 1 MiB

  # The maximum number of informational (1xx) responses accepted before the
  # final response.
  MAX_INFORMATIONAL_RESPONSES = 100

  # :stopdoc:
  # Thrown by #abort_body when called while #read_body is running, so that
  # control returns to the caller of #read_body instead of reading on.
  ABORT_BODY = Object.new
  private_constant :ABORT_BODY
  # :startdoc:

  class << self
    # true if the response has a body.
    def body_permitted?
      self::HAS_BODY
    end

    def exception_type   # :nodoc: internal use only
      self::EXCEPTION_TYPE
    end

    def read_new(sock)   #:nodoc: internal use only
      httpv, code, msg = read_status_line(sock)
      res = response_class(code).new(httpv, code, msg)
      each_response_header(sock) do |k,v|
        res.add_field k, v
      end
      res
    end

    def read_line(sock, limit, ignore_eof = false)   #:nodoc: internal use only
      sock.readuntil("\n", ignore_eof, limit: limit)
    rescue Net::ReadLimitExceeded
      raise Net::HTTPBadResponse, 'response line too long'
    end

    private
    # :stopdoc:

    def read_status_line(sock)
      str = read_line(sock, MAX_RESPONSE_HEADER_LENGTH).chop
      m = /\AHTTP(?:\/(\d+\.\d+))?\s+(\d\d\d)(?:\s+(.*))?\z/in.match(str) or
        raise Net::HTTPBadResponse, "wrong status line: #{str.dump}"
      m.captures
    end

    def response_class(code)
      CODE_TO_OBJ[code] or
      CODE_CLASS_TO_OBJ[code[0,1]] or
      Net::HTTPUnknownResponse
    end

    def each_response_header(sock)
      key = value = nil
      remaining = MAX_RESPONSE_HEADER_LENGTH
      while true
        line = read_line(sock, MAX_RESPONSE_HEADER_LENGTH, true)
        remaining -= line.bytesize
        raise Net::HTTPBadResponse, 'response header too large' if remaining < 0
        line = line.chomp
        break if line.empty?
        if line[0] == ?\s or line[0] == ?\t and value
          folded = line.strip
          unless folded.empty?
            value << ' ' unless value.empty?
            value << folded
          end
        else
          yield key, value if key
          key, value = line.strip.split(/\s*:\s*/, 2)
          raise Net::HTTPBadResponse, 'wrong header line format' if value.nil?
        end
      end
      yield key, value if key
    end
  end

  # next is to fix bug in RDoc, where the private inside class << self
  # spills out.
  public

  include Net::HTTPHeader

  def initialize(httpv, code, msg)   #:nodoc: internal use only
    @http_version = httpv
    @code         = code
    @message      = msg
    initialize_http_header nil
    @body = nil
    @body_complete = false
    @body_aborted = false
    @body_exception = nil
    @body_length = nil
    @body_counter = nil
    @reading_body = false
    @reading_thread = nil
    @read = false
    @uri  = nil
    @decode_content = false
    @body_encoding = false
    @ignore_eof = true
  end

  # The HTTP version supported by the server.
  attr_reader :http_version

  # The HTTP result code string. For example, '302'.  You can also
  # determine the response type by examining which response subclass
  # the response object is an instance of.
  attr_reader :code

  # The HTTP result message sent by the server. For example, 'Not Found'.
  attr_reader :message
  alias msg message   # :nodoc: obsolete

  # The URI used to fetch this response.  The response URI is only available
  # if a URI was used to create the request.
  attr_reader :uri

  # Set to true automatically when the request did not contain an
  # Accept-Encoding header from the user.
  attr_accessor :decode_content

  # Returns the value set by body_encoding=, or +false+ if none;
  # see #body_encoding=.
  attr_reader :body_encoding

  # Sets the encoding that should be used when reading the body:
  #
  # - If the given value is an Encoding object, that encoding will be used.
  # - Otherwise if the value is a string, the value of
  #   {Encoding#find(value)}[https://docs.ruby-lang.org/en/master/Encoding.html#method-c-find]
  #   will be used.
  # - Otherwise an encoding will be deduced from the body itself.
  #
  # Examples:
  #
  #   http = Net::HTTP.new(hostname)
  #   req = Net::HTTP::Get.new('/')
  #
  #   http.request(req) do |res|
  #     p res.body.encoding # => #<Encoding:ASCII-8BIT>
  #   end
  #
  #   http.request(req) do |res|
  #     res.body_encoding = "UTF-8"
  #     p res.body.encoding # => #<Encoding:UTF-8>
  #   end
  #
  def body_encoding=(value)
    value = Encoding.find(value) if value.is_a?(String)
    @body_encoding = value
  end

  # Whether to ignore EOF when reading bodies with a specified Content-Length
  # header.
  attr_accessor :ignore_eof

  def inspect   # :nodoc:
    "#<#{self.class} #{@code} #{@message} readbody=#{@read}>"
  end

  #
  # response <-> exception relationship
  #

  def code_type   #:nodoc:
    self.class
  end

  def error!   #:nodoc:
    message = @code
    message = "#{message} #{@message.dump}" if @message
    raise error_type().new(message, self)
  end

  def error_type   #:nodoc:
    self.class::EXCEPTION_TYPE
  end

  # Raises an HTTP error if the response is not 2xx (success).
  def value
    error! unless self.kind_of?(Net::HTTPSuccess)
  end

  def uri= uri # :nodoc:
    @uri = uri.dup if uri
  end

  #
  # header (for backward compatibility only; DO NOT USE)
  #

  def response   #:nodoc:
    warn "Net::HTTPResponse#response is obsolete", uplevel: 1 if $VERBOSE
    self
  end

  def header   #:nodoc:
    warn "Net::HTTPResponse#header is obsolete", uplevel: 1 if $VERBOSE
    self
  end

  def read_header   #:nodoc:
    warn "Net::HTTPResponse#read_header is obsolete", uplevel: 1 if $VERBOSE
    self
  end

  #
  # body
  #

  # Returns +true+ if the response body has been read completely (or if the
  # response has no body at all).
  #
  # A body that was cut short by #abort_body, or whose reading was interrupted
  # by an exception, leaves this +false+.
  def body_complete?
    @body_complete
  end

  # Returns +true+ if reading of the response body was cut short, either by
  # #abort_body or by an exception raised while the body was being read.
  def body_aborted?
    @body_aborted
  end

  # Returns the exception that ended reading of the body, or +nil+ if reading
  # ended normally.
  #
  # When an exception is raised from a #read_body block, that same exception
  # object is stored here (and is also the exception seen by the caller of
  # Net::HTTP#request). Passing +exception+ to #abort_body records it as well,
  # without raising, so the caller can re-raise the original object later.
  attr_reader :body_exception
  alias body_error body_exception

  # Explicitly abandons the response body.
  #
  # Call this from a Net::HTTP#request block or from a #read_body block when
  # only a prefix of the body (for example, enough to authenticate) is needed.
  # Reading stops immediately; the rest is not drained.
  #
  # The remaining bytes are discarded along with the connection, unless the
  # body was already complete (or the response has no body):
  #
  # - If the whole body has already been read from the connection, there is
  #   nothing left to discard. The connection remains reusable, and the next
  #   request on the same Net::HTTP session uses it.
  # - Otherwise the remaining bytes stay unread and the connection is closed
  #   at the end of the request; the next request opens a new connection.
  #   Net::HTTP does not silently drain them, since an unknown-length body can
  #   block indefinitely and leftover bytes must never be mistaken for the
  #   next response (for example after a cancelled download of an
  #   authentication prefix).
  #
  # Use #body_complete? and #body_aborted? after the request to learn which
  # happened. #body_exception returns the exception that ended reading, if
  # any; passing +exception+ here records it without raising, so the caller
  # can re-raise the original exception object later.
  #
  # When called while #read_body is running, control returns from that
  # #read_body call; otherwise reading of the body is skipped.
  #
  # Returns +true+ if the body was abandoned, +false+ if there was nothing
  # left to abandon (the body was already complete or absent).
  def abort_body(exception = nil)
    return false if @body_complete
    if @body_counter
      @body_counter.abort!
      if @body_length && @body_counter.count >= @body_length
        # All body bytes have already been consumed from the connection, so
        # there is nothing left to discard and the connection stays clean.
        @body_complete = true
        return false
      end
    end
    @body_aborted = true
    @body_exception ||= exception
    if @reading_body && @reading_thread.equal?(Thread.current)
      # Leave the enclosing read_body call; the remaining bytes stay unread
      # and the transport closes the connection when the request ends.
      throw ABORT_BODY
    end
    true
  end

  def reading_body(sock, reqmethodallowbody)  #:nodoc: internal use only
    @socket = sock
    @body_exist = reqmethodallowbody && self.class.body_permitted?
    @body_complete = !@body_exist || empty_body?
    begin
      yield
      self.body unless @body_aborted
    rescue Exception => err
      # Stop a later implicit read from draining the rest, and keep the
      # original exception available on the response object. The transport
      # closes the connection when the exception propagates.
      @body_aborted = true unless @body_complete
      @body_exception ||= err
      raise
    ensure
      @socket = nil
    end
  end

  # :nodoc: true if the response body is known to be empty before reading.
  def empty_body?
    return false if chunked? || @header['transfer-encoding']
    content_length() == 0
  rescue Net::HTTPHeaderSyntaxError
    false
  end
  private :empty_body?

  # Gets the entity body returned by the remote HTTP server.
  #
  # If a block is given, the body is passed to the block, and
  # the body is provided in fragments, as it is read in from the socket.
  #
  # If +dest+ argument is given, response is read into that variable,
  # with <code>dest#<<</code> method (it could be String or IO, or any
  # other object responding to <code><<</code>).
  #
  # Calling this method a second or subsequent time for the same
  # HTTPResponse object will return the value already read.
  #
  # If reading stops early because the block calls #abort_body or raises,
  # only the bytes delivered so far are kept, #body_complete? is +false+ and
  # the connection is closed when the request finishes; see #abort_body for
  # the exact disposal rules. A block that uses +break+ keeps the historical
  # behavior: the rest of the body is read and discarded afterwards.
  #
  #   http.request_get('/index.html') {|res|
  #     puts res.read_body
  #   }
  #
  #   http.request_get('/index.html') {|res|
  #     p res.read_body.object_id   # 538149362
  #     p res.read_body.object_id   # 538149362
  #   }
  #
  #   # using iterator
  #   http.request_get('/index.html') {|res|
  #     res.read_body do |segment|
  #       print segment
  #     end
  #   }
  #
  def read_body(dest = nil, &block)
    if @read
      raise IOError, "#{self.class}\#read_body called twice" if dest or block
      return @body
    end
    return if @body_aborted
    to = procdest(dest, block)
    if @body_exist
      to = @body_counter = BodyCounter.new(to)
    end
    stream_check
    @body_length = nil
    @reading_body = true
    @reading_thread = Thread.current
    completed = false
    begin
      catch(ABORT_BODY) do
        if @body_exist
          read_body_0 to
        else
          @body = nil
        end
        completed = true
      end
    ensure
      @reading_body = false
      @reading_thread = nil
      interrupted = @body_aborted
      @body_counter = nil
      if completed || interrupted
        if to.is_a?(BodyCounter)
          # A known length is also met when abort_body runs from the block
          # that received the final byte: nothing is left on the wire.
          @body_complete = completed &&
            (@body_length.nil? || to.count >= @body_length)
          if @body_complete
            @body = to.dest
          elsif !to.dest.is_a?(Net::ReadAdapter)
            # A caller-supplied destination keeps the prefix that was
            # received, matching a block that used `break'.
            @body = to.dest
          end
        else
          @body_complete = completed
        end
        @read = true
      end
      # A block that used `break' (neither completed nor aborted) leaves the
      # body unread here; reading_body's implicit read then drains it, as
      # before.
    end
    return if @body.nil?

    case enc = @body_encoding
    when Encoding, false, nil
      # Encoding: force given encoding
      # false/nil: do not force encoding
    else
      # other value: detect encoding from body
      enc = detect_encoding(@body)
    end

    @body.force_encoding(enc) if enc

    @body
  end

  # Returns the string response body;
  # note that repeated calls for the unmodified body return a cached string:
  #
  #   path = '/todos/1'
  #   Net::HTTP.start(hostname) do |http|
  #     res = http.get(path)
  #     p res.body
  #     p http.head(path).body # No body.
  #   end
  #
  # Output:
  #
  #   "{\n  \"userId\": 1,\n  \"id\": 1,\n  \"title\": \"delectus aut autem\",\n  \"completed\": false\n}"
  #   nil
  #
  def body
    read_body()
  end

  # Sets the body of the response to the given value.
  def body=(value)
    @body = value
  end

  alias entity body   #:nodoc: obsolete

  private

  # :nodoc:
  def detect_encoding(str, encoding=nil)
    if encoding
    elsif encoding = type_params['charset']
    elsif encoding = check_bom(str)
    else
      encoding = case content_type&.downcase
      when %r{text/x(?:ht)?ml|application/(?:[^+]+\+)?xml}
        /\A<xml[ \t\r\n]+
          version[ \t\r\n]*=[ \t\r\n]*(?:"[0-9.]+"|'[0-9.]*')[ \t\r\n]+
          encoding[ \t\r\n]*=[ \t\r\n]*
          (?:"([A-Za-z][\-A-Za-z0-9._]*)"|'([A-Za-z][\-A-Za-z0-9._]*)')/x =~ str
        encoding = $1 || $2 || Encoding::UTF_8
      when %r{text/html.*}
        sniff_encoding(str)
      end
    end
    return encoding
  end

  # :nodoc:
  def sniff_encoding(str, encoding=nil)
    # the encoding sniffing algorithm
    # http://www.w3.org/TR/html5/parsing.html#determining-the-character-encoding
    if enc = scanning_meta(str)
      enc
    # 6. last visited page or something
    # 7. frequency
    elsif str.ascii_only?
      Encoding::US_ASCII
    elsif str.dup.force_encoding(Encoding::UTF_8).valid_encoding?
      Encoding::UTF_8
    end
    # 8. implementation-defined or user-specified
  end

  # :nodoc:
  def check_bom(str)
    case str.byteslice(0, 2)
    when "\xFE\xFF"
      return Encoding::UTF_16BE
    when "\xFF\xFE"
      return Encoding::UTF_16LE
    end
    if "\xEF\xBB\xBF" == str.byteslice(0, 3)
      return Encoding::UTF_8
    end
    nil
  end

  # :nodoc:
  def scanning_meta(str)
    require 'strscan'
    ss = StringScanner.new(str)
    if ss.scan_until(/<meta[\t\n\f\r ]*/)
      attrs = {} # attribute_list
      got_pragma = false
      need_pragma = nil
      charset = nil

      # step: Attributes
      while attr = get_attribute(ss)
        name, value = *attr
        next if attrs[name]
        attrs[name] = true
        case name
        when 'http-equiv'
          got_pragma = true if value == 'content-type'
        when 'content'
          encoding = extracting_encodings_from_meta_elements(value)
          unless charset
            charset = encoding
          end
          need_pragma = true
        when 'charset'
          need_pragma = false
          charset = value
        end
      end

      # step: Processing
      return if need_pragma.nil?
      return if need_pragma && !got_pragma

      charset = Encoding.find(charset) rescue nil
      return unless charset
      charset = Encoding::UTF_8 if charset == Encoding::UTF_16
      return charset # tentative
    end
    nil
  end

  def get_attribute(ss)
    ss.scan(/[\t\n\f\r \/]*/)
    if ss.peek(1) == '>'
      ss.getch
      return nil
    end
    name = ss.scan(/[^=\t\n\f\r \/>]*/)
    name.downcase!
    raise if name.empty?
    ss.skip(/[\t\n\f\r ]*/)
    if ss.getch != '='
      value = ''
      return [name, value]
    end
    ss.skip(/[\t\n\f\r ]*/)
    case ss.peek(1)
    when '"'
      ss.getch
      value = ss.scan(/[^"]+/)
      value.downcase!
      ss.getch
    when "'"
      ss.getch
      value = ss.scan(/[^']+/)
      value.downcase!
      ss.getch
    when '>'
      value = ''
    else
      value = ss.scan(/[^\t\n\f\r >]+/)
      value.downcase!
    end
    [name, value]
  end

  def extracting_encodings_from_meta_elements(value)
    # http://dev.w3.org/html5/spec/fetching-resources.html#algorithm-for-extracting-an-encoding-from-a-meta-element
    if /charset[\t\n\f\r ]*=(?:"([^"]*)"|'([^']*)'|["']|\z|([^\t\n\f\r ;]+))/i =~ value
      return $1 || $2 || $3
    end
    return nil
  end

  ##
  # Checks for a supported Content-Encoding header and yields an Inflate
  # wrapper for this response's socket when zlib is present.  If the
  # Content-Encoding is not supported or zlib is missing, the plain socket is
  # yielded.
  #
  # If a Content-Range header is present, a plain socket is yielded as the
  # bytes in the range may not be a complete deflate block.

  def inflater # :nodoc:
    return yield @socket unless Net::HTTP::HAVE_ZLIB
    return yield @socket unless @decode_content
    return yield @socket if self['content-range']

    v = self['content-encoding']
    case v&.downcase
    when 'deflate', 'gzip', 'x-gzip' then
      self.delete 'content-encoding'

      inflate_body_io = Inflater.new(@socket)

      begin
        yield inflate_body_io
        success = true
      ensure
        begin
          inflate_body_io.finish
          if self['content-length']
            self['content-length'] = inflate_body_io.bytes_inflated.to_s
          end
        rescue => err
          # Ignore #finish's error if there is an exception from yield
          raise err if success
        end
      end
    when 'none', 'identity' then
      self.delete 'content-encoding'

      yield @socket
    else
      yield @socket
    end
  end

  def read_body_0(dest)
    inflater do |inflate_body_io|
      if chunked?
        read_chunked dest, inflate_body_io
        return
      end

      @socket = inflate_body_io

      # Transfer-Encoding overrides Content-Length, so a body that is not
      # chunk-framed runs until the server closes the connection.
      # See RFC 9112 Section 6.3.
      unless @header['transfer-encoding']
        clen = content_length()
        if clen
          # Inflated output does not correspond to Content-Length, so the
          # byte counter cannot tell whether the body is complete.
          @body_length = clen unless inflate_body_io.is_a?(Inflater)
          @socket.read clen, dest, @ignore_eof
          return
        end
        clen = range_length()
        if clen
          @body_length = clen unless inflate_body_io.is_a?(Inflater)
          @socket.read clen, dest
          return
        end
      end
      @body_length = nil
      @socket.read_all dest
    end
  end

  ##
  # read_chunked reads from +@socket+ for chunk-size, chunk-extension, CRLF,
  # etc. and +chunk_data_io+ for chunk-data which may be deflate or gzip
  # encoded.
  #
  # See RFC 2616 section 3.6.1 for definitions

  def read_chunked(dest, chunk_data_io) # :nodoc:
    total = 0
    while true
      line = self.class.read_line(@socket, MAX_RESPONSE_HEADER_LENGTH).chop
      hexlen = line.slice(/[0-9a-fA-F]+/) or
          raise Net::HTTPBadResponse, "wrong chunk size line: #{line}"
      len = hexlen.hex
      break if len == 0
      begin
        chunk_data_io.read len, dest
      ensure
        total += len
        # After abort_body the connection is closed anyway; waiting for the
        # chunk terminator (or the rest of an unknown-length body) here would
        # defeat the early exit.
        @socket.read 2 unless @body_aborted # \r\n
      end
    end
    until self.class.read_line(@socket, MAX_RESPONSE_HEADER_LENGTH).chop.empty?
      # none
    end
  end

  def stream_check
    raise IOError, 'attempt to read body out of block' if @socket.nil? || @socket.closed?
  end

  def procdest(dest, block)
    raise ArgumentError, 'both arg and block given for HTTP method' if
      dest and block
    if block
      Net::ReadAdapter.new(block)
    else
      dest || +''
    end
  end

  # A destination that records how many bytes were handed to +dest+, so
  # #abort_body can tell whether a body with a known length has been fully
  # consumed even when only a prefix was delivered to the caller.
  class BodyCounter # :nodoc:
    attr_reader :dest, :count

    def initialize(dest)
      @dest = dest
      @count = 0
      @aborted = false
    end

    def <<(str)
      return self if @aborted
      @count += str.bytesize
      @dest << str
    end

    def abort!
      @aborted = true
    end
  end
  private_constant :BodyCounter

  ##
  # Inflater is a wrapper around Net::BufferedIO that transparently inflates
  # zlib and gzip streams.

  class Inflater # :nodoc:

    ##
    # Creates a new Inflater wrapping +socket+

    def initialize socket
      @socket = socket
      # zlib with automatic gzip detection
      @inflate = Zlib::Inflate.new(32 + Zlib::MAX_WBITS)
    end

    ##
    # Finishes the inflate stream.

    def finish
      return if @inflate.total_in == 0
      @inflate.finish
    end

    ##
    # The number of bytes inflated, used to update the Content-Length of
    # the response.

    def bytes_inflated
      @inflate.total_out
    end

    ##
    # Returns a Net::ReadAdapter that inflates each read chunk into +dest+.
    #
    # This allows a large response body to be inflated without storing the
    # entire body in memory.

    def inflate_adapter(dest)
      if dest.respond_to?(:set_encoding)
        dest.set_encoding(Encoding::ASCII_8BIT)
      elsif dest.respond_to?(:force_encoding)
        dest.force_encoding(Encoding::ASCII_8BIT)
      end
      block = proc do |compressed_chunk|
        @inflate.inflate(compressed_chunk) do |chunk|
          compressed_chunk.clear
          dest << chunk
        end
      end

      Net::ReadAdapter.new(block)
    end

    ##
    # Reads +clen+ bytes from the socket, inflates them, then writes them to
    # +dest+.  +ignore_eof+ is passed down to Net::BufferedIO#read
    #
    # Unlike Net::BufferedIO#read, this method returns more than +clen+ bytes.
    # At this time there is no way for a user of Net::HTTPResponse to read a
    # specific number of bytes from the HTTP response body, so this internal
    # API does not return the same number of bytes as were requested.
    #
    # See https://bugs.ruby-lang.org/issues/6492 for further discussion.

    def read clen, dest, ignore_eof = false
      temp_dest = inflate_adapter(dest)

      @socket.read clen, temp_dest, ignore_eof
    end

    ##
    # Reads the rest of the socket, inflates it, then writes it to +dest+.

    def read_all dest
      temp_dest = inflate_adapter(dest)

      @socket.read_all temp_dest
    end

  end

end

