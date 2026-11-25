# frozen_string_literal: true
#
# = net/ftp.rb - FTP Client Library
#
# Written by Shugo Maeda <shugo@ruby-lang.org>.
#
# Documentation by Gavin Sinclair, sourced from "Programming Ruby" (Hunt/Thomas)
# and "Ruby In a Nutshell" (Matsumoto), used with permission.
#
# This library is distributed under the terms of the Ruby license.
# You can freely distribute/modify this library.
#
# It is included in the Ruby standard library.
#
# See the Net::FTP class for an overview.
#

require "socket"
require "monitor"
require "net/protocol"
require "time"
require "digest"
require "json"
begin
  require "openssl"
rescue LoadError
end

module Net

  # :stopdoc:
  class FTPError < StandardError; end
  class FTPReplyError < FTPError; end
  class FTPTempError < FTPError; end
  class FTPPermError < FTPError; end
  class FTPProtoError < FTPError; end
  class FTPConnectionError < FTPError; end

  # Raised when a resumable transfer cannot safely reuse the locally saved
  # prefix because the remote file cannot be proven to be the same version
  # (or is provably a different one).  The prefix is kept as a pending
  # candidate rather than being appended to or archived.
  class FTPResumeVersionError < FTPError
    attr_reader :receipt

    def initialize(message, receipt)
      super(message)
      @receipt = receipt
    end
  end
  # :startdoc:

  #
  # This class implements the File Transfer Protocol.  If you have used a
  # command-line FTP program, and are familiar with the commands, you will be
  # able to use this class easily.  Some extra features are included to take
  # advantage of Ruby's style and strengths.
  #
  # == Example
  #
  #   require 'net/ftp'
  #
  # === Example 1
  #
  #   ftp = Net::FTP.new('example.com')
  #   ftp.login
  #   files = ftp.chdir('pub/lang/ruby/contrib')
  #   files = ftp.list('n*')
  #   ftp.getbinaryfile('nif.rb-0.91.gz', 'nif.gz', 1024)
  #   ftp.close
  #
  # === Example 2
  #
  #   Net::FTP.open('example.com') do |ftp|
  #     ftp.login
  #     files = ftp.chdir('pub/lang/ruby/contrib')
  #     files = ftp.list('n*')
  #     ftp.getbinaryfile('nif.rb-0.91.gz', 'nif.gz', 1024)
  #   end
  #
  # == Major Methods
  #
  # The following are the methods most likely to be useful to users:
  # - FTP.open
  # - #getbinaryfile
  # - #gettextfile
  # - #putbinaryfile
  # - #puttextfile
  # - #chdir
  # - #nlst
  # - #size
  # - #rename
  # - #delete
  #
  # == Mainframe User Support
  # - #literal
  # - #quote
  #
  class FTP < Protocol
    include MonitorMixin
    if defined?(OpenSSL::SSL)
      include OpenSSL
      include SSL
    end

    # :stopdoc:
    VERSION = "0.3.9"
    FTP_PORT = 21
    CRLF = "\r\n"
    DEFAULT_BLOCKSIZE = BufferedIO::BUFSIZE
    @@default_passive = true
    # :startdoc:

    # When +true+, transfers are performed in binary mode.  Default: +true+.
    attr_reader :binary

    # When +true+, the connection is in passive mode.  Default: +true+.
    attr_accessor :passive

    # When +true+, use the IP address in PASV responses.  Otherwise, it uses
    # the same IP address for the control connection.  Default: +false+.
    attr_accessor :use_pasv_ip

    # When +true+, all traffic to and from the server is written
    # to +$stdout+.  Default: +false+.
    attr_accessor :debug_mode

    # Sets or retrieves the output stream for debugging.
    # Output stream will be used only when +debug_mode+ is set to true.
    # The default value is +$stdout+.
    attr_accessor :debug_output

    # Sets or retrieves the +resume+ status, which decides whether incomplete
    # transfers are resumed or restarted.  Default: +false+.
    attr_accessor :resume

    # Number of seconds to wait for the connection to open. Any number
    # may be used, including Floats for fractional seconds. If the FTP
    # object cannot open a connection in this many seconds, it raises a
    # Net::OpenTimeout exception. The default value is +nil+.
    attr_accessor :open_timeout

    # Number of seconds to wait for the TLS handshake. Any number
    # may be used, including Floats for fractional seconds. If the FTP
    # object cannot complete the TLS handshake in this many seconds, it
    # raises a Net::OpenTimeout exception. The default value is +nil+.
    # If +ssl_handshake_timeout+ is +nil+, +open_timeout+ is used instead.
    attr_accessor :ssl_handshake_timeout

    # Number of seconds to wait for one block to be read (via one read(2)
    # call). Any number may be used, including Floats for fractional
    # seconds. If the FTP object cannot read data in this many seconds,
    # it raises a Timeout::Error exception. The default value is 60 seconds.
    attr_reader :read_timeout

    # Setter for the read_timeout attribute.
    def read_timeout=(sec)
      @sock.read_timeout = sec
      @read_timeout = sec
    end

    # The server's welcome message.
    attr_reader :welcome

    # The server's last response code.
    attr_reader :last_response_code
    alias lastresp last_response_code

    # The server's last response.
    attr_reader :last_response

    # When +true+, connections are in passive mode per default.
    # Default: +true+.
    def self.default_passive=(value)
      @@default_passive = value
    end

    # When +true+, connections are in passive mode per default.
    # Default: +true+.
    def self.default_passive
      @@default_passive
    end

    #
    # A synonym for <tt>FTP.new</tt>, but with a mandatory host parameter.
    #
    # If a block is given, it is passed the +FTP+ object, which will be closed
    # when the block finishes, or when an exception is raised.
    #
    def FTP.open(host, *args)
      if block_given?
        ftp = new(host, *args)
        begin
          yield ftp
        ensure
          ftp.close
        end
      else
        new(host, *args)
      end
    end

    # :call-seq:
    #    Net::FTP.new(host = nil, options = {})
    #
    # Creates and returns a new +FTP+ object. If a +host+ is given, a connection
    # is made.
    #
    # +options+ is an option hash, each key of which is a symbol.
    #
    # The available options are:
    #
    # port::      Port number (default value is 21)
    # ssl::       If +options+[:ssl] is true, then an attempt will be made
    #             to use SSL (now TLS) to connect to the server.  For this
    #             to work OpenSSL [OSSL] and the Ruby OpenSSL [RSSL]
    #             extensions need to be installed.  If +options+[:ssl] is a
    #             hash, it's passed to OpenSSL::SSL::SSLContext#set_params
    #             as parameters.
    # private_data_connection::  If true, TLS is used for data connections.
    #                            Default: +true+ when +options+[:ssl] is true.
    # implicit_ftps::  If true, TLS is established on initial connection.
    #                  Default: +false+
    # username::  Username for login.  If +options+[:username] is the string
    #             "anonymous" and the +options+[:password] is +nil+,
    #             "anonymous@" is used as a password.
    # password::  Password for login.
    # account::   Account information for ACCT.
    # passive::   When +true+, the connection is in passive mode. Default:
    #             +true+.
    # open_timeout::  Number of seconds to wait for the connection to open.
    #                 See Net::FTP#open_timeout for details.  Default: +nil+.
    # read_timeout::  Number of seconds to wait for one block to be read.
    #                 See Net::FTP#read_timeout for details.  Default: +60+.
    # ssl_handshake_timeout::  Number of seconds to wait for the TLS
    #                          handshake.
    #                          See Net::FTP#ssl_handshake_timeout for
    #                          details.  Default: +nil+.
    # use_pasv_ip::  When +true+, use the IP address in PASV responses.
    #                Otherwise, it uses the same IP address for the control
    #                connection.  Default: +false+.
    # debug_mode::  When +true+, all traffic to and from the server is
    #               written to +$stdout+.  Default: +false+.
    #
    def initialize(host = nil, user_or_options = {}, passwd = nil, acct = nil)
      super()
      begin
        options = user_or_options.to_hash
      rescue NoMethodError
        # for backward compatibility
        options = {}
        options[:username] = user_or_options
        options[:password] = passwd
        options[:account] = acct
      end
      @host = nil
      if options[:ssl]
        unless defined?(OpenSSL::SSL)
          raise "SSL extension not installed"
        end
        ssl_params = options[:ssl] == true ? {} : options[:ssl]
        @ssl_context = SSLContext.new
        @ssl_context.set_params(ssl_params)
        if defined?(VerifyCallbackProc)
          @ssl_context.verify_callback = VerifyCallbackProc
        end

        # jruby-openssl does not support session caching
        unless RUBY_ENGINE == "jruby"
          @ssl_context.session_cache_mode =
            OpenSSL::SSL::SSLContext::SESSION_CACHE_CLIENT |
            OpenSSL::SSL::SSLContext::SESSION_CACHE_NO_INTERNAL_STORE
          @ssl_context.session_new_cb = proc {|sock, sess| @ssl_session = sess }
        end

        @ssl_session = nil
        if options[:private_data_connection].nil?
          @private_data_connection = true
        else
          @private_data_connection = options[:private_data_connection]
        end
        if options[:implicit_ftps].nil?
          @implicit_ftps = false
        else
          @implicit_ftps = options[:implicit_ftps]
        end
      else
        @ssl_context = nil
        if options[:private_data_connection]
          raise ArgumentError,
            "private_data_connection can be set to true only when ssl is enabled"
        end
        @private_data_connection = false
        if options[:implicit_ftps]
          raise ArgumentError,
                "implicit_ftps can be set to true only when ssl is enabled"
        end
        @implicit_ftps = false
      end
      @binary = true
      if options[:passive].nil?
        @passive = @@default_passive
      else
        @passive = options[:passive]
      end
      if options[:debug_mode].nil?
        @debug_mode = false
      else
        @debug_mode = options[:debug_mode]
      end
      @debug_output = $stdout
      @resume = false
      @bare_sock = @sock = NullSocket.new
      @logged_in = false
      @open_timeout = options[:open_timeout]
      @ssl_handshake_timeout = options[:ssl_handshake_timeout]
      @read_timeout = options[:read_timeout] || 60
      @use_pasv_ip = options[:use_pasv_ip] || false
      if host
        connect(host, options[:port] || FTP_PORT)
        if options[:username]
          login(options[:username], options[:password], options[:account])
        end
      end
    end

    # A setter to toggle transfers in binary mode.
    # +newmode+ is either +true+ or +false+
    def binary=(newmode)
      if newmode != @binary
        @binary = newmode
        send_type_command if @logged_in
      end
    end

    # Sends a command to destination host, with the current binary sendmode
    # type.
    #
    # If binary mode is +true+, then "TYPE I" (image) is sent, otherwise "TYPE
    # A" (ascii) is sent.
    def send_type_command # :nodoc:
      if @binary
        voidcmd("TYPE I")
      else
        voidcmd("TYPE A")
      end
    end
    private :send_type_command

    # Toggles transfers in binary mode and yields to a block.
    # This preserves your current binary send mode, but allows a temporary
    # transaction with binary sendmode of +newmode+.
    #
    # +newmode+ is either +true+ or +false+
    def with_binary(newmode) # :nodoc:
      oldmode = binary
      self.binary = newmode
      begin
        yield
      ensure
        self.binary = oldmode
      end
    end
    private :with_binary

    # Obsolete
    def return_code # :nodoc:
      warn("Net::FTP#return_code is obsolete and do nothing", uplevel: 1)
      return "\n"
    end

    # Obsolete
    def return_code=(s) # :nodoc:
      warn("Net::FTP#return_code= is obsolete and do nothing", uplevel: 1)
    end

    # Constructs a socket with +host+ and +port+.
    #
    # If SOCKSSocket is defined and the environment (ENV) defines
    # SOCKS_SERVER, then a SOCKSSocket is returned, else a Socket is
    # returned.
    def open_socket(host, port) # :nodoc:
      return Timeout.timeout(@open_timeout, OpenTimeout) {
        if defined? SOCKSSocket and ENV["SOCKS_SERVER"]
          @passive = true
          SOCKSSocket.open(host, port)
        else
          Socket.tcp(host, port)
        end
      }
    end
    private :open_socket

    def start_tls_session(sock)
      ssl_sock = SSLSocket.new(sock, @ssl_context)
      ssl_sock.sync_close = true
      ssl_sock.hostname = @host if ssl_sock.respond_to? :hostname=
      if @ssl_session &&
          Process.clock_gettime(Process::CLOCK_REALTIME) < @ssl_session.time.to_f + @ssl_session.timeout
        # ProFTPD returns 425 for data connections if session is not reused.
        ssl_sock.session = @ssl_session
      end
      ssl_socket_connect(ssl_sock, @ssl_handshake_timeout || @open_timeout)
      if @ssl_context.verify_mode != VERIFY_NONE
        ssl_sock.post_connection_check(@host)
      end
      return ssl_sock
    end
    private :start_tls_session

    #
    # Establishes an FTP connection to host, optionally overriding the default
    # port. If the environment variable +SOCKS_SERVER+ is set, sets up the
    # connection through a SOCKS proxy. Raises an exception (typically
    # <tt>Errno::ECONNREFUSED</tt>) if the connection cannot be established.
    #
    def connect(host, port = FTP_PORT)
      debug_print "connect: #{host}:#{port}"
      synchronize do
        @host = host
        @bare_sock = open_socket(host, port)
        if @ssl_context
          begin
            unless @implicit_ftps
              set_socket(BufferedSocket.new(@bare_sock, read_timeout: @read_timeout))
              voidcmd("AUTH TLS")
            end
            set_socket(BufferedSSLSocket.new(start_tls_session(@bare_sock), read_timeout: @read_timeout), @implicit_ftps)
            if @private_data_connection
              voidcmd("PBSZ 0")
              voidcmd("PROT P")
            end
          rescue OpenSSL::SSL::SSLError, OpenTimeout
            @sock.close
            raise
          end
        else
          set_socket(BufferedSocket.new(@bare_sock, read_timeout: @read_timeout))
        end
      end
    end

    #
    # Set the socket used to connect to the FTP server.
    #
    # May raise FTPReplyError if +get_greeting+ is false.
    def set_socket(sock, get_greeting = true)
      synchronize do
        @sock = sock
        if get_greeting
          voidresp
        end
      end
    end

    # If string +s+ includes the PASS command (password), then the contents of
    # the password are cleaned from the string using "*"
    def sanitize(s) # :nodoc:
      if s =~ /^PASS /i
        return s[0, 5] + "*" * (s.length - 5)
      else
        return s
      end
    end
    private :sanitize

    # Ensures that +line+ has a control return / line feed (CRLF) and writes
    # it to the socket.
    def putline(line) # :nodoc:
      debug_print "put: #{sanitize(line)}"
      if /[\r\n]/ =~ line
        raise ArgumentError, "A line must not contain CR or LF"
      end
      line = line + CRLF
      @sock.write(line)
    end
    private :putline

    # Reads a line from the sock.  If EOF, then it will raise EOFError
    def getline # :nodoc:
      line = @sock.readline # if get EOF, raise EOFError
      line.sub!(/(\r\n|\n|\r)\z/n, "")
      debug_print "get: #{sanitize(line)}"
      return line
    end
    private :getline

    # Receive a section of lines until the response code's match.
    def getmultiline # :nodoc:
      lines = []
      lines << getline
      code = lines.last.slice(/\A([0-9a-zA-Z]{3})-/, 1)
      if code
        delimiter = code + " "
        begin
          lines << getline
        end until lines.last.start_with?(delimiter)
      end
      return lines.join("\n") + "\n"
    end
    private :getmultiline

    # Receives a response from the destination host.
    #
    # Returns the response code or raises FTPTempError, FTPPermError, or
    # FTPProtoError
    def getresp # :nodoc:
      @last_response = getmultiline
      @last_response_code = @last_response[0, 3]
      case @last_response_code
      when /\A[123]/
        return @last_response
      when /\A4/
        raise FTPTempError, @last_response
      when /\A5/
        raise FTPPermError, @last_response
      else
        raise FTPProtoError, @last_response
      end
    end
    private :getresp

    # Receives a response.
    #
    # Raises FTPReplyError if the first position of the response code is not
    # equal 2.
    def voidresp # :nodoc:
      resp = getresp
      if !resp.start_with?("2")
        raise FTPReplyError, resp
      end
    end
    private :voidresp

    #
    # Sends a command and returns the response.
    #
    def sendcmd(cmd)
      synchronize do
        putline(cmd)
        return getresp
      end
    end

    #
    # Sends a command and expect a response beginning with '2'.
    #
    def voidcmd(cmd)
      synchronize do
        putline(cmd)
        voidresp
      end
    end

    # Constructs and send the appropriate PORT (or EPRT) command
    def sendport(host, port) # :nodoc:
      remote_address = @bare_sock.remote_address
      if remote_address.ipv4?
        cmd = "PORT " + (host.split(".") + port.divmod(256)).join(",")
      elsif remote_address.ipv6?
        cmd = sprintf("EPRT |2|%s|%d|", host, port)
      else
        raise FTPProtoError, host
      end
      voidcmd(cmd)
    end
    private :sendport

    # Constructs a TCPServer socket
    def makeport # :nodoc:
      Addrinfo.tcp(@bare_sock.local_address.ip_address, 0).listen
    end
    private :makeport

    # sends the appropriate command to enable a passive connection
    def makepasv # :nodoc:
      if @bare_sock.remote_address.ipv4?
        host, port = parse227(sendcmd("PASV"))
      else
        host, port = parse229(sendcmd("EPSV"))
      end
      return host, port
    end
    private :makepasv

    # Constructs a connection for transferring data
    def transfercmd(cmd, rest_offset = nil) # :nodoc:
      if @passive
        host, port = makepasv
        succeeded = false
        begin
          conn = open_socket(host, port)
          if @resume and rest_offset
            resp = sendcmd("REST " + rest_offset.to_s)
            if !resp.start_with?("3")
              raise FTPReplyError, resp
            end
          end
          resp = sendcmd(cmd)
          # skip 2XX for some ftp servers
          resp = getresp if resp.start_with?("2")
          if !resp.start_with?("1")
            raise FTPReplyError, resp
          end
          succeeded = true
        ensure
          conn&.close if !succeeded
        end
      else
        sock = makeport
        begin
          addr = sock.local_address
          sendport(addr.ip_address, addr.ip_port)
          if @resume and rest_offset
            resp = sendcmd("REST " + rest_offset.to_s)
            if !resp.start_with?("3")
              raise FTPReplyError, resp
            end
          end
          resp = sendcmd(cmd)
          # skip 2XX for some ftp servers
          resp = getresp if resp.start_with?("2")
          if !resp.start_with?("1")
            raise FTPReplyError, resp
          end
          conn, = sock.accept
          sock.shutdown(Socket::SHUT_WR) rescue nil
          sock.read rescue nil
        ensure
          sock.close
        end
      end
      if @private_data_connection
        return BufferedSSLSocket.new(start_tls_session(conn),
                                     read_timeout: @read_timeout)
      else
        return BufferedSocket.new(conn, read_timeout: @read_timeout)
      end
    end
    private :transfercmd

    #
    # Logs in to the remote host.  The session must have been
    # previously connected.  If +user+ is the string "anonymous" and
    # the +password+ is +nil+, "anonymous@" is used as a password.  If
    # the +acct+ parameter is not +nil+, an FTP ACCT command is sent
    # following the successful login.  Raises an exception on error
    # (typically <tt>Net::FTPPermError</tt>).
    #
    def login(user = "anonymous", passwd = nil, acct = nil)
      if user == "anonymous" and passwd == nil
        passwd = "anonymous@"
      end

      resp = ""
      synchronize do
        resp = sendcmd('USER ' + user)
        if resp.start_with?("3")
          raise FTPReplyError, resp if passwd.nil?
          resp = sendcmd('PASS ' + passwd)
        end
        if resp.start_with?("3")
          raise FTPReplyError, resp if acct.nil?
          resp = sendcmd('ACCT ' + acct)
        end
      end
      if !resp.start_with?("2")
        raise FTPReplyError, resp
      end
      @welcome = resp
      send_type_command
      @logged_in = true
    end

    #
    # Puts the connection into binary (image) mode, issues the given command,
    # and fetches the data returned, passing it to the associated block in
    # chunks of +blocksize+ characters. Note that +cmd+ is a server command
    # (such as "RETR myfile").
    #
    def retrbinary(cmd, blocksize, rest_offset = nil, receipt: nil) # :yield: data
      synchronize do
        with_binary(true) do
          begin
            conn = transfercmd(cmd, rest_offset)
            while data = conn.read(blocksize)
              yield(data)
            end
            receipt&.mark_data_end!
            conn.shutdown(Socket::SHUT_WR) rescue nil
            conn.read_timeout = 1
            conn.read rescue nil
          ensure
            conn.close if conn
          end
          voidresp
          receipt&.mark_confirmed!(@last_response_code, @last_response)
        end
      end
    end

    #
    # Puts the connection into ASCII (text) mode, issues the given command, and
    # passes the resulting data, one line at a time, to the associated block. If
    # no block is given, prints the lines. Note that +cmd+ is a server command
    # (such as "RETR myfile").
    #
    def retrlines(cmd) # :yield: line
      synchronize do
        with_binary(false) do
          begin
            conn = transfercmd(cmd)
            while line = conn.gets
              yield(line.sub(/\r?\n\z/, ""), !line.match(/\n\z/).nil?)
            end
            conn.shutdown(Socket::SHUT_WR) rescue nil
            conn.read_timeout = 1
            conn.read rescue nil
          ensure
            conn.close if conn
          end
          voidresp
        end
      end
    end

    #
    # Puts the connection into binary (image) mode, issues the given server-side
    # command (such as "STOR myfile"), and sends the contents of the file named
    # +file+ to the server. If the optional block is given, it also passes it
    # the data, in chunks of +blocksize+ characters.
    #
    def storbinary(cmd, file, blocksize, rest_offset = nil) # :yield: data
      if rest_offset
        file.seek(rest_offset, IO::SEEK_SET)
      end
      synchronize do
        with_binary(true) do
          begin
            conn = transfercmd(cmd)
            while buf = file.read(blocksize)
              conn.write(buf)
              yield(buf) if block_given?
            end
            conn.shutdown(Socket::SHUT_WR) rescue nil
            conn.read_timeout = 1
            conn.read rescue nil
          ensure
            conn.close if conn
          end
          voidresp
        end
      end
    rescue Errno::EPIPE
      # EPIPE, in this case, means that the data connection was unexpectedly
      # terminated.  Rather than just raising EPIPE to the caller, check the
      # response on the control connection.  If getresp doesn't raise a more
      # appropriate exception, re-raise the original exception.
      getresp
      raise
    end

    #
    # Puts the connection into ASCII (text) mode, issues the given server-side
    # command (such as "STOR myfile"), and sends the contents of the file
    # named +file+ to the server, one line at a time. If the optional block is
    # given, it also passes it the lines.
    #
    def storlines(cmd, file) # :yield: line
      synchronize do
        with_binary(false) do
          begin
            conn = transfercmd(cmd)
            while buf = file.gets
              if buf[-2, 2] != CRLF
                buf = buf.chomp + CRLF
              end
              conn.write(buf)
              yield(buf) if block_given?
            end
            conn.shutdown(Socket::SHUT_WR) rescue nil
            conn.read_timeout = 1
            conn.read rescue nil
          ensure
            conn.close if conn
          end
          getresp # The response might be important when connected to a mainframe
        end
      end
    rescue Errno::EPIPE
      # EPIPE, in this case, means that the data connection was unexpectedly
      # terminated.  Rather than just raising EPIPE to the caller, check the
      # response on the control connection.  If getresp doesn't raise a more
      # appropriate exception, re-raise the original exception.
      getresp
      raise
    end

    #
    # Retrieves +remotefile+ in binary mode, storing the result in +localfile+.
    # If +localfile+ is nil, returns retrieved data.
    # If a block is supplied, it is passed the retrieved data in +blocksize+
    # chunks.
    #
    # When +receipt+ is a Net::FTP::TransferReceipt, the transfer is performed
    # as a safe, resumable, staged download.  Data is written to a staging
    # file (localfile with a ".part" suffix) and only moved to +localfile+
    # once the control connection confirms the end of the transfer.  The
    # receipt records which attempt produced the saved prefix, the bytes
    # received afterwards and the exact step at which the file becomes safe
    # to archive.  A prefix that cannot be proven to match the current
    # remote version is retained as a pending candidate instead of being
    # reused.
    #
    def getbinaryfile(remotefile, localfile = File.basename(remotefile),
                      blocksize = DEFAULT_BLOCKSIZE, receipt: nil, &block) # :yield: data
      return getbinaryfile_with_receipt(remotefile, localfile, blocksize,
                                        receipt, &block) if receipt

      f = nil
      result = nil
      if localfile
        if @resume
          rest_offset = File.size?(localfile)
          f = File.open(localfile, "a")
        else
          rest_offset = nil
          f = File.open(localfile, "w")
        end
      elsif !block_given?
        result = String.new
      end
      begin
        f&.binmode
        retrbinary("RETR #{remotefile}", blocksize, rest_offset) do |data|
          f&.write(data)
          block&.(data)
          result&.concat(data)
        end
        return result
      ensure
        f&.close
      end
    end

    # Implements the receipt-aware, resumable staged download.  Kept separate
    # from #getbinaryfile so the legacy path is unchanged.
    def getbinaryfile_with_receipt(remotefile, localfile, blocksize,
                                   receipt, &block)
      facts = collect_version_facts(remotefile)
      rest_offset, version_status =
        prepare_resumable_prefix(localfile, receipt, facts)
      if version_status == :mismatch || version_status == :indeterminate
        receipt.record_verification!(facts, version_status)
        receipt.mark_candidate!
        receipt.persist!
        raise FTPResumeVersionError.new(
          "cannot resume #{remotefile}: saved prefix cannot be verified " \
          "against the current remote version (#{version_status}); " \
          "retained as pending candidate at #{receipt.candidate_path}",
          receipt
        )
      end

      state = rest_offset.positive? ? :resuming : :receiving
      receipt.mark_attempt!(state: state,
                            rest_offset: rest_offset,
                            version_facts: facts,
                            version_status: version_status)
      f = File.open(receipt.staging_path, "a")
      f.binmode
      result = block_given? ? nil : String.new
      previous_resume = @resume
      self.resume = true
      failed = false
      begin
        retrbinary("RETR #{remotefile}", blocksize, rest_offset,
                   receipt: receipt) do |data|
          f.write(data)
          receipt.add_received!(data.bytesize)
          block&.(data)
          result&.concat(data)
        end
      rescue Exception
        failed = true
        raise
      ensure
        f.close
        self.resume = previous_resume
        if failed
          # Record the on-disk prefix only after the handle is closed and
          # flushed, so its length and digest reflect what was actually saved.
          record_saved_prefix(receipt)
          receipt.persist!
        end
      end
      if rest_offset.zero?
        # A fresh reception: the whole file is this attempt's saved prefix.
        record_saved_prefix(receipt)
      end
      # On a successful resume, leave prefix_* describing the verified prefix
      # produced by the earlier attempt rather than overwriting it with the
      # now-complete file.
      archive_confirmed_file(receipt)
      return result
    end
    private :getbinaryfile_with_receipt

    # Gathers the facts available to tell revisions of +remotefile+ apart.
    def collect_version_facts(remotefile)
      file_size =
        begin
          size(remotefile)
        rescue FTPError
          nil
        end
      modify_time =
        begin
          mtime(remotefile)
        rescue FTPError
          nil
        end
      unique =
        begin
          mlst(remotefile).unique
        rescue FTPError
          nil
        end
      return VersionFacts.new(size: file_size,
                               mtime: modify_time,
                               unique: unique)
    end
    private :collect_version_facts

    # Decides whether a previously saved prefix can be reused.  Returns the
    # REST offset to use and the version comparison result.  An unverifiable
    # prefix is moved aside as a pending candidate and forces a restart at 0.
    def prepare_resumable_prefix(localfile, receipt, facts)
      unless File.file?(receipt.sidecar_path) &&
               File.file?(receipt.staging_path)
        return [0, :fresh]
      end

      saved = TransferReceipt.load(receipt.sidecar_path)
      saved.localfile = localfile
      inherit_saved_receipt(receipt, saved)

      status = saved.version_facts.compare(facts)
      if status == :verified
        actual_digest = digest_file(receipt.staging_path)
        if actual_digest != saved.prefix_digest
          retain_candidate(receipt, "local prefix digest mismatch")
          return [0, :indeterminate]
        end
        return [saved.prefix_bytes, :verified]
      else
        reason = status == :mismatch ? "remote version changed" :
                                        "remote version cannot be distinguished"
        retain_candidate(receipt, reason)
        return [0, status]
      end
    end
    private :prepare_resumable_prefix

    # Copies the persisted prefix bookkeeping into the in-memory receipt so a
    # later attempt still knows which earlier attempt produced the prefix.
    def inherit_saved_receipt(receipt, saved)
      receipt.instance_variable_set(:@attempt_count, saved.attempt_count)
      receipt.instance_variable_set(:@prefix_attempt, saved.prefix_attempt)
      receipt.instance_variable_set(:@prefix_bytes, saved.prefix_bytes)
      receipt.instance_variable_set(:@prefix_digest, saved.prefix_digest)
      receipt.instance_variable_set(:@last_response_code,
                                    saved.last_response_code)
      receipt.instance_variable_set(:@last_response, saved.last_response)
    end
    private :inherit_saved_receipt

    # Moves an unverifiable staging file out of the way and records why.
    def retain_candidate(receipt, reason)
      File.rename(receipt.staging_path, receipt.candidate_path)
      receipt.mark_candidate!
      receipt.instance_variable_set(:@candidate_reason, reason)
      receipt.persist!
    end
    private :retain_candidate

    # Attributes the currently saved staging bytes to the latest attempt.
    def record_saved_prefix(receipt)
      bytes = File.size?(receipt.staging_path) || 0
      receipt.record_prefix!(bytes, digest_file(receipt.staging_path))
    end
    private :record_saved_prefix

    # Promotes a confirmed staging file to the final destination.
    def archive_confirmed_file(receipt)
      File.rename(receipt.staging_path, receipt.localfile)
      receipt.mark_archived!
      File.delete(receipt.sidecar_path) if File.file?(receipt.sidecar_path)
    end
    private :archive_confirmed_file

    def digest_file(path)
      File.file?(path) ? Digest::SHA256.file(path).hexdigest : nil
    end
    private :digest_file

    #
    # Retrieves +remotefile+ in ASCII (text) mode, storing the result in
    # +localfile+.
    # If +localfile+ is nil, returns retrieved data.
    # If a block is supplied, it is passed the retrieved data one
    # line at a time.
    #
    def gettextfile(remotefile, localfile = File.basename(remotefile),
                    &block) # :yield: line
      f = nil
      result = nil
      if localfile
        f = File.open(localfile, "w")
      elsif !block_given?
        result = String.new
      end
      begin
        retrlines("RETR #{remotefile}") do |line, newline|
          l = newline ? line + "\n" : line
          f&.print(l)
          block&.(line, newline)
          result&.concat(l)
        end
        return result
      ensure
        f&.close
      end
    end

    #
    # Retrieves +remotefile+ in whatever mode the session is set (text or
    # binary).  See #gettextfile and #getbinaryfile.
    #
    def get(remotefile, localfile = File.basename(remotefile),
            blocksize = DEFAULT_BLOCKSIZE, receipt: nil, &block) # :yield: data
      if @binary
        getbinaryfile(remotefile, localfile, blocksize,
                      receipt: receipt, &block)
      else
        gettextfile(remotefile, localfile, &block)
      end
    end

    #
    # Transfers +localfile+ to the server in binary mode, storing the result in
    # +remotefile+. If a block is supplied, calls it, passing in the transmitted
    # data in +blocksize+ chunks.
    #
    def putbinaryfile(localfile, remotefile = File.basename(localfile),
                      blocksize = DEFAULT_BLOCKSIZE, &block) # :yield: data
      if @resume
        begin
          rest_offset = size(remotefile)
        rescue Net::FTPPermError
          rest_offset = nil
        end
      else
        rest_offset = nil
      end
      f = File.open(localfile)
      begin
        f.binmode
        if rest_offset
          storbinary("APPE #{remotefile}", f, blocksize, rest_offset, &block)
        else
          storbinary("STOR #{remotefile}", f, blocksize, rest_offset, &block)
        end
      ensure
        f.close
      end
    end

    #
    # Transfers +localfile+ to the server in ASCII (text) mode, storing the result
    # in +remotefile+. If callback or an associated block is supplied, calls it,
    # passing in the transmitted data one line at a time.
    #
    # Returns the response which will contain a job number if the user was communicating with a mainframe in ASCII mode
    # after issuing 'quote site filetype=jes'
    #
    def puttextfile(localfile, remotefile = File.basename(localfile), &block) # :yield: line
      f = File.open(localfile)
      response = ''
      begin
        response = storlines("STOR #{remotefile}", f, &block)
      ensure
        f.close
      end
      response
    end

    #
    # Transfers +localfile+ to the server in whatever mode the session is set
    # (text or binary).  See #puttextfile and #putbinaryfile.
    #
    def put(localfile, remotefile = File.basename(localfile),
            blocksize = DEFAULT_BLOCKSIZE, &block)
      if @binary
        putbinaryfile(localfile, remotefile, blocksize, &block)
      else
        puttextfile(localfile, remotefile, &block)
      end
    end

    #
    # Sends the ACCT command.
    #
    # This is a less common FTP command, to send account
    # information if the destination host requires it.
    #
    def acct(account)
      cmd = "ACCT " + account
      voidcmd(cmd)
    end

    #
    # Returns an array of filenames in the remote directory.
    #
    def nlst(dir = nil)
      cmd = "NLST"
      if dir
        cmd = "#{cmd} #{dir}"
      end
      files = []
      retrlines(cmd) do |line|
        files.push(line)
      end
      return files
    end

    #
    # Returns an array of file information in the directory (the output is like
    # `ls -l`).  If a block is given, it iterates through the listing.
    #
    def list(*args, &block) # :yield: line
      cmd = "LIST"
      args.each do |arg|
        cmd = "#{cmd} #{arg}"
      end
      lines = []
      retrlines(cmd) do |line|
        lines << line
      end
      if block
        lines.each(&block)
      end
      return lines
    end
    alias ls list
    alias dir list

    #
    # MLSxEntry represents an entry in responses of MLST/MLSD.
    # Each entry has the facts (e.g., size, last modification time, etc.)
    # and the pathname.
    #
    class MLSxEntry
      attr_reader :facts, :pathname

      def initialize(facts, pathname)
        @facts = facts
        @pathname = pathname
      end

      standard_facts = %w(size modify create type unique perm
                          lang media-type charset)
      standard_facts.each do |factname|
        define_method factname.gsub(/-/, "_") do
          facts[factname]
        end
      end

      #
      # Returns +true+ if the entry is a file (i.e., the value of the type
      # fact is file).
      #
      def file?
        return facts["type"] == "file"
      end

      #
      # Returns +true+ if the entry is a directory (i.e., the value of the
      # type fact is dir, cdir, or pdir).
      #
      def directory?
        if /\A[cp]?dir\z/.match(facts["type"])
          return true
        else
          return false
        end
      end

      #
      # Returns +true+ if the APPE command may be applied to the file.
      #
      def appendable?
        return facts["perm"].include?(?a)
      end

      #
      # Returns +true+ if files may be created in the directory by STOU,
      # STOR, APPE, and RNTO.
      #
      def creatable?
        return facts["perm"].include?(?c)
      end

      #
      # Returns +true+ if the file or directory may be deleted by DELE/RMD.
      #
      def deletable?
        return facts["perm"].include?(?d)
      end

      #
      # Returns +true+ if the directory may be entered by CWD/CDUP.
      #
      def enterable?
        return facts["perm"].include?(?e)
      end

      #
      # Returns +true+ if the file or directory may be renamed by RNFR.
      #
      def renamable?
        return facts["perm"].include?(?f)
      end

      #
      # Returns +true+ if the listing commands, LIST, NLST, and MLSD are
      # applied to the directory.
      #
      def listable?
        return facts["perm"].include?(?l)
      end

      #
      # Returns +true+ if the MKD command may be used to create a new
      # directory within the directory.
      #
      def directory_makable?
        return facts["perm"].include?(?m)
      end

      #
      # Returns +true+ if the objects in the directory may be deleted, or
      # the directory may be purged.
      #
      def purgeable?
        return facts["perm"].include?(?p)
      end

      #
      # Returns +true+ if the RETR command may be applied to the file.
      #
      def readable?
        return facts["perm"].include?(?r)
      end

      #
      # Returns +true+ if the STOR command may be applied to the file.
      #
      def writable?
        return facts["perm"].include?(?w)
      end
    end

    #
    # VersionFacts captures the facts a server exposes that may distinguish
    # one revision of a pathname from another.  The file size alone is never
    # enough: servers commonly replace a file with a same-size new revision.
    #
    # +mtime+ (from MDTM) and +unique+ (from the MLST "unique" fact) are the
    # usable discriminators.  When a server provides neither, two files with
    # the same name and size cannot be told apart.
    #
    class VersionFacts
      attr_reader :size, :mtime, :unique

      def initialize(size: nil, mtime: nil, unique: nil)
        @size = size
        # Normalize to a canonical MDTM-style UTC string.  A live MDTM is
        # parsed by Net::FTP#mtime into a Time, but a receipt reloaded from
        # JSON carries a String; using the same YYYYMMDDHHMMSS form keeps a
        # freshly collected fact equal to a persisted one.
        @mtime =
          case mtime
          when nil then nil
          when Time then mtime.utc.strftime("%Y%m%d%H%M%S")
          else mtime.to_s
          end
        @unique = unique
      end

      # Returns true when at least one fact beyond the size is available to
      # distinguish revisions.
      def distinguishable?
        !(@mtime.nil? && @unique.nil?)
      end

      # Compares two sets of facts.
      #
      # Only discriminators present on *both* sides can be checked.
      #
      # Returns:
      # +:verified+::      at least one shared discriminator exists and every
      #                    shared one matches.
      # +:mismatch+::      a shared discriminator differs.
      # +:indeterminate+:: the two sides share no discriminator, so the
      #                    versions cannot be proven equal (e.g. neither side
      #                    can distinguish revisions, or they expose different
      #                    fact types).
      def compare(other)
        comparisons = []
        unless @mtime.nil? || other.mtime.nil?
          comparisons << (@mtime == other.mtime)
        end
        unless @unique.nil? || other.unique.nil?
          comparisons << (@unique == other.unique)
        end
        return :indeterminate if comparisons.empty?
        comparisons.all? ? :verified : :mismatch
      end

      def to_h
        {
          "size" => @size,
          "mtime" => @mtime,
          "unique" => @unique,
        }
      end

      def self.from_h(hash)
        new(
          size: hash["size"],
          mtime: hash["mtime"],
          unique: hash["unique"],
        )
      end
    end

    #
    # TransferReceipt is an optional record of a resumable binary download.
    #
    # It answers three questions about a transfer:
    # 1. which reception attempt produced the locally saved prefix
    #    (#prefix_attempt, #prefix_digest);
    # 2. which byte ranges have been received since then
    #    (#rest_offset, #received_bytes, #received_range);
    # 3. at which step the transfer became safe to archive (#state):
    #    the data finishing is distinct from the control connection
    #    confirming the end of the transfer.
    #
    # The lifecycle states are:
    # +:candidate+::      a saved prefix exists but has not been verified to
    #                     belong to the current remote version.
    # +:resuming+::       the prefix was verified and a reception is appending
    #                     to it.
    # +:receiving+::      a fresh reception is writing the file.
    # +:interrupted+::    the data connection ended before all bytes arrived.
    # +:data_complete+::  every expected byte was received, but the control
    #                     connection has not yet confirmed the end.
    # +:confirmed+::      the control connection reported a successful end
    #                     (2xx), so the bytes are sound.
    # +:archived+::       the confirmed file was moved into its final place.
    #
    class TransferReceipt
      STAGE_PATH_SUFFIX = ".part"
      SIDECAR_SUFFIX = ".ftp-receipt"
      CANDIDATE_SUFFIX = ".candidate"

      attr_accessor :localfile, :remotefile
      attr_reader :state, :attempt_count, :prefix_attempt, :prefix_bytes,
                  :prefix_digest, :rest_offset, :received_bytes,
                  :expected_size, :version_status, :version_facts,
                  :staging_path, :sidecar_path, :candidate_path,
                  :candidate_reason, :last_response_code, :last_response

      def initialize(localfile:, remotefile:, expected_size: nil)
        @localfile = localfile
        @remotefile = remotefile
        @expected_size = expected_size
        @staging_path = localfile.to_s + STAGE_PATH_SUFFIX
        @sidecar_path = localfile.to_s + SIDECAR_SUFFIX
        @candidate_path = localfile.to_s + CANDIDATE_SUFFIX
        @candidate_reason = nil
        @state = :candidate
        @attempt_count = 0
        @prefix_attempt = nil
        @prefix_bytes = 0
        @prefix_digest = nil
        @rest_offset = 0
        @received_bytes = 0
        @version_status = nil
        @version_facts = nil
        @last_response_code = nil
        @last_response = nil
      end

      # Loads a receipt previously persisted next to a staged file.
      def self.load(path)
        hash = JSON.parse(File.binread(path))
        receipt = new(
          localfile: hash["localfile"],
          remotefile: hash["remotefile"],
          expected_size: hash["expected_size"],
        )
        receipt.instance_variable_set(:@state, hash["state"].to_sym)
        receipt.instance_variable_set(:@attempt_count, hash["attempt_count"])
        receipt.instance_variable_set(:@prefix_attempt, hash["prefix_attempt"])
        receipt.instance_variable_set(:@prefix_bytes, hash["prefix_bytes"])
        receipt.instance_variable_set(:@prefix_digest, hash["prefix_digest"])
        receipt.instance_variable_set(:@rest_offset, hash["rest_offset"])
        receipt.instance_variable_set(:@received_bytes, hash["received_bytes"])
        receipt.instance_variable_set(:@version_status,
                                      hash["version_status"]&.to_sym)
        receipt.instance_variable_set(:@version_facts,
                                      VersionFacts.from_h(hash["version_facts"]))
        receipt.instance_variable_set(:@last_response_code,
                                      hash["last_response_code"])
        receipt.instance_variable_set(:@last_response, hash["last_response"])
        receipt.instance_variable_set(:@candidate_reason,
                                      hash["candidate_reason"])
        return receipt
      end

      # Persists the receipt so a later process can resume from the prefix.
      def persist!(path = @sidecar_path)
        File.binwrite(path, JSON.generate(to_h))
        return self
      end

      def to_h
        {
          "localfile" => @localfile,
          "remotefile" => @remotefile,
          "expected_size" => @expected_size,
          "state" => @state.to_s,
          "attempt_count" => @attempt_count,
          "prefix_attempt" => @prefix_attempt,
          "prefix_bytes" => @prefix_bytes,
          "prefix_digest" => @prefix_digest,
          "rest_offset" => @rest_offset,
          "received_bytes" => @received_bytes,
          "version_status" => @version_status&.to_s,
          "version_facts" => (@version_facts || VersionFacts.new).to_h,
          "last_response_code" => @last_response_code,
          "last_response" => @last_response,
          "candidate_reason" => @candidate_reason,
        }
      end

      # Records the start of a new reception attempt and returns its number.
      def mark_attempt!(state:, rest_offset:, version_facts:, version_status:)
        @attempt_count += 1
        @state = state
        @rest_offset = rest_offset
        @received_bytes = 0
        @version_facts = version_facts
        @version_status = version_status
        @expected_size = version_facts.size if version_facts
        return @attempt_count
      end

      # Records that the current attempt's prefix of +bytes+ was saved, with
      # the digest of those bytes.  The prefix is attributed to this attempt.
      def record_prefix!(bytes, digest)
        @prefix_attempt = @attempt_count
        @prefix_bytes = bytes
        @prefix_digest = digest
      end

      # Accumulates bytes handed to the per-chunk callback during the current
      # reception attempt.
      def add_received!(bytes)
        @received_bytes += bytes
      end

      # The absolute byte range received during the current attempt.
      def received_range
        (@rest_offset)...(@rest_offset + @received_bytes)
      end

      # Called when the data connection reaches EOF.  When every expected
      # byte is present the data is complete but still awaits the control
      # confirmation; otherwise the transfer was interrupted.
      def mark_data_end!
        @state =
          if !@expected_size.nil? &&
               @rest_offset + @received_bytes >= @expected_size
            :data_complete
          else
            :interrupted
          end
        return @state
      end

      # Called when the control connection confirms the transfer end (2xx).
      def mark_confirmed!(response_code, response)
        @last_response_code = response_code
        @last_response = response
        @state = :confirmed
      end

      # Called when a confirmed staged file is moved to its final destination.
      def mark_archived!
        @state = :archived
      end

      # A prefix retained without proof that it matches the remote version.
      def mark_candidate!
        @state = :candidate
      end

      # Records the outcome of comparing a saved prefix against the current
      # remote version, including the freshly collected remote facts.
      def record_verification!(version_facts, version_status)
        @version_facts = version_facts
        @version_status = version_status
        @expected_size = version_facts.size if version_facts
      end

      def archivable?
        @state == :confirmed || @state == :archived
      end

      def confirmed?
        @state == :confirmed || @state == :archived
      end

      def data_complete?
        @state == :data_complete
      end

      def interrupted?
        @state == :interrupted
      end

      def candidate?
        @state == :candidate
      end
    end

    CASE_DEPENDENT_PARSER = ->(value) { value }
    CASE_INDEPENDENT_PARSER = ->(value) { value.downcase }
    DECIMAL_PARSER = ->(value) { value.to_i }
    OCTAL_PARSER = ->(value) { value.to_i(8) }
    TIME_PARSER = ->(value, local = false) {
      unless /\A(?<year>\d{4})(?<month>\d{2})(?<day>\d{2})
            (?<hour>\d{2})(?<min>\d{2})(?<sec>\d{2})
            (?:\.(?<fractions>\d{1,17}))?/x =~ value
        value = value[0, 97] + "..." if value.size > 100
        raise FTPProtoError, "invalid time-val: #{value}"
      end
      usec = ".#{fractions}".to_r * 1_000_000 if fractions
      Time.public_send(local ? :local : :utc, year, month, day, hour, min, sec, usec)
    }
    FACT_PARSERS = Hash.new(CASE_DEPENDENT_PARSER)
    FACT_PARSERS["size"] = DECIMAL_PARSER
    FACT_PARSERS["modify"] = TIME_PARSER
    FACT_PARSERS["create"] = TIME_PARSER
    FACT_PARSERS["type"] = CASE_INDEPENDENT_PARSER
    FACT_PARSERS["unique"] = CASE_DEPENDENT_PARSER
    FACT_PARSERS["perm"] = CASE_INDEPENDENT_PARSER
    FACT_PARSERS["lang"] = CASE_INDEPENDENT_PARSER
    FACT_PARSERS["media-type"] = CASE_INDEPENDENT_PARSER
    FACT_PARSERS["charset"] = CASE_INDEPENDENT_PARSER
    FACT_PARSERS["unix.mode"] = OCTAL_PARSER
    FACT_PARSERS["unix.owner"] = DECIMAL_PARSER
    FACT_PARSERS["unix.group"] = DECIMAL_PARSER
    FACT_PARSERS["unix.ctime"] = TIME_PARSER
    FACT_PARSERS["unix.atime"] = TIME_PARSER

    def parse_mlsx_entry(entry)
      facts, pathname = entry.chomp.split(/ /, 2)
      unless pathname
        raise FTPProtoError, entry
      end
      return MLSxEntry.new(
        facts.scan(/(.*?)=(.*?);/).each_with_object({}) {
          |(factname, value), h|
          name = factname.downcase
          h[name] = FACT_PARSERS[name].(value)
        },
        pathname)
    end
    private :parse_mlsx_entry

    #
    # Returns data (e.g., size, last modification time, entry type, etc.)
    # about the file or directory specified by +pathname+.
    # If +pathname+ is omitted, the current directory is assumed.
    #
    def mlst(pathname = nil)
      cmd = pathname ? "MLST #{pathname}" : "MLST"
      resp = sendcmd(cmd)
      if !resp.start_with?("250")
        raise FTPReplyError, resp
      end
      line = resp.lines[1]
      unless line
        raise FTPProtoError, resp
      end
      entry = line.sub(/\A(250-| *)/, "")
      return parse_mlsx_entry(entry)
    end

    #
    # Returns an array of the entries of the directory specified by
    # +pathname+.
    # Each entry has the facts (e.g., size, last modification time, etc.)
    # and the pathname.
    # If a block is given, it iterates through the listing.
    # If +pathname+ is omitted, the current directory is assumed.
    #
    def mlsd(pathname = nil, &block) # :yield: entry
      cmd = pathname ? "MLSD #{pathname}" : "MLSD"
      entries = []
      retrlines(cmd) do |line|
        entries << parse_mlsx_entry(line)
      end
      if block
        entries.each(&block)
      end
      return entries
    end

    #
    # Renames a file on the server.
    #
    def rename(fromname, toname)
      resp = sendcmd("RNFR #{fromname}")
      if !resp.start_with?("3")
        raise FTPReplyError, resp
      end
      voidcmd("RNTO #{toname}")
    end

    #
    # Deletes a file on the server.
    #
    def delete(filename)
      resp = sendcmd("DELE #{filename}")
      if resp.start_with?("250")
        return
      elsif resp.start_with?("5")
        raise FTPPermError, resp
      else
        raise FTPReplyError, resp
      end
    end

    #
    # Changes the (remote) directory.
    #
    def chdir(dirname)
      if dirname == ".."
        begin
          voidcmd("CDUP")
          return
        rescue FTPPermError => e
          if e.message[0, 3] != "500"
            raise e
          end
        end
      end
      cmd = "CWD #{dirname}"
      voidcmd(cmd)
    end

    def get_body(resp) # :nodoc:
      resp.slice(/\A[0-9a-zA-Z]{3} (.*)$/, 1)
    end
    private :get_body

    #
    # Returns the size of the given (remote) filename.
    #
    def size(filename)
      with_binary(true) do
        resp = sendcmd("SIZE #{filename}")
        if !resp.start_with?("213")
          raise FTPReplyError, resp
        end
        return get_body(resp).to_i
      end
    end

    #
    # Returns the last modification time of the (remote) file.  If +local+ is
    # +true+, it is returned as a local time, otherwise it's a UTC time.
    #
    def mtime(filename, local = false)
      return TIME_PARSER.(mdtm(filename), local)
    end

    #
    # Creates a remote directory.
    #
    def mkdir(dirname)
      resp = sendcmd("MKD #{dirname}")
      return parse257(resp)
    end

    #
    # The "quote" subcommand sends arguments verbatim to the remote ftp server.
    # The "literal" subcommand is an alias for "quote".
    # @param arguments Array[String] to be sent verbatim to the remote ftp server
    #
    def quote(arguments)
      sendcmd(arguments)
    end
    alias literal quote

    #
    # Removes a remote directory.
    #
    def rmdir(dirname)
      voidcmd("RMD #{dirname}")
    end

    #
    # Returns the current remote directory.
    #
    def pwd
      resp = sendcmd("PWD")
      return parse257(resp)
    end
    alias getdir pwd

    #
    # Returns system information.
    #
    def system
      resp = sendcmd("SYST")
      if !resp.start_with?("215")
        raise FTPReplyError, resp
      end
      return get_body(resp)
    end

    #
    # Aborts the previous command (ABOR command).
    #
    def abort
      line = "ABOR" + CRLF
      debug_print "put: ABOR"
      @sock.send(line, Socket::MSG_OOB)
      resp = getmultiline
      unless ["426", "226", "225"].include?(resp[0, 3])
        raise FTPProtoError, resp
      end
      return resp
    end

    #
    # Returns the status (STAT command).
    #
    # pathname:: when stat is invoked with pathname as a parameter it acts like
    #            list but a lot faster and over the same tcp session.
    #
    def status(pathname = nil)
      line = pathname ? "STAT #{pathname}" : "STAT"
      if /[\r\n]/ =~ line
        raise ArgumentError, "A line must not contain CR or LF"
      end
      debug_print "put: #{line}"
      @sock.send(line + CRLF, Socket::MSG_OOB)
      return getresp
    end

    #
    # Returns the raw last modification time of the (remote) file in the format
    # "YYYYMMDDhhmmss" (MDTM command).
    #
    # Use +mtime+ if you want a parsed Time instance.
    #
    def mdtm(filename)
      resp = sendcmd("MDTM #{filename}")
      if resp.start_with?("213")
        return get_body(resp)
      end
    end

    #
    # Issues the HELP command.
    #
    def help(arg = nil)
      cmd = "HELP"
      if arg
        cmd = cmd + " " + arg
      end
      sendcmd(cmd)
    end

    #
    # Exits the FTP session.
    #
    def quit
      voidcmd("QUIT")
    end

    #
    # Issues a NOOP command.
    #
    # Does nothing except return a response.
    #
    def noop
      voidcmd("NOOP")
    end

    #
    # Issues a SITE command.
    #
    def site(arg)
      cmd = "SITE " + arg
      voidcmd(cmd)
    end

    #
    # Issues a FEAT command
    #
    # Returns an array of supported optional features
    #
    def features
      resp = sendcmd("FEAT")
      if !resp.start_with?("211")
        raise FTPReplyError, resp
      end

      feats = []
      resp.each_line do |line|
        next if !line.start_with?(' ') # skip status lines

        feats << line.strip
      end

      return feats
    end

    #
    # Issues an OPTS command
    # - name Should be the name of the option to set
    # - params is any optional parameters to supply with the option
    #
    # example: option('UTF8', 'ON') => 'OPTS UTF8 ON'
    #
    def option(name, params = nil)
      cmd = "OPTS #{name}"
      cmd += " #{params}" if params

      voidcmd(cmd)
    end

    #
    # Closes the connection.  Further operations are impossible until you open
    # a new connection with #connect.
    #
    def close
      if @sock and not @sock.closed?
        begin
          @sock.shutdown(Socket::SHUT_WR) rescue nil
          orig, self.read_timeout = self.read_timeout, 3
          @sock.read rescue nil
        ensure
          @sock.close
          self.read_timeout = orig
        end
      end
    end

    #
    # Returns +true+ if and only if the connection is closed.
    #
    def closed?
      @sock == nil or @sock.closed?
    end

    # handler for response code 227
    # (Entering Passive Mode (h1,h2,h3,h4,p1,p2))
    #
    # Returns host and port.
    def parse227(resp) # :nodoc:
      if !resp.start_with?("227")
        raise FTPReplyError, resp
      end
      if m = /(?<host>\d+(?:,\d+){3}),(?<port>\d+,\d+)/.match(resp)
        if @use_pasv_ip
          host = parse_pasv_ipv4_host(m["host"])
        else
          host = @bare_sock.remote_address.ip_address
        end
        return host, parse_pasv_port(m["port"])
      else
        raise FTPProtoError, resp
      end
    end
    private :parse227

    def parse_pasv_ipv4_host(s)
      return s.tr(",", ".")
    end
    private :parse_pasv_ipv4_host

    def parse_pasv_ipv6_host(s)
      return s.split(/,/).map { |i|
        "%02x" % i.to_i
      }.each_slice(2).map(&:join).join(":")
    end
    private :parse_pasv_ipv6_host

    def parse_pasv_port(s)
      return s.split(/,/).map(&:to_i).inject { |x, y|
        (x << 8) + y
      }
    end
    private :parse_pasv_port

    # handler for response code 229
    # (Extended Passive Mode Entered)
    #
    # Returns host and port.
    def parse229(resp) # :nodoc:
      if !resp.start_with?("229")
        raise FTPReplyError, resp
      end
      if m = /\((?<d>[!-~])\k<d>\k<d>(?<port>\d+)\k<d>\)/.match(resp)
        return @bare_sock.remote_address.ip_address, m["port"].to_i
      else
        raise FTPProtoError, resp
      end
    end
    private :parse229

    # handler for response code 257
    # ("PATHNAME" created)
    #
    # Returns host and port.
    def parse257(resp) # :nodoc:
      if !resp.start_with?("257")
        raise FTPReplyError, resp
      end
      return resp.slice(/"(([^"]|"")*)"/, 1).to_s.gsub(/""/, '"')
    end
    private :parse257

    #
    # Writes debug message to the debug output stream
    #
    def debug_print(msg)
      @debug_output << msg + "\n" if @debug_mode && @debug_output
    end

    # :stopdoc:
    class NullSocket
      def read_timeout=(sec)
      end

      def closed?
        true
      end

      def close
      end

      def method_missing(mid, *args)
        raise FTPConnectionError, "not connected"
      end
    end

    class BufferedSocket < BufferedIO
      [:local_address, :remote_address, :addr, :peeraddr, :send, :shutdown].each do |method|
        define_method(method) { |*args|
          @io.__send__(method, *args)
        }
      end

      def read(len = nil)
        if len
          s = super(len, String.new, true)
          return s.empty? ? nil : s
        else
          result = String.new
          while s = super(DEFAULT_BLOCKSIZE, String.new, true)
            break if s.empty?
            result << s
          end
          return result
        end
      end

      def gets
        line = readuntil("\n", true)
        return line.empty? ? nil : line
      end

      def readline
        line = gets
        if line.nil?
          raise EOFError, "end of file reached"
        end
        return line
      end
    end

    if defined?(OpenSSL::SSL::SSLSocket)
      class BufferedSSLSocket < BufferedSocket

        def shutdown(*args)
          # Invokes SSL_shutdown, which sends a close_notify message to the peer.
          @io.__send__(:stop)
        end

        def send(mesg, flags, dest = nil)
          # Ignore flags and dest.
          @io.write(mesg)
        end

      end
    end
    # :startdoc:
  end
end


# Documentation comments:
#  - sourced from pickaxe and nutshell, with improvements (hopefully)
