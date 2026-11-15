require 'net/sftp/constants'
require 'net/sftp/errors'
require 'net/sftp/response'

module Net; module SFTP

  # Encapsulates a single active SFTP request. This is instantiated
  # automatically by the Net::SFTP::Session class when an operation is
  # executed.
  #
  #   request = sftp.open("/path/to/file")
  #   puts request.pending? #-> true
  #   request.wait
  #   puts request.pending? #-> false
  #   result = request.response
  class Request
    include Constants::PacketTypes
    include Constants::StatusCodes

    # The response packet types that may carry a successful result for each
    # request type. Every request may also receive an FXP_STATUS packet, but
    # only the request types in ::EOF_REQUESTS may report FX_EOF and an
    # FX_OK status never satisfies a request that expects a payload packet.
    # The same request id on a packet of another type is therefore a protocol
    # violation, not a success.
    RESPONSE_TYPES = {
      :open      => [FXP_HANDLE].freeze,
      :opendir   => [FXP_HANDLE].freeze,
      :read      => [FXP_DATA].freeze,
      :readdir   => [FXP_NAME].freeze,
      :stat      => [FXP_ATTRS].freeze,
      :lstat     => [FXP_ATTRS].freeze,
      :fstat     => [FXP_ATTRS].freeze,
      :realpath  => [FXP_NAME].freeze,
      :readlink  => [FXP_NAME].freeze,
      :close     => [].freeze,
      :write     => [].freeze,
      :setstat   => [].freeze,
      :fsetstat  => [].freeze,
      :remove    => [].freeze,
      :mkdir     => [].freeze,
      :rmdir     => [].freeze,
      :rename    => [].freeze,
      :symlink   => [].freeze,
      :link      => [].freeze,
      :block     => [].freeze,
      :unblock   => [].freeze
    }.each_value(&:freeze).freeze

    # Request types for which FX_EOF is a normal, protocol-defined terminal
    # status rather than an error.
    EOF_REQUESTS = [:read, :readdir].freeze

    # The Net::SFTP session object that is servicing this request
    attr_reader :session

    # The SFTP packet identifier for this request
    attr_reader :id

    # The type of this request (e.g., :open, :symlink, etc.)
    attr_reader :type

    # The callback (if any) associated with this request. When the response
    # is recieved for this request, the callback will be invoked.
    attr_reader :callback

    # The hash of properties associated with this request. Properties allow
    # programmers to associate arbitrary data with a request, making state
    # machines richer.
    attr_reader :properties

    # The response that was received for this request (see Net::SFTP::Response)
    attr_reader :response

    # Instantiate a new Request object, serviced by the given +session+, and
    # being of the given +type+. The +id+ is the packet identifier for this
    # request.
    def initialize(session, type, id, &callback) #:nodoc:
      @session, @id, @type, @callback = session, id, type, callback
      @response = nil
      @error = nil
      @properties = {}
    end

    # Returns the value of property with the given +key+. If +key+ is not a
    # symbol, it will be converted to a symbol before lookup.
    def [](key)
      properties[key.to_sym]
    end

    # Sets the value of the property with name +key+ to +value+. If +key+ is
    # not a symbol, it will be converted to a symbol before lookup.
    def []=(key, value)
      properties[key.to_sym] = value
    end

    # Returns +true+ if the request is still waiting for a response from the
    # server, and +false+ otherwise. The SSH event loop must be run in order
    # for a request to be processed; see #wait.
    def pending?
      session.pending_requests.key?(id)
    end

    # Waits (blocks) until the server responds to this packet. If prior
    # SFTP packets were also pending, they will be processed as well (since
    # SFTP packets are processed in the order in which they are received by
    # the server). Returns the request object itself. Raises
    # Net::SFTP::SessionClosedError if the channel closed before the server
    # responded.
    def wait
      session.loop { pending? }
      raise @error if @error
      self
    end

    public # but not "published". Internal use only

      # When the server responds to this request, the packet is passed to
      # this method, which first verifies that the packet honors the contract
      # of this request (see ::RESPONSE_TYPES), then parses it and builds a
      # Net::SFTP::Response object to encapsulate it. If a #callback has been
      # provided for this request, the callback is invoked with the new
      # response object.
      #
      # A structurally valid packet of the wrong type, or an FXP_STATUS that
      # cannot answer this request, fails the request with a
      # Net::SFTP::MalformedPacketError: no Response is stored, no success
      # callback runs, and #wait re-raises the error. The request has already
      # been removed from the session's pending requests by the dispatcher.
      def respond_to(packet) #:nodoc:
        data = session.protocol.parse(packet)
        data[:type] = packet.type
        verify_response!(packet, data)

        @response = Response.new(self, data)

        callback.call(@response) if callback
      rescue Net::SFTP::Exception => error
        fail!(error)
        raise
      end

      # Marks this request as failed without a response; #wait will raise
      # +error+.
      def fail!(error) #:nodoc:
        @error = error
      end

    private

      # Raises Net::SFTP::MalformedPacketError unless the parsed +packet+ is a
      # legal answer to a request of this type. An FXP_STATUS is legal when it
      # reports an error, and legal with FX_EOF only for #read and #readdir;
      # an FX_OK status never replaces the payload packet that payload-bearing
      # requests require.
      def verify_response!(packet, data)
        expected = RESPONSE_TYPES.fetch(type) do
          raise MalformedPacketError, "no response contract is defined for the #{type.inspect} request"
        end

        return if expected.include?(packet.type)

        unless packet.type == FXP_STATUS
          raise MalformedPacketError,
            "expected #{describe_types(expected)} response for #{type} request (id #{id}), " \
            "but got packet type #{packet.type}"
        end

        if data[:code] == FX_OK && !expected.empty?
          raise MalformedPacketError,
            "FX_OK status without a #{describe_types(expected)} packet cannot satisfy the #{type} request (id #{id})"
        end

        if data[:code] == FX_EOF && !EOF_REQUESTS.include?(type)
          raise MalformedPacketError,
            "FX_EOF status is not a valid response for the #{type} request (id #{id})"
        end
      end

      def describe_types(types)
        return "FXP_STATUS" if types.empty?
        types.map { |value| Constants::PacketTypes.constants.find { |name| Constants::PacketTypes.const_get(name) == value } || value }.join(" or ")
      end
  end

end; end