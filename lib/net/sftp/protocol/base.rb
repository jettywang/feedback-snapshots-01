require 'net/ssh/loggable'
require 'net/sftp/constants'
require 'net/sftp/protocol/bounded_read'

module Net; module SFTP; module Protocol

  # The abstract superclass of the specific implementations for each supported
  # SFTP protocol version. It implements general packet parsing logic, and
  # provides a way for subclasses to send requests.
  class Base
    include Net::SSH::Loggable
    include Net::SFTP::Constants
    include Net::SFTP::Constants::PacketTypes
    include Net::SFTP::Protocol::BoundedRead

    # The SFTP session object that acts as client to this protocol instance
    attr_reader :session

    # Create a new instance of a protocol driver, servicing the given session.
    def initialize(session)
      @session = session
      self.logger = session.logger
      @request_id_counter = -1
      @request_ids_wrapped = false
    end

    # Attept to parse the given packet. If the packet is of an unsupported
    # type, an exception will be raised. Returns the parsed data as a hash
    # (the keys in the hash are packet-type specific).
    def parse(packet)
      case packet.type
      when FXP_STATUS then parse_status_packet(packet)
      when FXP_HANDLE then parse_handle_packet(packet)
      when FXP_DATA   then parse_data_packet(packet)
      when FXP_NAME   then parse_name_packet(packet)
      when FXP_ATTRS  then parse_attrs_packet(packet)
      else raise NotImplementedError, "unknown packet type: #{packet.type}"
      end
    end

    # Asks an OpenSSH server to fsync(2) the open file identified by +handle+.
    # The server must advertise the fsync@openssh.com extension.
    def fsync(handle)
      send_request(FXP_EXTENDED, :string, "fsync@openssh.com", :string, handle)
    end

    # Asks an OpenSSH server to rename +old_path+ to +new_path+ with POSIX
    # rename(2) semantics, replacing +new_path+ if it exists. The server must
    # advertise the posix-rename@openssh.com extension.
    def posix_rename(old_path, new_path)
      send_request(FXP_EXTENDED, :string, "posix-rename@openssh.com",
        :string, old_path, :string, new_path)
    end

    private

      # Send a new packet of the given type, and with the given data arguments.
      # A new request identifier will be allocated to this request, and will
      # be returned.
      def send_request(type, *args)
        begin
          previous_request_id = @request_id_counter
          @request_id_counter = (@request_id_counter + 1) & 0xffffffff
          @request_ids_wrapped = true if previous_request_id == 0xffffffff
        end while @request_ids_wrapped && session.pending_requests.key?(@request_id_counter)

        session.send_packet(type, :long, @request_id_counter, *args)
        return @request_id_counter
      end
  end

end; end; end
