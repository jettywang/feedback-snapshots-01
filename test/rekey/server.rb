# frozen_string_literal: true

require 'openssl'
require 'net/ssh/buffer'
require 'net/ssh/packet'
require 'net/ssh/transport/constants'
require 'net/ssh/transport/openssl'
require_relative 'crypto'
require_relative 'memory_transport'

module Net
  module SSH
    module Rekey
      # A minimal but cryptographically real SSH-2 server peer that runs entirely
      # over an in-memory socket. It performs ECDH key exchange, derives and
      # rotates keys on every rekey, frames packets with the negotiated
      # cipher/HMAC, and implements just enough of the connection and
      # authentication protocols to exercise a real Net::SSH client.
      #
      # The server is driven step-by-step by the test pump rather than a thread,
      # so the ordering of interleaved channel data, window adjustments and
      # NEWKEYS is fully deterministic.
      class Server
        include Net::SSH::Transport::Constants

        CURVE = 'prime256v1'
        KEX = 'ecdh-sha2-nistp256'
        HOST_KEY = 'ecdsa-sha2-nistp256'
        CIPHER = 'aes256-ctr'
        HMAC = 'hmac-sha2-256'
        VERSION = 'SSH-2.0-NetSSH-Rekey-Harness'

        attr_reader :host_key, :session_id, :exchange_hashes, :generation
        attr_reader :kex_count, :newkeys_seen, :kexinit_seen, :packets_processed
        attr_reader :last_shared, :last_hash

        # True while the server is mid key-exchange (its NEWKEYS has either not
        # been sent or the client's matching NEWKEYS has not arrived).
        def kex_pending?
          @kex_pending
        end

        def initialize(io, options = {})
          @io = io
          @logger = options[:logger]
          @host_key = OpenSSL::PKey::EC.generate(CURVE)
          @session_id = nil
          @exchange_hashes = []
          @generation = 0
          @kex_count = 0
          @newkeys_seen = 0
          @kexinit_seen = 0
          @codec = nil
          @pending_newkeys = false
          @kex_pending = false
          @client_kexinit = nil
          @server_kexinit_raw = nil
          @ingress = Buffer.new
          @raw_buffer = Buffer.new
          @pending_rotation = nil
          # Monotonic per-direction sequence numbers across the whole
          # connection, including the unprotected frames of the first exchange.
          @send_sequence = 0
          @recv_sequence = 0
          @channel_payloads = []
          @auth_requests = []
          @rekey_after_packets = nil
          @packets_processed = 0
          @on_userauth = options[:on_userauth]
        end

        # Send the protocol banner; the real client reads it during its own
        # ServerVersion negotiation.
        def send_banner
          @io.write("#{VERSION}\r\n")
        end

        # The version string as the client stores it after its own chomp!, which
        # is also the exact identifier that must feed the exchange hash.
        def server_version_string
          VERSION
        end

        # Pull every byte currently on the read pipe into one ingress buffer.
        # Both the unprotected banner line and the binary frames that follow it
        # arrive on this single pipe, so all reads must funnel through here to
        # keep the banner/KEXINIT boundary unambiguous.
        def read_inbound
          while @io.readable?
            chunk = @io.recv_nonblock(1_048_576)
            break if chunk == :wait_readable || chunk.nil?
            raise Net::SSH::Exception, 'read after server transport closed' if chunk.empty?

            @ingress.append(chunk)
          end
        end

        # Read and discard the client banner (it has no framing). Non-blocking:
        # returns :ready once the banner newline is consumed and :wait_readable
        # if more bytes are still needed. Any bytes buffered past the newline
        # (the client's first KEXINIT) are moved into the frame buffer intact.
        def consume_client_banner
          return :ready if @client_version

          read_inbound
          line = @banner_buffer ||= +""
          while (byte = @ingress.read(1))
            line << byte
            next unless byte == "\n"

            @client_version = line.chomp
            @banner_buffer = nil
            # Preserve anything already received after the banner for frame
            # parsing instead of letting it be mis-read as banner text.
            @raw_buffer.append(@ingress.read!) if @ingress.available.positive?
            return :ready
          end
          :wait_readable
        end

        def client_version
          @client_version || Net::SSH::Transport::ServerVersion::PROTO_VERSION
        end

        # Build the fixed KEXINIT name-lists. They intentionally intersect the
        # client defaults so negotiation always settles on the harness ciphers.
        def kexinit_payload
          names = {
            kex: KEX,
            host_key: HOST_KEY,
            enc: CIPHER,
            mac: HMAC,
            comp: 'none',
            lang: ''
          }
          Buffer.from(
            :byte, KEXINIT,
            :long, [1, 2, 3, 4],
            :mstring, [names[:kex], names[:host_key], names[:enc], names[:enc],
                       names[:mac], names[:mac]],
            :mstring, [names[:comp], names[:comp], names[:lang], names[:lang]],
            :bool, false, :long, 0
          ).to_s
        end

        # Server-initiated rekey: emit a KEXINIT without having seen one. The
        # client will answer and the exchange completes in #handle_kexinit.
        def request_rekey
          raise 'rekey already pending' if @kex_pending

          send_kexinit
          @kex_pending = true
        end

        # Drain everything currently buffered and process each decoded packet.
        # Before the first NEWKEYS the transport is unprotected, so the initial
        # exchange is parsed as plaintext SSH payloads; once keys exist every
        # frame is routed through the cipher/HMAC codec. Returns the number of
        # application packets handed to the connection layer (i.e. excluding
        # key-exchange traffic).
        # Non-blocking single step. Reads whatever is buffered on the pipe right
        # now and processes it; returns the number of application packets handed
        # to the connection layer. Scheduling (yielding to the peer thread) is
        # the driver's responsibility via the harness, keeping this method
        # reentrant and free of blocking calls.
        def pump
          return 0 unless @client_version

          read_inbound
          # The banner reader may have already moved the first post-banner
          # bytes into the frame buffer; feed both sources through one path so
          # nothing is stranded when no new bytes have arrived.
          @raw_buffer.append(@ingress.read!) if @ingress.available.positive?
          return 0 if @raw_buffer.available.zero? && @codec.nil?

          app_packets = 0
          if @codec.nil?
            each_plaintext_packet do |packet|
              # Count before dispatching: handling the client's NEWKEYS rotates
              # the keys and must seed the new receive direction with a sequence
              # number that already includes this frame.
              @recv_sequence = (@recv_sequence + 1) & 0xFFFFFFFF
              handle_packet(packet)
              app_packets += 1 unless kex_traffic?(packet.type)
              @packets_processed += 1
            end
          else
            # After the first NEWKEYS every frame is encrypted; move any buffered
            # bytes into the codec in one stream.
            @codec.decode(@raw_buffer.read!).each do |packet|
              handle_packet(packet)
              @recv_sequence = @codec.recv_dir.sequence_number
              app_packets += 1 unless kex_traffic?(packet.type)
              @packets_processed += 1
            end
          end
          maybe_auto_rekey
          app_packets
        end

        # Parses the unprotected packets of the first exchange out of the raw
        # buffer. An SSH frame starts with a uint32 packet_length (the bytes that
        # follow the length field itself), then a padding_length byte and the
        # payload. Only KEXINIT, KEXECDH_INIT and NEWKEYS are legal before keys
        # are installed, so a bounded length-prefix parse is sufficient. Bytes
        # are consumed as complete frames are removed so a later pump never
        # re-parses an already handled packet.
        def each_plaintext_packet
          while @raw_buffer.available >= 5
            header = Net::SSH::Buffer.new(@raw_buffer.remainder_as_buffer.to_s)
            packet_length = header.read_long
            raise Net::SSH::Exception, "bad plaintext packet length #{packet_length}" if packet_length < 5 || packet_length > 256 * 1024
            break if @raw_buffer.available < 4 + packet_length

            frame = @raw_buffer.read!(4 + packet_length)
            body = Net::SSH::Buffer.new(frame.byteslice(4, packet_length))
            padding_length = body.read_byte
            # packet_length counts the padding_length byte, the payload and the
            # padding, so the payload is everything before that trailing padding.
            payload = body.read(packet_length - padding_length - 1)
            yield Net::SSH::Packet.new(Net::SSH::Buffer.new(payload))
          end
        end

        # Bytes the server still holds for a channel, in arrival order.
        def channel_data
          @channel_payloads.dup
        end

        def auth_requests
          @auth_requests.dup
        end

        # Test hook: feed a decoded packet straight into the dispatch logic.
        # Used to assert that a NEWKEYS arriving without a matching exchange is
        # rejected rather than silently rotating the keys again.
        def feed_packet(packet)
          handle_packet(packet)
        end

        # Verify the captured publickey signature against the long-lived session
        # id. The client signs session_id + the unsigned USERAUTH_REQUEST body,
        # so rebuilding that body and checking the signature with the advertised
        # key proves the signature is bound to the *first* exchange hash even
        # after one or more rekeys have introduced newer exchange hashes.
        def verify_publickey_signature!(record)
          unsigned = build_unsigned_userauth(record)
          signed_data = Net::SSH::Buffer.new
          signed_data.write_string(@session_id)
          signed_data.append(unsigned)

          sig_buffer = Net::SSH::Buffer.new(record[:sig_blob])
          sig_algorithm = sig_buffer.read_string
          raw_signature = sig_buffer.read_string
          key = Net::SSH::Buffer.new(record[:key_blob]).read_key

          unless key.ssh_do_verify(raw_signature, signed_data.to_s, host_key: sig_algorithm)
            raise Net::SSH::Exception, 'publickey signature did not verify against the long-lived session id'
          end

          true
        end

        # Reconstruct the exact USERAUTH_REQUEST bytes the client signed: the
        # full signed request up to (but not including) its trailing signature
        # string. Walking the fields leaves the buffer positioned exactly at that
        # signature field, so a prefix slice reproduces the unsigned body without
        # re-encoding (which could diverge in padding or key blob formatting).
        def build_unsigned_userauth(record)
          reader = Net::SSH::Buffer.new(record[:raw])
          reader.read_byte # type
          reader.read_string # username
          reader.read_string # service
          reader.read_string # method
          reader.read_bool # has_signature
          reader.read_string # algorithm
          reader.read_string # key blob
          record[:raw].byteslice(0, reader.position)
        end

        # -- application helpers --------------------------------------------

        def send_channel_data(remote_id, data)
          send_payload(Buffer.from(:byte, CHANNEL_DATA, :long, remote_id, :string, data).to_s)
        end

        def send_window_adjust(remote_id, bytes)
          send_payload(Buffer.from(:byte, CHANNEL_WINDOW_ADJUST, :long, remote_id, :long, bytes).to_s)
        end

        def send_channel_confirmation(local_id, remote_id, window, packet_size)
          send_payload(Buffer.from(:byte, CHANNEL_OPEN_CONFIRMATION,
                                   :long, remote_id, :long, local_id,
                                   :long, window, :long, packet_size).to_s)
        end

        private

        CHANNEL_DATA = 94
        CHANNEL_WINDOW_ADJUST = 93
        CHANNEL_OPEN = 90
        CHANNEL_CLOSE = 97
        CHANNEL_EOF = 96
        SERVICE_REQUEST = 5
        USERAUTH_REQUEST = 50
        USERAUTH_PK_OK = 60
        USERAUTH_SUCCESS = 52
        SERVICE_ACCEPT = 6

        def kex_traffic?(type)
          type == KEXINIT || type == NEWKEYS || type == 30 || type == 31
        end

        def maybe_auto_rekey
          return unless @rekey_after_packets
          return if @kex_pending

          request_rekey if @packets_processed >= @rekey_after_packets
        end

        def rekey_after_packets!(count)
          @rekey_after_packets = count
        end

        def handle_packet(packet)
          case packet.type
          when KEXINIT then handle_kexinit(packet)
          when NEWKEYS then accept_client_newkeys
          when 30 then handle_ecdh_init(packet)
          when CHANNEL_DATA then handle_channel_data(packet)
          when CHANNEL_WINDOW_ADJUST then # consumed: window bookkeeping is irrelevant to the harness
          when CHANNEL_OPEN then handle_channel_open(packet)
          when CHANNEL_CLOSE, CHANNEL_EOF then # no-op
          when SERVICE_REQUEST then handle_service_request(packet)
          when USERAUTH_REQUEST then handle_userauth_request(packet)
          else
            # Unimplemented message types are ignored rather than fatal so the
            # harness can focus on transport behaviour.
          end
        end

        def handle_service_request(packet)
          name = packet.read_string
          send_payload(Buffer.from(:byte, SERVICE_ACCEPT, :string, name).to_s)
        end

        def handle_channel_open(packet)
          packet.read_string # channel type
          remote_id = packet.read_long
          send_channel_confirmation(0, remote_id, 2_097_152, 32_768)
        end

        # CHANNEL_DATA is a registered Net::SSH::Packet, so instantiate! already
        # parsed its local id and data string; read the named element directly.
        def handle_channel_data(packet)
          @channel_payloads << packet[:data]
        end

        # Capture the publickey USERAUTH_REQUEST so tests can prove the client
        # signed the long-lived session id. The full payload is snapshotted
        # before any field is consumed so it can be rebuilt for verification.
        def handle_userauth_request(packet)
          raw = packet.content.dup
          reader = Net::SSH::Buffer.new(raw)
          reader.read_byte # message type
          username = reader.read_string
          service = reader.read_string
          method = reader.read_string
          record = { username: username, service: service, method: method, raw: raw }

          if method == 'publickey'
            has_signature = reader.read_bool
            algorithm = reader.read_string
            key_blob = reader.read_string
            if has_signature
              sig_blob = reader.read_string
              record[:algorithm] = algorithm
              record[:key_blob] = key_blob
              record[:sig_blob] = sig_blob
              @on_userauth&.call(record, self)
              send_payload(Buffer.from(:byte, USERAUTH_SUCCESS).to_s)
            else
              send_payload(Buffer.from(:byte, USERAUTH_PK_OK).to_s)
            end
          else
            send_payload(Buffer.from(:byte, USERAUTH_SUCCESS).to_s)
          end
          @auth_requests << record
        end

        # -- key exchange ----------------------------------------------------

        def send_kexinit
          payload = kexinit_payload
          @server_kexinit_raw = payload
          send_kex_message(payload)
        end

        # Protect a key-exchange message with the keys of the generation that is
        # currently active on this endpoint. Before the first NEWKEYS that is the
        # unencrypted identity "cipher"; on a rekey it is the outgoing generation
        # still in force until both NEWKEYS have been exchanged.
        def send_kex_message(payload)
          if @codec.nil?
            send_raw(encode_plaintext(payload))
            # Pre-key frames belong to generation 0 and share the connection's
            # single monotonic send sequence with later encrypted frames.
            @io.record_packet(@send_sequence, payload.getbyte(0), payload)
            @send_sequence += 1
          else
            send_payload(payload)
          end
        end

        def handle_kexinit(packet)
          @kexinit_seen += 1
          @client_kexinit = packet.content.dup
          send_kexinit unless @kex_pending
          @kex_pending = true
        end

        def handle_ecdh_init(packet)
          client_qc = packet.read_string

          ecdh = OpenSSL::PKey::EC.generate(CURVE)
          server_qs = ecdh.public_key.to_bn.to_s(2)
          client_point = OpenSSL::PKey::EC::Point.new(
            OpenSSL::PKey::EC.new(CURVE).group, OpenSSL::BN.new(client_qc, 2)
          )
          shared_bn = OpenSSL::BN.new(ecdh.dh_compute_key(client_point), 2)
          shared = shared_bn.to_ssh

          hash = exchange_hash(shared_bn, client_qc, server_qs)
          @exchange_hashes << hash
          @session_id ||= hash

          signature = encode_host_signature(hash)
          key_blob = Net::SSH::Buffer.from(:key, @host_key).to_s

          reply = Buffer.from(
            :byte, 31,
            :string, key_blob,
            :string, server_qs,
            :string, signature
          )
          # The KEXECDH_REPLY is still a key-exchange message and goes out in
          # the current generation's protection. NEWKEYS itself is also sent with
          # the pre-rotation keys (plaintext on the first exchange), mirroring
          # Net::SSH which only installs the new cipher after confirm_newkeys
          # returns. The rotation is therefore deferred until the client's
          # matching NEWKEYS arrives.
          send_kex_message(reply.to_s)

          @pending_rotation = { shared: shared, hash: hash }
          @pending_newkeys = true
          send_kex_message(Buffer.from(:byte, NEWKEYS).to_s)
        end

        def accept_client_newkeys
          @newkeys_seen += 1
          unless @pending_newkeys
            raise Net::SSH::Exception, 'unexpected or duplicated NEWKEYS: server had not completed its key rotation'
          end

          rotate_keys(@pending_rotation[:shared], @pending_rotation[:hash])
          @pending_rotation = nil
          @pending_newkeys = false
          @kex_pending = false
          @kex_count += 1
        end

        # +shared_bn+ is the raw OpenSSL::BN; write_bignum performs the single
        # mpint encoding, matching Net::SSH's Abstract5656#build_signature_buffer.
        def exchange_hash(shared_bn, client_qc, server_qs)
          key_blob = Net::SSH::Buffer.from(:key, @host_key).to_s
          Buffer.new.tap do |b|
            b.write_string(client_version, VERSION,
                           @client_kexinit, @server_kexinit_raw,
                           key_blob, client_qc, server_qs)
            b.write_bignum(shared_bn)
          end.then { |b| OpenSSL::Digest::SHA256.digest(b.to_s) }
        end

        def encode_host_signature(hash)
          raw_sig = @host_key.ssh_do_sign(hash)
          Buffer.from(:string, HOST_KEY, :string, raw_sig).to_s
        end

        # Build fresh send/recv Directions from the new exchange hash and switch
        # the codec over. Key material changes per generation, but the SSH packet
        # sequence numbers keep increasing across the whole connection (RFC 4253
        # 6.4), so each new direction starts where the old codec's direction left
        # off. Reading the live direction counters (rather than the connection
        # level mirrors) is essential because rotation runs from inside
        # accept_client_newkeys, after the NEWKEYS frame has already advanced the
        # receive direction but before its mirror is refreshed. The server's send
        # traffic is client->server's reverse, so the SSH B/D/F salts protect
        # server writes while A/C/E protect what it reads.
        def rotate_keys(shared, hash)
          @last_shared = shared
          @last_hash = hash
          digester = OpenSSL::Digest::SHA256
          send_seq = @codec ? @codec.send_dir.sequence_number : @send_sequence
          recv_seq = @codec ? @codec.recv_dir.sequence_number : @recv_sequence
          send_dir = Direction.new(:server_send, shared, hash, @session_id, digester,
                                   CIPHER, HMAC, send_seq)
          recv_dir = Direction.new(:server_recv, shared, hash, @session_id, digester,
                                   CIPHER, HMAC, recv_seq)
          @codec = FrameCodec.new(send_dir, recv_dir)
          @send_sequence = send_seq
          @recv_sequence = recv_seq
          @generation += 1
          @io.generation = @generation
        end

        # -- framing ---------------------------------------------------------

        def send_payload(payload)
          raise 'cannot send protected traffic before first key exchange' if @codec.nil?

          frame, seq = @codec.encode(payload)
          @io.write(frame)
          type = payload.getbyte(0)
          @io.record_packet(seq, type, payload)
          @send_sequence = @codec.send_dir.sequence_number
        end

        def send_raw(payload)
          @io.write(payload)
        end

        # Build an unencrypted SSH frame for traffic exchanged before the first
        # NEWKEYS. The pre-negotiation block size is 8 and there is no MAC, but
        # the length/padding rules otherwise match a protected frame.
        def encode_plaintext(payload)
          block_size = 8
          actual_length = 4 + payload.bytesize + 1
          padding_length = block_size - (actual_length % block_size)
          padding_length += block_size if padding_length < 4
          packet_length = payload.bytesize + padding_length + 1
          if packet_length < 16
            padding_length += block_size
            packet_length = payload.bytesize + padding_length + 1
          end
          padding = Array.new(padding_length) { rand(256) }.pack('C*')
          [packet_length, padding_length, payload, padding].pack('NCA*A*')
        end
      end
    end
  end
end
