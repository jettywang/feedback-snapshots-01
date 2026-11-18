# frozen_string_literal: true

require 'openssl'
require 'net/ssh/buffer'
require 'net/ssh/transport/cipher_factory'
require 'net/ssh/transport/hmac'
require 'net/ssh/transport/key_expander'

module Net
  module SSH
    module Rekey
      # Short, fully-qualified handles to the library primitives reused here.
      CipherFactory = Net::SSH::Transport::CipherFactory
      HMAC = Net::SSH::Transport::HMAC
      Buffer = Net::SSH::Buffer
      # Derives the six session keys for one direction of an SSH connection and
      # wraps them in a ready-to-use cipher/HMAC pair. The derivation mirrors
      # RFC 4253 section 7.2 and Net::SSH::Transport::Algorithms#exchange_keys
      # exactly, so a harness endpoint and the real client stay wire-compatible.
      #
      # Importantly the exchange hash changes on every rekey while +session_id+
      # stays fixed at the first exchange hash; keys therefore differ per
      # generation but remain bound to the long-lived session id.
      class Direction
        attr_reader :cipher, :hmac, :block_size, :sequence_number
        attr_reader :cipher_name, :cipher_key, :iv, :shared, :hash, :digester

        def initialize(role, shared, hash, session_id, digester,
                       cipher_name, hmac_name, start_sequence = 0)
          key_material = Proc.new { |salt| digester.digest(shared + hash + salt + session_id) }

          # From a given endpoint's perspective it encrypts with its own send key
          # and decrypts with the peer's. The caller passes the salt letters that
          # correspond to this direction.
          iv_salt, key_salt, mac_salt = salts_for(role)
          iv = key_material.call(iv_salt)
          key = key_material.call(key_salt)
          mac_key = key_material.call(mac_salt)

          parameters = { shared: shared, hash: hash, digester: digester }

          @cipher = CipherFactory.get(
            cipher_name,
            parameters.merge(iv: iv, key: key, encrypt: encrypting?(role))
          )
          @hmac =
            if @cipher.implicit_mac?
              @cipher.implicit_mac
            else
              HMAC.get(hmac_name, mac_key, parameters)
            end
          @block_size = @cipher.block_size
          # SSH sequence numbers are monotonic across the whole connection and
          # are NOT reset by a rekey (RFC 4253 6.4); a rotation continues the
          # prior direction's count.
          @sequence_number = start_sequence & 0xFFFFFFFF
          @blocks_processed = 0

          # Retain the negotiated key material so a receive codec can build a
          # throwaway probe cipher for length peeking without consuming CTR state.
          @cipher_name = cipher_name
          @cipher_key = key
          @iv = iv
          @shared = shared
          @hash = hash
          @digester = digester
        end

        def increment
          @sequence_number = (@sequence_number + 1) & 0xFFFFFFFF
        end

        # Total cipher blocks consumed since the generation began. CTR has no
        # inter-packet carry, so the counter for the next frame is always the
        # initial IV advanced by exactly this many blocks.
        attr_reader :blocks_processed

        def note_blocks(encrypted_length)
          @blocks_processed += encrypted_length / @block_size
        end

        # Counter value at the start of the next frame: initial IV plus the block
        # offset, computed as a big-endian integer addition modulo 2**(iv bits).
        def current_counter_iv
          bit_width = @iv.bytesize * 8
          value = (@iv.unpack1('H*').to_i(16) + @blocks_processed) % (1 << bit_width)
          byte_length = (bit_width + 7) / 8
          hex = value.to_s(16)
          hex = "0#{hex}" if hex.length.odd?
          [hex].pack('H*').rjust(byte_length, "\0")
        end

        private

        # Salt letters A/C/E protect client->server traffic, B/D/F the reverse.
        # The role names describe whose traffic this direction carries:
        #   :encrypt / :server_recv -> client->server (A/C/E)
        #   :decrypt / :server_send -> server->client (B/D/F)
        # The :self_send / :self_recv pair deliberately share one key stream
        # (A/C/E) and differ only in the cipher direction, letting a test
        # protect and then validate a frame without a second endpoint.
        def salts_for(role)
          case role
          when :encrypt, :server_recv, :self_send, :self_recv then %w[A C E]
          when :decrypt, :server_send then %w[B D F]
          else raise ArgumentError, "unknown direction role #{role.inspect}"
          end
        end

        def encrypting?(role)
          role == :encrypt || role == :server_send || role == :self_send
        end
      end

      # Protects and unprotects SSH binary packets for one harness endpoint. It
      # is a deliberately small, explicit implementation of the same framing
      # rules as Net::SSH::Transport::PacketStream (standard CTR + HMAC, no
      # EtM/AEAD in these tests) so the generation boundaries are visible.
      class FrameCodec
        attr_reader :send_dir, :recv_dir

        def initialize(send_dir, recv_dir)
          @send_dir = send_dir
          @recv_dir = recv_dir
          @frame_bytes = Buffer.new
          # A second cipher over the same key stream advanced in lock-step with
          # the primary receive cipher, so its CTR counter always points at the
          # start of the next frame while the primary cipher is reserved for
          # full-frame decryption and HMAC verification.
          @length_cipher = new_length_cipher
        end

        # Encrypt + MAC one payload and return the on-wire bytes, advancing the
        # send sequence number. Mirrors PacketStream#enqueue_packet.
        def encode(payload)
          payload = payload.to_s
          actual_length = 4 + payload.bytesize + 1
          padding_length = @send_dir.block_size - (actual_length % @send_dir.block_size)
          padding_length += @send_dir.block_size if padding_length < 4
          packet_length = payload.bytesize + padding_length + 1

          if packet_length < 16
            padding_length += @send_dir.block_size
            packet_length = payload.bytesize + padding_length + 1
          end

          padding = Array.new(padding_length) { rand(256) }.pack('C*')
          unencrypted = [packet_length, padding_length, payload, padding].pack('NCA*A*')
          mac = @send_dir.hmac.digest([@send_dir.sequence_number, unencrypted].pack('NA*'))
          encrypted = @send_dir.cipher.update(unencrypted) << @send_dir.cipher.final
          @send_dir.note_blocks(encrypted.bytesize)

          frame = encrypted + mac
          seq = @send_dir.sequence_number
          @send_dir.increment
          [frame, seq]
        end

        # Feed raw bytes from the peer and return every payload that can be
        # fully decoded. Raises on a bad length or HMAC, which is what makes a
        # premature key-generation switch or a replayed NEWKEYS observable.
        def decode(data)
          @frame_bytes.append(data)
          packets = []

          while (payload = read_one_packet)
            packets << payload
          end

          packets
        end

        private

        def read_one_packet
          minimum = [@recv_dir.block_size, 4].max
          return nil if @frame_bytes.available < minimum

          # The persistent length cipher is parked at this frame's starting
          # counter. Decrypt the leading four bytes to learn the packet length
          # without consuming the primary receive cipher's stream.
          head = @frame_bytes.remainder_as_buffer.read(4)
          packet_length = Buffer.new(@length_cipher.update(head) << @length_cipher.final).read_long
          return nil if packet_length.nil?

          raise Net::SSH::Exception, "bad packet length #{packet_length}" if packet_length < 5 || packet_length > 256 * 1024

          mac_length = @recv_dir.hmac.mac_length
          total = 4 + packet_length + mac_length
          return nil if @frame_bytes.available < total

          # Remove the complete frame from the buffer so it is not re-decoded.
          raw = @frame_bytes.read!(total)
          encrypted = raw.byteslice(0, 4 + packet_length)
          real_hmac = raw.byteslice(4 + packet_length, mac_length)

          # Advance the length cipher over the remainder of this same frame so
          # it stays aligned with the primary cipher for the next frame.
          @length_cipher.update(encrypted.byteslice(4, encrypted.bytesize - 4))
          @length_cipher.final

          decrypted = @recv_dir.cipher.update(encrypted) << @recv_dir.cipher.final
          @recv_dir.note_blocks(encrypted.bytesize)
          computed = @recv_dir.hmac.digest([@recv_dir.sequence_number, decrypted].pack('NA*'))
          unless secure_compare(real_hmac, computed)
            raise Net::SSH::Exception, "corrupted hmac detected at sequence #{@recv_dir.sequence_number}"
          end

          packet = Buffer.new(decrypted)
          packet.read_long # packet_length
          padding_length = packet.read_byte
          payload = packet.read(packet_length - padding_length - 1)

          @recv_dir.increment
          Net::SSH::Packet.new(Buffer.new(payload))
        end

        # Build the independent length-probe cipher at the receive direction's
        # current starting counter and key material.
        def new_length_cipher
          CipherFactory.get(
            @recv_dir.cipher_name,
            iv: @recv_dir.current_counter_iv, key: @recv_dir.cipher_key, decrypt: true,
            shared: @recv_dir.shared, hash: @recv_dir.hash, digester: @recv_dir.digester
          )
        end

        def secure_compare(a, b)
          return false unless a.bytesize == b.bytesize

          l = a.unpack('C*')
          r = b.unpack('C*')
          result = 0
          l.each_with_index { |x, i| result |= x ^ r[i] }
          result.zero?
        end
      end
    end
  end
end
