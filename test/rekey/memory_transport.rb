# frozen_string_literal: true

require 'net/ssh/buffer'
require 'net/ssh/loggable'

module Net
  module SSH
    module Rekey
      # A single, ordered record of one SSH packet that crossed the in-memory
      # wire. Each endpoint appends one record per packet it *sends*, tagged
      # with the key generation active when the packet was protected and the
      # role that emitted it. Keeping a shared, append-only transcript lets the
      # regression assert on delivery order and key generations without relying
      # on timing or threads.
      WireRecord = Struct.new(:seq, :role, :type, :generation, :payload, keyword_init: true)

      # A full-duplex, in-memory SSH socket built on two cross-connected
      # IO.pipe pairs (one per direction). Using real pipe descriptors means the
      # unmodified Net::SSH transport can extend this object with
      # Net::SSH::Transport::PacketStream and keep calling IO.select, recv and
      # write exactly as it would against a TCP socket, while every byte still
      # stays inside the process.
      #
      # The endpoint deliberately exposes only the raw IO surface (#recv,
      # #write/#send, #to_io, socket-shaped no-ops). Once PacketStream is
      # extended onto it by the real transport, the library's own
      # BufferedIo#fill / #available_for_read? take over. It additionally tracks
      # the active key generation and appends a WireRecord to the shared
      # transcript whenever the framing layer finishes protecting a packet.
      class MemoryIO
        attr_accessor :role, :generation
        attr_reader :transcript, :read_io, :write_io

        def initialize(read_io, write_io, peer, transcript, role)
          @read_io = read_io
          @write_io = write_io
          @peer = peer
          @transcript = transcript
          @role = role
          @generation = 0
          @read_mutex = Mutex.new
        end

        # Build a connected client/server pair. Writes from one endpoint land on
        # the other endpoint's read pipe, and both share one transcript.
        def self.pair
          client_read, server_write = IO.pipe
          server_read, client_write = IO.pipe
          transcript = []
          client = new(client_read, client_write, nil, transcript, :client)
          server = new(server_read, server_write, nil, transcript, :server)
          client.instance_variable_set(:@peer, server)
          server.instance_variable_set(:@peer, client)
          [client, server]
        end

        # -- write side -----------------------------------------------------

        def write(data)
          @write_io.write(data)
          data.bytesize
        end

        def flush
          @write_io.flush
          self
        rescue IOError
          self
        end

        # BufferedIo#send_pending invokes Kernel#send(data, 0).
        def send_bytes(data, _flags = 0)
          write(data)
        end
        alias send send_bytes

        # -- read side ------------------------------------------------------

        # BufferedIo#fill calls recv, and PacketStream#next_packet only fills
        # after #available_for_read? reported the descriptor ready. The harness
        # pump runs concurrently and may consume those bytes in the gap between
        # the readiness check and the read. When that happens, block on the pipe
        # (releasing the GVL so the pump can finish) until either fresh bytes
        # arrive or the write end closes. A genuine EOF yields "" so the framing
        # layer's disconnect detection still works; a scheduling race yields the
        # real data instead of a spurious zero-length fill.
        def recv(length)
          chunk = @read_io.read_nonblock(length, exception: false)
          return chunk unless chunk == :wait_readable

          # Distinguish a closed peer (EOF, select returns the fd immediately)
          # from "temporarily drained".
          ready = IO.select([@read_io], nil, nil, 5)
          if ready.nil?
            +""
          else
            again = @read_io.read_nonblock(length, exception: false)
            again == :wait_readable ? +"" : again
          end
        end

        # Non-blocking variant that preserves the :wait_readable sentinel for
        # harness code that explicitly polls readiness.
        def recv_nonblock(length)
          @read_io.read_nonblock(length, exception: false)
        end

        def readpartial(length)
          @read_io.readpartial(length)
        end

        # IO.select([self]) needs a real descriptor; expose the read pipe.
        def to_io
          @read_io
        end

        # True when at least one byte is buffered on the read pipe.
        def readable?
          !IO.select([@read_io], nil, nil, 0).nil?
        end

        def close
          @read_io.close unless @read_io.closed?
          @write_io.close unless @write_io.closed?
        end

        def closed?
          @read_io.closed?
        end

        # -- socket-shaped surface used by Transport::Session ---------------

        def setsockopt(*_args); end

        def getsockname
          ::Socket.sockaddr_in(0, '127.0.0.1')
        end

        def getpeername
          ::Socket.sockaddr_in(0, '127.0.0.1')
        end

        def peer_ip
          '127.0.0.1'
        end

        # Record a fully protected packet at the generation currently active for
        # this endpoint. Invoked by the framing layer after a frame is written.
        def record_packet(seq, type, payload)
          @transcript << WireRecord.new(
            seq: seq,
            role: @role,
            type: type,
            generation: @generation,
            payload: payload.dup
          )
        end
      end
    end
  end
end
