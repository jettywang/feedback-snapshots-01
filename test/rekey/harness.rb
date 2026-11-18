# frozen_string_literal: true

require 'net/ssh/buffer'
require 'net/ssh/transport/session'
require 'net/ssh/connection/constants'
require_relative 'memory_transport'
require_relative 'server'

module Net
  module SSH
    module Rekey
      # Drives a real Net::SSH::Transport::Session against the in-memory Server.
      #
      # Concurrency model: the test thread is the only reader of the *server's*
      # receive pipe; a mutex (@client_lock) makes the *client's* receive pipe a
      # single-reader resource as well. Blocking client calls (connect, rekey)
      # run on a worker thread while holding the lock, and every explicit
      # application-packet drain takes the same lock first. This guarantees no
      # two threads ever read the same socket concurrently, which is what makes
      # the pump deterministic and free of lost or duplicated packets.
      class Harness
        DEFAULT_OPTIONS = {
          verify_host_key: :never,
          encryption: 'aes256-ctr',
          hmac: 'hmac-sha2-256',
          kex: 'ecdh-sha2-nistp256',
          host_key: 'ecdsa-sha2-nistp256'
        }.freeze

        class ProgressError < StandardError; end

        attr_reader :client, :server, :client_io, :server_io

        def initialize(options = {})
          @options = DEFAULT_OPTIONS.merge(options)
          @client_io, @server_io = MemoryIO.pair
          @server = Server.new(@server_io, logger: @options[:logger])
          @client = nil
          @incoming = []
          @client_lock = Mutex.new
        end

        def transcript
          @server_io.transcript
        end

        # Application-level packets the client decrypted, in arrival order.
        def incoming
          @incoming.dup
        end

        # Run the initial key exchange to completion.
        def connect!
          @server.send_banner
          run_worker { @client = Net::SSH::Transport::Session.new('mem.local', client_options) }
          raise ProgressError, 'client did not finish the initial key exchange' unless @client.algorithms.initialized?

          self
        end

        # Client-initiated rekey, blocked until both generations rotate.
        def client_rekey!
          run_worker { @client.rekey! }
          pump_until { !@server.kex_pending? && !@client.algorithms.pending? }
        end

        # Server-initiated rekey. A worker holds the client lock and polls the
        # client transport so the unsolicited KEXINIT/NEWKEYS are consumed; the
        # test thread pumps the server until both sides settle.
        def server_rekey!
          @server.request_rekey
          error = nil
          worker = Thread.new do
            @client_lock.synchronize do
              begin
                loop do
                  @client.poll_message(:nonblock, false)
                  break if !@client.algorithms.pending? && !@server.kex_pending?

                  Thread.pass
                  sleep 0.0005
                end
              rescue StandardError => e
                error = e
              end
            end
          end
          pump_until { !worker.alive? && !@server.kex_pending? && !@client.algorithms.pending? }
          raise error if error
        end

        # Send an encrypted application payload from the client and pump until
        # the server has fully decrypted it.
        def client_send(payload)
          before = @server.packets_processed
          run_worker { @client.send_message(Net::SSH::Buffer.new(payload)) }
          pump_until { @server.packets_processed > before }
        end

        def server_send_channel_data(remote_id, data)
          @server.send_channel_data(remote_id, data)
          collect_until(Connection::Constants::CHANNEL_DATA)
        end

        def server_send_window_adjust(remote_id, bytes)
          @server.send_window_adjust(remote_id, bytes)
          collect_until(Connection::Constants::CHANNEL_WINDOW_ADJUST)
        end

        private

        def client_options
          options = @options.dup
          io = @client_io
          options[:proxy] = Object.new.tap { |p| p.define_singleton_method(:open) { |_h, _p, _o| io } }
          options
        end

        # Run a blocking client operation on a worker thread holding the client
        # lock, and pump the server until the worker finishes. While the worker
        # owns the lock it is the sole client-pipe reader.
        def run_worker
          error = nil
          thread = Thread.new do
            @client_lock.synchronize do
              begin
                yield
              rescue StandardError => e
                error = e
              end
            end
          end
          pump_until { !thread.alive? }
          raise error if error

          thread.value
        end

        # Pump the server while taking the client lock to drain application
        # packets until a *new* packet of +type+ arrives. The starting count
        # matters because earlier packets of the same type (e.g. a prior
        # CHANNEL_DATA) must not satisfy the wait for this send.
        def collect_until(type, max_steps = 100_000, idle_limit = 5_000)
          target = @incoming.count { |packet| packet.type == type } + 1
          idle = 0
          max_steps.times do
            return if @incoming.count { |packet| packet.type == type } >= target

            progressed = tick
            progressed += drain_application_packets
            idle = progressed.zero? ? idle + 1 : 0
            raise ProgressError, 'harness made no progress and the expected state was not reached' if idle > idle_limit
          end
          raise ProgressError, 'harness exceeded the step budget'
        end

        # Take the client lock briefly and pull every currently-decryptable
        # application packet. The lock makes this mutually exclusive with any
        # blocking worker, so no packet can be read twice or skipped.
        def drain_application_packets
          count = 0
          @client_lock.synchronize do
            loop do
              packet = @client.poll_message(:nonblock, false)
              break if packet.nil?

              @incoming << packet
              count += 1
            end
          end
          count
        end

        def received?(type)
          @incoming.any? { |packet| packet.type == type }
        end

        # One server-side scheduling tick; never reads the client pipe.
        def tick
          Thread.pass
          sleep 0.0005
          @server.consume_client_banner
          @server.pump
        end

        def pump_until(max_steps = 100_000, idle_limit = 5_000)
          idle = 0
          max_steps.times do
            return if yield

            progressed = tick
            idle = progressed.zero? ? idle + 1 : 0
            raise ProgressError, 'harness made no progress and the expected state was not reached' if idle > idle_limit
          end
          raise ProgressError, 'harness exceeded the step budget'
        end
      end
    end
  end
end
