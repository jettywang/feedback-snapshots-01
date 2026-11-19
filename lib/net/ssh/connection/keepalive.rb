require 'net/ssh/loggable'

module Net
  module SSH
    module Connection
      # Liveness check based on "keepalive@openssh.com" global requests.
      #
      # A probe is sent every +interval+ seconds (measured on a monotonic
      # clock, so wall-clock adjustments never disturb the schedule), and the
      # session is declared dead once +keepalive_maxcount+ probes are
      # unanswered at the moment the next probe comes due.
      #
      # Replies are matched to probes in send order: per RFC 4254 the server
      # answers global requests in the order it received them, so a reply
      # only ever excuses the oldest outstanding probe. A late reply to an
      # old probe therefore cannot hide newer unanswered ones, and ordinary
      # traffic does not postpone or replace probing -- only an actual
      # keepalive reply proves the peer is still there.
      class Keepalive
        include Loggable

        # The clock used for scheduling, in seconds. Defaults to a monotonic
        # clock; inject a controllable one in tests.
        attr_accessor :clock

        # Monotonic timestamps of the probes sent but not yet answered,
        # oldest first.
        attr_reader :outstanding

        def initialize(session)
          @session = session
          self.logger = session.logger
          @clock = -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
          @last_sent_at = nil
          @outstanding = []
        end

        def options
          @session.options
        end

        def enabled?
          options[:keepalive]
        end

        def interval
          options[:keepalive_interval] || Session::DEFAULT_IO_SELECT_TIMEOUT
        end

        # How many probes may remain unanswered before the session is
        # declared dead. A value of zero or less disables the timeout.
        def keepalive_maxcount
          (options[:keepalive_maxcount] || 3).to_i
        end

        # The number of probes sent but not yet answered by the server.
        def unresponded_count
          @outstanding.size
        end

        def should_send?(now = monotonic_now)
          return false unless enabled?
          return true unless @last_sent_at

          now - @last_sent_at >= interval
        end

        # Called from the event loop after each iteration. Business events
        # (+was_events+) deliberately do not suppress probing: a peer that
        # stopped answering must be detected even while unrelated IO keeps
        # the loop busy.
        def send_as_needed(_was_events)
          return unless enabled?
          return if @session.closed?
          return if rekey_in_progress?

          now = monotonic_now
          return unless should_send?(now)

          if keepalive_maxcount > 0 && unresponded_count >= keepalive_maxcount
            error { "Timeout, server #{@session.host} not responding. Missed #{unresponded_count} keepalives." }
            reset
            raise Net::SSH::Timeout, "Timeout, server #{@session.host} not responding."
          end

          send_keepalive(now)
        end

        private

        def monotonic_now
          @clock.call
        end

        def send_keepalive(now)
          info { "sending keepalive #{unresponded_count}" }
          @session.send_global_request("keepalive@openssh.com") do |_success, _response|
            keepalive_response
          end
          @outstanding << now
          @last_sent_at = now
        end

        # Invoked with the ordered reply to the oldest outstanding probe.
        def keepalive_response
          if @outstanding.empty?
            # The session was closed or has timed out since the probe was
            # sent; a late reply must not resurrect liveness state.
            debug { "keepalive response arrived after close or timeout; ignoring" }
            return
          end

          @outstanding.shift
          debug { "keepalive response successful. Missed #{unresponded_count} keepalives" }
        end

        def reset
          @outstanding.clear
          @last_sent_at = nil
        end

        # Global requests must not be sent while a key exchange is pending,
        # and replies cannot arrive then either, so probing (and the timeout
        # it feeds) waits for the rekey to finish.
        def rekey_in_progress?
          algorithms = @session.transport.algorithms
          !algorithms.nil? && algorithms.pending?
        end
      end
    end
  end
end
