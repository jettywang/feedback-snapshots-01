# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2022-2023, by Samuel Williams.

require_relative 'abstract/id'

module Rack
  module Session
    # Rack::Session::Pool provides simple cookie based session management.
    # Session data is stored in a hash held by @pool.
    # In the context of a multithreaded environment, sessions being
    # committed to the pool is done in a merging manner.
    #
    # The :drop option is available in rack.session.options if you wish to
    # explicitly remove the session from the session cache.
    #
    # Server-side retention can be declared with two additional options:
    # * :idle_timeout sets the number of seconds a session may go unused
    #   before it is discarded. Each access renews the session, sliding the
    #   window forward.
    # * :absolute_timeout sets the maximum number of seconds a session may
    #   live, counted from its creation, regardless of activity.
    # Expired sessions are deleted from the pool and the next request starts
    # a fresh session with a new id.
    #
    # Sessions stored before retention was enabled carry no timing
    # information. The :legacy_sessions option controls how they are
    # treated on their next access:
    # * :reject cautiously discards them, forcing a fresh session.
    # * :backfill (the default) stamps them with the current time, gradually
    #   bringing them under the retention policy.
    #
    # The :clock option accepts a callable returning the current time, which
    # is useful for testing retention behavior.
    #
    # Example:
    #   myapp = MyRackApp.new
    #   sessioned = Rack::Session::Pool.new(myapp,
    #     :domain => 'foo.com',
    #     :expire_after => 2592000
    #   )
    #   Rack::Handler::WEBrick.run sessioned

    class Pool < Abstract::PersistedSecure
      attr_reader :mutex, :pool
      DEFAULT_OPTIONS = Abstract::ID::DEFAULT_OPTIONS.merge(drop: false, allow_fallback: true)

      def initialize(app, options = {})
        super
        @pool = Hash.new
        @mutex = Mutex.new
        @allow_fallback = @default_options.delete(:allow_fallback)
        @idle_timeout = @default_options.delete(:idle_timeout)
        @absolute_timeout = @default_options.delete(:absolute_timeout)
        @legacy_sessions = @default_options.delete(:legacy_sessions) || :backfill
        @clock = @default_options.delete(:clock) || -> { Time.now }

        unless [:reject, :backfill].include?(@legacy_sessions)
          raise ArgumentError, ":legacy_sessions must be :reject or :backfill"
        end

        @timestamps = Hash.new if retention_enabled?
      end

      def generate_sid(*args, use_mutex: true)
        loop do
          sid = super(*args)
          break sid unless use_mutex ? @mutex.synchronize { @pool.key? sid.private_id } : @pool.key?(sid.private_id)
        end
      end

      def find_session(req, sid)
        @mutex.synchronize do
          if sid and session = get_session_with_fallback(sid)
            return [sid, session] if retain_session?(sid)

            delete_session_entry(sid)
          end

          sid, session = generate_sid(use_mutex: false), {}
          @pool.store sid.private_id, session
          track_session(sid)
          [sid, session]
        end
      end

      def write_session(req, session_id, new_session, options)
        @mutex.synchronize do
          return false unless get_session_with_fallback(session_id)
          @pool.store session_id.private_id, new_session
          track_session(session_id)
          session_id
        end
      end

      def delete_session(req, session_id, options)
        @mutex.synchronize do
          delete_session_entry(session_id)

          unless options[:drop]
            sid = generate_sid(use_mutex: false)
            @pool.store(sid.private_id, {})
            track_session(sid)
            sid
          end
        end
      end

      private

      def get_session_with_fallback(sid)
        @pool[sid.private_id] || (@pool[sid.public_id] if @allow_fallback)
      end

      def retention_enabled?
        !@idle_timeout.nil? || !@absolute_timeout.nil?
      end

      def now
        @clock.call
      end

      # Decide whether the session referenced by sid may be kept, applying
      # the idle and absolute timeouts. Sessions retained are stamped with
      # the current time, sliding the idle window forward. Sessions without
      # timing information are handled according to :legacy_sessions.

      def retain_session?(sid)
        return true unless retention_enabled?

        timestamps = @timestamps[sid.private_id]
        return retain_legacy_session?(sid) unless timestamps

        current = now
        if (@absolute_timeout && current - timestamps[:created_at] >= @absolute_timeout) ||
            (@idle_timeout && current - timestamps[:touched_at] >= @idle_timeout)
          false
        else
          timestamps[:touched_at] = current
          true
        end
      end

      def retain_legacy_session?(sid)
        case @legacy_sessions
        when :backfill
          track_session(sid)
          true
        else
          false
        end
      end

      # Record the current time for sid, preserving the original creation
      # time if the session is already tracked.

      def track_session(sid)
        return unless retention_enabled?

        current = now
        timestamps = @timestamps[sid.private_id]
        if timestamps
          timestamps[:touched_at] = current
        else
          @timestamps[sid.private_id] = {created_at: current, touched_at: current}
        end
      end

      def delete_session_entry(session_id)
        @pool.delete(session_id.public_id)
        @pool.delete(session_id.private_id)
        @timestamps.delete(session_id.private_id) if retention_enabled?
      end
    end
  end
end
