# frozen-string-literal: true

class Roda
  module RodaPlugins
    # The conditional_sessions plugin loads the sessions plugin.  However,
    # it only allows sessions if the block passed to the plugin returns
    # truthy.  The block is evaluated in request context. This is designed for
    # use in applications that want to use sessions for some requests,
    # and want to be sure that sessions are not used for other requests.
    # For example, if you want to make sure that sessions are not used for
    # requests with paths starting with +/static+, you could do:
    #
    #   plugin :conditional_sessions, secret: ENV["SECRET"] do
    #     !path_info.start_with?('/static')
    #   end
    #
    # Then the request +session+, +session_created_at+, and +session_updated_at+ methods
    # raise a RodaError exception when sessions are not allowed.  The request
    # +persist_session+ and route scope +clear_session+ methods do nothing when
    # sessions are not allowed.
    #
    # Individual routes can also opt out of sessions for the rest of the
    # request by calling +no_sessions!+ (or its alias +sessionless!+) before
    # any code can load the session.  This is useful for public health check
    # and preview endpoints that must never read or write the session cookie,
    # even if the conditional block would otherwise allow sessions:
    #
    #   route do |r|
    #     r.on "public" do
    #       r.on "health" do
    #         r.no_sessions!
    #         "OK"
    #       end
    #     end
    #   end
    #
    # +no_sessions!+ stores the sessionless marker in the request environment,
    # so it also applies when the request is delegated to another Roda app with
    # +r.run+.  Other Roda apps using conditional_sessions will see the marker
    # and skip session persistence for the request as well.
    #
    # The following request methods allow the behavior to be verified in tests
    # or from surrounding code:
    #
    # +sessionless?+ :: Whether the request was explicitly marked sessionless.
    # +use_sessions?+ :: Whether sessions are allowed for the request.
    # +session_loaded?+ :: Whether session data was loaded into the request
    #                      environment under this app's session env key,
    #                      either by this app or an outer app.
    # +session_persist_called?+ :: Whether +persist_session+ was called for the
    #                              request, even if it did nothing.
    # +session_persisted?+ :: Whether a session cookie was actually written or
    #                         deleted for the response.
    #
    # The same information is stored in the request environment under
    # <tt>roda.conditional_sessions.*</tt> keys, so middleware or tests can
    # verify the behavior after the request has been handled:
    #
    # <tt>roda.conditional_sessions.sessionless</tt> :: The sessionless marker.
    # <tt>roda.conditional_sessions.persist_called</tt> :: Set when
    #   +persist_session+ is called.
    # <tt>roda.conditional_sessions.persisted</tt> :: Set when
    #   +persist_session+ changes the Set-Cookie response header.
    #
    # A sessionless request never calls +persist_session+ from the sessions
    # plugin's after processing, so neither environment key is set for it
    # unless the application explicitly calls +persist_session+, in which case
    # +persist_called+ is set but +persisted+ remains unset because no cookie
    # is written.
    #
    # If +no_sessions!+ is called after the session has already been loaded,
    # it still marks the request as sessionless so the loaded session cannot be
    # written back, but it also raises a RodaError, since the guarantee that
    # the session was not loaded can no longer be met.
    module ConditionalSessions
      # Environment key used to share the sessionless marker between Roda apps
      # handling the same request.
      SESSIONLESS_ENV_KEY = 'roda.conditional_sessions.sessionless'.freeze
      # Environment key set when persist_session is called.
      PERSIST_CALLED_ENV_KEY = 'roda.conditional_sessions.persist_called'.freeze
      # Environment key set when persist_session changes the response cookie.
      PERSISTED_ENV_KEY = 'roda.conditional_sessions.persisted'.freeze
      private_constant :SESSIONLESS_ENV_KEY, :PERSIST_CALLED_ENV_KEY, :PERSISTED_ENV_KEY

      # Pass all options to the sessions block, and use the block to define
      # a request method for whether sessions are allowed.  The block is only
      # evaluated if the request has not been marked sessionless.
      def self.load_dependencies(app, opts=OPTS, &block)
        app.plugin :sessions, opts
        app::RodaRequest.class_exec do
          define_method(:_roda_conditional_sessions_allowed?, &block)
          private :_roda_conditional_sessions_allowed?

          def use_sessions?
            !@env[SESSIONLESS_ENV_KEY] && _roda_conditional_sessions_allowed?
          end
        end
      end

      module InstanceMethods
        # Do nothing if not using sessions.
        def clear_session
          super if @_request.use_sessions?
        end

        private

        # Skip the sessions plugin's after processing entirely for explicitly
        # sessionless requests. This avoids loading or persisting the session,
        # and also covers responses generated by the error_handler plugin.
        # Requests where sessions are merely disallowed by the conditional
        # block keep the previous behavior, where persist_session is called but
        # does nothing.
        def _roda_after_50__sessions(res)
          super unless @_request.sessionless?
        end
      end

      module RequestMethods
        # Mark the remainder of the request as not using sessions.  The marker
        # is stored in the request environment so it applies across +r.run+
        # boundaries.  If the session was already loaded, mark the request
        # first (so it cannot be written back) and then raise, because the
        # sessionless guarantee can no longer be met.
        def no_sessions!
          env = @env
          env[SESSIONLESS_ENV_KEY] = true

          if session_loaded?
            raise RodaError, "no_sessions! called on request with an already loaded session"
          end

          nil
        end
        alias sessionless! no_sessions!

        # Whether the request was explicitly marked sessionless.
        def sessionless?
          !!@env[SESSIONLESS_ENV_KEY]
        end

        # Whether session data has been loaded into the request environment.
        # This is also true if an outer Roda app loaded the session.
        def session_loaded?
          @env.key?(roda_class.sessions_config.env_key)
        end

        # Raise RodaError if not using sessions.
        def session
          raise RodaError, "session called on request not using sessions" unless use_sessions?
          super
        end

        # Raise RodaError if not using sessions.
        def session_created_at
          raise RodaError, "session_created_at called on request not using sessions" unless use_sessions?
          super
        end

        # Raise RodaError if not using sessions.
        def session_updated_at
          raise RodaError, "session_updated_at called on request not using sessions" unless use_sessions?
          super
        end

        # Track whether persistence was called, before checking if it is allowed.
        # This makes it possible to verify that sessionless requests do not
        # reach persistence at all, including from surrounding middleware.
        def persist_session(headers, session)
          env = @env
          env[PERSIST_CALLED_ENV_KEY] = true
          return unless use_sessions?

          before = headers[RodaResponseHeaders::SET_COOKIE]
          before = before.dup if before.is_a?(Array)

          super

          after = headers[RodaResponseHeaders::SET_COOKIE]
          env[PERSISTED_ENV_KEY] = true if before != after
          nil
        end

        # Whether persist_session was called for the request, even if it was a
        # no-op or did not end up writing a cookie.
        def session_persist_called?
          !!@env[PERSIST_CALLED_ENV_KEY]
        end

        # Whether persist_session wrote or deleted the session cookie for the
        # response.
        def session_persisted?
          !!@env[PERSISTED_ENV_KEY]
        end
      end
    end

    register_plugin(:conditional_sessions, ConditionalSessions)
  end
end
