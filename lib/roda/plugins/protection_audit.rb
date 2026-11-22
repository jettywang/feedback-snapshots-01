# frozen-string-literal: true

#
class Roda
  module RodaPlugins
    # The protection_audit plugin adds an optional audit handoff for Roda's
    # protection plugins, so the application can record which protection
    # stage actually ran for a request and what the result was.  This is
    # useful for security duty and audit logging, where you need to know at
    # which layer the decision on a request was made.
    #
    # The plugin is loaded with a block (or the +:handler+ option) that is
    # called with each audit event:
    #
    #   plugin :protection_audit do |event|
    #     AuditLog.record(event)
    #   end
    #
    # Each event is a frozen hash with exactly two entries:
    #
    # :source :: The protection stage that made the decision, as a symbol
    #            (e.g. +:host_authorization+ or +:bearer_token+).
    # :action :: The result of the stage, as a symbol
    #            (e.g. +:allowed+ or +:denied+).
    #
    # Events intentionally do not contain any request content (such as the
    # Host header value, tokens, paths, or parameters), so sensitive request
    # data is never written to the audit log.
    #
    # Events are recorded in the order the protection stages actually run.
    # In addition to being passed to the handler, they are stored per
    # request and can be accessed via +r.protection_audit_events+ (or
    # <tt>env['roda.protection_audit_events']</tt>).
    #
    # = Integration with other plugins
    #
    # The host_authorization plugin automatically emits
    # <tt>:host_authorization</tt> events (<tt>:allowed</tt> or
    # <tt>:denied</tt>) when the protection_audit plugin is loaded.  No
    # other behavior of host_authorization changes, and no events are
    # emitted if protection_audit is not loaded.
    #
    # Applications can emit events for their own protection checks (such as
    # bearer token validation) via +protection_audit_event+:
    #
    #   plugin :bearer_token
    #   plugin :host_authorization, 'www.example.com'
    #   plugin :protection_audit do |event|
    #     AuditLog.record(event)
    #   end
    #
    #   route do |r|
    #     check_host_authorization!
    #
    #     unless r.bearer_token == expected_token
    #       protection_audit_event(:bearer_token, :denied)
    #       response.status = 401
    #       next 'invalid token'
    #     end
    #     protection_audit_event(:bearer_token, :allowed)
    #
    #     # ...
    #   end
    module ProtectionAudit
      def self.configure(app, opts=OPTS, &block)
        unless handler = (block || opts[:handler])
          raise RodaError, "must provide a block or :handler option when loading the protection_audit plugin"
        end
        app.opts[:protection_audit_handler] = handler
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :protection_audit_handler)
      end

      module RequestMethods
        # The protection audit events recorded for the current request, in
        # the order the protection stages actually ran.
        def protection_audit_events
          @env['roda.protection_audit_events'] ||= []
        end
      end

      module InstanceMethods
        # Record a protection audit event with the given source (the
        # protection stage) and action (the result of the stage).  Only the
        # source and action are recorded; request content must not be
        # included in either.
        def protection_audit_event(source, action)
          event = {source: source, action: action}.freeze
          @_request.protection_audit_events << event
          self.class.protection_audit_handler.call(event)
          nil
        end
      end
    end

    register_plugin(:protection_audit, ProtectionAudit)
  end
end
