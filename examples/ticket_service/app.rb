# frozen_string_literal: true

require 'json'
require 'omniauth'
require 'rack/session/cookie'

require_relative 'lib/ticket_service/policy_registry'
require_relative 'lib/ticket_service/permission_view'
require_relative 'lib/ticket_service/audit_log'
require_relative 'lib/ticket_service/providers'

module TicketService
  # Tenant is derived from the registered strategy (provider), never from
  # a user-supplied claim: strategy registration decides which tenant a
  # login belongs to.
  PROVIDER_TENANTS = {
    'alpha_directory' => 'alpha',
    'beta_directory' => 'beta'
  }.freeze

  # The only approved export source: tenant alpha, extra-claims layer,
  # key "role", value "ticket_exporter". Tenant beta has no registration,
  # so beta logins can never obtain the export permit — no matter what
  # their (identical) claims say or how profile fields are merged.
  def self.build_registry
    PolicyRegistry.new.register(
      tenant: 'alpha', operation: :export_tickets,
      layer: :extra, key: 'role', value: 'ticket_exporter'
    )
  end

  def self.build_app(registry: build_registry, audit_log: AuditLog.new)
    app = App.new(registry: registry, audit_log: audit_log)

    Rack::Builder.new do
      use Rack::Session::Cookie, secret: 'ticket-service-demo-secret-' + '0' * 48

      use OmniAuth::Builder do
        # Demo only: the fictional providers confirm identities inline, so
        # the authenticity-token form round-trip is disabled. Real apps
        # must keep the default protection.
        configure { |config| config.request_validation_phase = nil }
        provider TicketService::Providers::AlphaDirectory
        provider TicketService::Providers::BetaDirectory
      end

      run app
    end.to_app
  end

  # Rack endpoint behind the OmniAuth middleware.
  class App
    def initialize(registry:, audit_log:)
      @registry = registry
      @audit_log = audit_log
    end

    def call(env)
      # OmniAuth hands the confirmed auth hash to the app on the callback
      # leg (for these fictional providers, on the request path itself).
      return login_callback(env) if env['omniauth.auth']

      request = Rack::Request.new(env)

      case [request.request_method, request.path_info]
      in ['GET', '/'] then home
      in ['GET', '/profile'] then profile(env)
      in ['GET', '/permits/export'] then export_permit(env)
      in ['GET', '/tickets'] then tickets(env)
      in ['POST', '/tickets/export'] then export_tickets(env)
      else respond(404, 'text/plain', 'not found')
      end
    end

    private

    def home
      respond(200, 'text/html', <<~HTML)
        <h1>Ticket Service</h1>
        <form method="post" action="/auth/alpha_directory"><button>Log in via Alpha Directory</button></form>
        <form method="post" action="/auth/beta_directory"><button>Log in via Beta Directory</button></form>
      HTML
    end

    def login_callback(env)
      auth = env['omniauth.auth']
      return respond(401, 'text/plain', 'authentication failed') unless auth

      session = env['rack.session']
      session['auth'] = auth.to_h
      redirect('/profile')
    end

    # Existing behavior, unchanged: the profile view merges user info with
    # extra claims (extra wins on duplicate keys). This merge is display
    # sugar only and plays no part in permit decisions.
    def profile(env)
      auth = current_auth(env)
      return respond(401, 'text/plain', 'not logged in') unless auth

      merged = auth.fetch('info', {}).merge(auth.fetch('extra', {}))
      respond(200, 'application/json', JSON.pretty_generate(
        provider: auth['provider'],
        uid: auth['uid'],
        merged_profile: merged
      ))
    end

    # The optional permission view. Login state and permit state are
    # reported separately, so "logged in but permit unavailable/denied" is
    # distinguishable from "logged in and permitted" and "not logged in".
    def export_permit(env)
      auth = current_auth(env)
      return respond(200, 'application/json', JSON.generate(authenticated: false, permit: nil)) unless auth

      decision = permission_view(env).decision(:export_tickets)
      respond(200, 'application/json', JSON.pretty_generate(
        authenticated: true,
        permit: decision.to_h.merge(granted: decision.granted?)
      ))
    end

    def tickets(env)
      return respond(401, 'text/plain', 'not logged in') unless current_auth(env)

      respond(200, 'text/html', <<~HTML)
        <h1>Tickets</h1>
        <ul><li>#1 Printer on fire</li><li>#2 VPN flaky</li></ul>
        <form method="post" action="/tickets/export"><button>Export tickets</button></form>
      HTML
    end

    # Triggered from the low-level tickets page. Every attempt — granted
    # or not — is audited with the tenant and the effective claim layer.
    def export_tickets(env)
      auth = current_auth(env)
      return respond(401, 'text/plain', 'not logged in') unless auth

      decision = permission_view(env).decision(:export_tickets)
      entry = @audit_log.record(
        decision: decision,
        provider: auth['provider'], uid: auth['uid'], name: auth.dig('info', 'name')
      )

      if decision.granted?
        respond(200, 'text/csv', "id,title\n1,Printer on fire\n2,VPN flaky\n",
                'x-audit-status' => entry.status.to_s)
      else
        respond(403, 'application/json', JSON.pretty_generate(
          error: 'export_not_permitted',
          permit: decision.to_h
        ))
      end
    end

    def permission_view(env)
      auth = current_auth(env)
      PermissionView.new(auth, tenant: PROVIDER_TENANTS.fetch(auth['provider']), registry: @registry)
    end

    def current_auth(env)
      env['rack.session']['auth']
    end

    def redirect(location)
      [302, { 'location' => location, 'content-type' => 'text/plain' }, []]
    end

    def respond(status, content_type, body, extra_headers = {})
      [status, { 'content-type' => content_type }.merge(extra_headers), [body]]
    end
  end
end
