require_relative "../spec_helper"

describe "protection_audit plugin" do
  it "requires a block or :handler option" do
    app
    proc{app.plugin :protection_audit}.must_raise Roda::RodaError
  end

  it "records host denial, token denial after host pass, and full success in actual order" do
    events = []
    app do |r|
      check_host_authorization!

      unless r.bearer_token == 'valid-token'
        protection_audit_event(:bearer_token, :denied)
        response.status = 401
        next 'invalid token'
      end
      protection_audit_event(:bearer_token, :allowed)

      'ok'
    end
    app.plugin :bearer_token
    app.plugin :host_authorization, 'www.example.com'
    app.plugin(:protection_audit){|event| events << event}

    # Host rejected: only the host authorization stage runs.
    status('HTTP_HOST'=>'evil.example.com').must_equal 403
    events.must_equal [{source: :host_authorization, action: :denied}]

    # Host passes, token invalid: host stage allowed, then token stage denied.
    events.clear
    status('HTTP_HOST'=>'www.example.com', 'HTTP_AUTHORIZATION'=>'Bearer wrong-token').must_equal 401
    events.must_equal [
      {source: :host_authorization, action: :allowed},
      {source: :bearer_token, action: :denied}
    ]

    # Full success: both stages allowed, in order.
    events.clear
    status('HTTP_HOST'=>'www.example.com', 'HTTP_AUTHORIZATION'=>'Bearer valid-token').must_equal 200
    events.must_equal [
      {source: :host_authorization, action: :allowed},
      {source: :bearer_token, action: :allowed}
    ]
    body('HTTP_HOST'=>'www.example.com', 'HTTP_AUTHORIZATION'=>'Bearer valid-token').must_equal 'ok'
  end

  it "does not include request content in audit events" do
    events = []
    app do |r|
      check_host_authorization!
      protection_audit_event(:bearer_token, r.bearer_token == 'valid-token' ? :allowed : :denied)
      'ok'
    end
    app.plugin :bearer_token
    app.plugin :host_authorization, 'www.example.com'
    app.plugin(:protection_audit){|event| events << event}

    status('HTTP_HOST'=>'www.example.com', 'HTTP_AUTHORIZATION'=>'Bearer valid-token').must_equal 200
    status('HTTP_HOST'=>'evil.example.com', 'HTTP_AUTHORIZATION'=>'Bearer valid-token').must_equal 403

    events.each do |event|
      event.keys.sort.must_equal [:action, :source]
      event.frozen?.must_equal true
      event.values.each do |value|
        value.must_be_kind_of Symbol
        value.to_s.wont_include 'www.example.com'
        value.to_s.wont_include 'evil.example.com'
        value.to_s.wont_include 'valid-token'
      end
    end
  end

  it "stores events per request, accessible via r.protection_audit_events and env" do
    app do |r|
      check_host_authorization!
      protection_audit_event(:bearer_token, :allowed)
      r.protection_audit_events.must_equal r.env['roda.protection_audit_events']
      r.protection_audit_events.map{|e| "#{e[:source]}:#{e[:action]}"}.join(',')
    end
    app.plugin :host_authorization, 'www.example.com'
    app.plugin(:protection_audit){|_|}

    body('HTTP_HOST'=>'www.example.com').must_equal 'host_authorization:allowed,bearer_token:allowed'
    body('HTTP_HOST'=>'evil.example.com').must_equal ''
  end

  it "supports the :handler option instead of a block" do
    events = []
    app do |r|
      protection_audit_event(:stage, :allowed)
      'ok'
    end
    app.plugin :protection_audit, handler: proc{|event| events << event}

    body.must_equal 'ok'
    events.must_equal [{source: :stage, action: :allowed}]
  end

  it "does not change host_authorization behavior when protection_audit is not loaded" do
    app do |r|
      check_host_authorization!
      'ok'
    end
    app.plugin :host_authorization, 'www.example.com'

    status('HTTP_HOST'=>'www.example.com').must_equal 200
    body('HTTP_HOST'=>'www.example.com').must_equal 'ok'
    status('HTTP_HOST'=>'evil.example.com').must_equal 403
  end
end
