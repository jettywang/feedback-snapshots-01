# encoding: utf-8
# frozen_string_literal: true
RSpec.describe "restricted failure dispatch" do
  before(:all) do
    load_strategies

    Warden::Strategies.add(:restricted_custom) do
      def authenticate!
        custom!([418, {"Content-Type" => "text/plain", "X-Custom" => "custom-header"}, ["Custom Stuff"]])
      end
    end

    Warden::Strategies.add(:restricted_redirect) do
      def authenticate!
        redirect!("/sign-in", {}, :message => "redirected")
      end
    end
  end

  before(:each) do
    Warden::Manager._before_failure.clear
  end

  after(:each) do
    Warden::Manager._before_failure.clear
  end

  let(:marker) { "synthetic-canary-258" }

  # Receipts captured inside the independently maintained page component.
  let(:page_receipts) { [] }

  let(:page) do
    receipts = page_receipts
    lambda do |env|
      context = Warden::FailureContext.from_env(env)
      receipts << { :env => env, :context => context }
      body = [
        "category=#{context.category}",
        "action=#{context.action}",
        "return_to=#{context.return_to.inspect}"
      ].join("\n")
      [401, {"Content-Type" => "text/plain"}, [body]]
    end
  end

  # One manager serves all failure kinds. The application picks which kind of
  # failure the request should produce.
  let(:application) do
    lambda do |env|
      case env['PATH_INFO']
      when '/deny'
        env['warden'].authenticate!(:failz)
      when '/locked'
        env['warden'].authenticate!(:failz)
      when '/custom'
        env['warden'].authenticate!(:restricted_custom)
      when '/redirect'
        env['warden'].authenticate!(:restricted_redirect)
      end
      [200, {"Content-Type" => "text/plain"}, ["OK"]]
    end
  end

  let(:manager) do
    Warden::Manager.new(application, :failure_app => nil) do |config|
      config.restricted_failure_app = page
    end
  end

  let(:deny_app) { lambda { |env| env['warden'].authenticate!(:failz) } }

  def request(path, opts = {})
    env = env_with_params(path, {}, opts.delete(:headers) || {})
    env['rack.session'] = opts.delete(:session) || {}
    manager.call(env)
  end

  def last_receipt
    page_receipts.last
  end

  it "routes a strategy rejection, a reclassification and a custom response through one manager" do
    Warden::Manager.before_failure do |_env, opts|
      opts[:failure_category] = :account_locked if opts[:attempted_path] == "/locked"
    end

    denied = request("/deny")
    expect(denied.first).to eq(401)
    expect(last_receipt[:context].category).to eq(:authentication_failed)

    locked = request("/locked")
    expect(locked.first).to eq(401)
    expect(last_receipt[:context].category).to eq(:account_locked)

    receipts_before_custom = page_receipts.length
    custom = request("/custom")
    expect(custom).to eq([418, {"Content-Type" => "text/plain", "X-Custom" => "custom-header"}, ["Custom Stuff"]])
    expect(page_receipts.length).to eq(receipts_before_custom)
  end

  it "leaves the redirect contract untouched" do
    response = request("/redirect")
    expect(response.first).to eq(302)
    expect(response[1]['Location']).to eq("/sign-in")
    expect(response.last).to eq(["redirected"])
    expect(page_receipts).to be_empty
  end

  it "keeps before_failure on the trusted side while the page only gets allowlisted values" do
    trusted = []
    Warden::Manager.before_failure do |env, opts|
      opts[:failure_category] = :account_locked
      opts[:internal_note] = marker
      opts[:return_to] = "/staff/orders?token=#{marker}"
      trusted << {
        :session => env['rack.session'],
        :header => env['HTTP_X_MARKER'],
        :query => env['QUERY_STRING'],
        :note => opts[:internal_note]
      }
    end

    response = request("/deny?token=#{marker}",
                       :headers => {'HTTP_X_MARKER' => marker},
                       :session => {'probe' => marker})

    expect(trusted.length).to eq(1)
    expect(trusted.first[:session]['probe']).to eq(marker)
    expect(trusted.first[:header]).to eq(marker)
    expect(trusted.first[:query]).to include(marker)
    expect(trusted.first[:note]).to eq(marker)

    context = last_receipt[:context]
    expect(context.category).to eq(:account_locked)
    expect(context.return_to).to eq("/staff/orders")
    expect(context.to_h.values.map(&:to_s).join).not_to include(marker)
    expect(response.last.join).not_to include(marker)
  end

  it "does not hand the page the proxy, session, headers, query or callback extras" do
    Warden::Manager.before_failure do |_env, opts|
      opts[:failure_category] = :account_locked
      opts[:internal_note] = marker
    end

    response = request("/deny?token=#{marker}",
                       :headers => {'HTTP_X_MARKER' => marker},
                       :session => {'probe' => marker})

    public_env = last_receipt[:env]
    expect(public_env).not_to have_key('warden')
    expect(public_env).not_to have_key('rack.session')
    expect(public_env).not_to have_key('warden.options')
    expect(public_env.keys.grep(/\AHTTP_/)).to be_empty
    expect(public_env['QUERY_STRING']).to eq('')
    expect(public_env['PATH_INFO']).to eq('/unauthenticated')
    expect(public_env['REQUEST_METHOD']).to eq('GET')
    expect(public_env.keys).to include('rack.input', 'rack.errors', 'SERVER_NAME')

    context = last_receipt[:context]
    expect(context.to_h.keys).to contain_exactly(:action, :category, :return_to)
    expect(context[:internal_note]).to be_nil
    expect(context).to be_frozen
    expect(response.last.join).not_to include(marker)
  end

  it "does not reuse a failure category from an earlier request" do
    Warden::Manager.before_failure do |_env, opts|
      opts[:failure_category] = :account_locked if opts[:attempted_path] == '/locked'
      opts[:internal_note] = marker
    end

    request("/locked")
    first = last_receipt[:context]
    request("/deny")
    second = last_receipt[:context]

    expect(first.category).to eq(:account_locked)
    expect(second.category).to eq(:authentication_failed)
    expect(second[:internal_note]).to be_nil
  end

  it "only reclassifies through a safe identifier and ignores arbitrary values" do
    Warden::Manager.before_failure do |_env, opts|
      opts[:failure_category] = "Contains #{marker} and spaces"
    end
    request("/deny")
    expect(last_receipt[:context].category).to eq(:authentication_failed)
  end

  describe "return_to approval" do
    it "drops external, protocol-relative and traversal locations" do
      ["https://example.com/staff", "//example.com/staff", "/staff/../admin"].each do |candidate|
        page_receipts.clear
        Warden::Manager._before_failure.clear
        Warden::Manager.before_failure { |_env, opts| opts[:return_to] = candidate }
        request("/deny")
        expect(last_receipt[:context].return_to).to be_nil
      end
    end

    it "strips the query string from an otherwise approved in-site location" do
      Warden::Manager.before_failure { |_env, opts| opts[:return_to] = "/staff?token=#{marker}" }
      request("/deny")
      expect(last_receipt[:context].return_to).to eq("/staff")
    end

    it "supports an application allowlist" do
      restricted = Warden::Manager.new(deny_app, :failure_app => nil) do |config|
        config.restricted_failure_app = page
        config.approved_return_paths = ["/staff"]
      end

      env = env_with_params("/admin/orders")
      env['rack.session'] = {}
      restricted.call(env)
      expect(last_receipt[:context].return_to).to be_nil

      page_receipts.clear
      env = env_with_params("/staff/orders")
      env['rack.session'] = {}
      restricted.call(env)
      expect(last_receipt[:context].return_to).to eq("/staff/orders")
    end
  end

  describe "the existing full failure app" do
    it "still receives the complete environment and options" do
      seen = nil
      full = lambda do |env|
        seen = env
        [401, {}, ["full"]]
      end
      env = env_with_params("/staff")
      env['rack.session'] = {'probe' => marker}
      Warden::Manager.new(deny_app, :failure_app => full).call(env)

      expect(seen).to equal(env)
      expect(seen['rack.session']['probe']).to eq(marker)
      expect(seen['warden.options'][:attempted_path]).to eq("/staff")
    end
  end
end
