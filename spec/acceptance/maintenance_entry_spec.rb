# encoding: utf-8
# frozen_string_literal: true

# 维护入口（Warden 锁 + 失败应用）接入验收。
#
# 只使用合成用户 SyntheticUser 与假策略 :fake_grant / :fake_deny。
# 不访问数据库、不调用真实认证服务；每个用例都会把真实调用、钩子触发
# 与代理状态写入 $maintenance_log，运行输出即验收记录。
#
# 运行：
#   BUNDLE_FROZEN=true .feedback/bundle-env exec rspec -Ilib spec/acceptance/maintenance_entry_spec.rb

class SyntheticUser
  attr_reader :id

  def initialize(id)
    @id = id
  end

  def ==(other)
    other.is_a?(SyntheticUser) && other.id == id
  end
end

$maintenance_log = []

Warden::Strategies.add(:fake_grant) do
  def authenticate!
    $maintenance_log << [:strategy_run, :fake_grant, scope]
    success!(SyntheticUser.new("u-#{scope}"))
  end
end

Warden::Strategies.add(:fake_deny) do
  def authenticate!
    $maintenance_log << [:strategy_run, :fake_deny, scope]
    fail!("fake policy denied")
  end
end

RSpec.describe "维护入口：Warden 锁与失败应用接入" do
  APPROVED = :maint
  OTHER = :admin

  def log(*entry)
    $maintenance_log << entry
  end

  def session_env(keys)
    env_with_params("/origin", {}, "rack.session" => keys)
  end

  def strategy_runs
    $maintenance_log.select { |entry| entry.first == :strategy_run }
  end

  def failure_entries
    $maintenance_log.select { |entry| entry.first == :failure }
  end

  before(:all) do
    @saved = {}
    %i(_on_request _after_set_user _after_failed_fetch _before_failure).each do |kind|
      @saved[kind] = Warden::Manager.send(kind).dup
    end

    Warden::Manager.serialize_into_session(APPROVED) { |user| user.id }
    Warden::Manager.serialize_from_session(APPROVED) do |key|
      $maintenance_log << [:session, :deserialize, APPROVED, key]
      key.to_s.start_with?("u-") ? SyntheticUser.new(key) : nil
    end
    Warden::Manager.serialize_into_session(OTHER) { |user| user.id }
    Warden::Manager.serialize_from_session(OTHER) do |key|
      $maintenance_log << [:session, :deserialize, OTHER, key]
      key.to_s.start_with?("u-") ? SyntheticUser.new(key) : nil
    end

    Warden::Manager.on_request do |_proxy|
      log(:hook, :on_request)
    end
    Warden::Manager.after_set_user do |_user, _auth, opts|
      log(:hook, :after_set_user, opts[:event], opts[:scope])
    end
    Warden::Manager.after_failed_fetch do |_user, _auth, opts|
      log(:hook, :after_failed_fetch, opts[:scope])
    end
    Warden::Manager.before_failure do |env, opts|
      log(:hook, :before_failure, opts[:action], env["PATH_INFO"])
    end
  end

  after(:all) do
    @saved.each { |kind, saved| Warden::Manager.send(kind).replace(saved) }
    %i(maint_serialize maint_deserialize admin_serialize admin_deserialize).each do |name|
      Warden::SessionSerializer.send(:remove_method, name) if Warden::SessionSerializer.method_defined?(name)
    end
  end

  before { $maintenance_log.clear }
  after do
    $maintenance_log.each { |entry| puts "  RECORD #{entry.inspect}" }
  end

  # --- 场景一：锁定前已有请求级策略结果（缓存） -------------------------
  it "已缓存策略：锁后已核准 scope 继续返回缓存用户，另一 scope 不再执行策略" do
    app = lambda do |env|
      warden = env["warden"]
      first = warden.authenticate(:fake_grant, :scope => APPROVED)
      second = warden.authenticate(:fake_grant, :scope => APPROVED)
      log(:state, :cached_identity, first && first.id, second && second.id)
      log(:state, :winning_before_lock, warden.winning_strategy && warden.winning_strategy.scope)

      warden.lock!

      kept = warden.authenticate(:fake_deny, :scope => APPROVED)
      blocked = warden.authenticate(:fake_grant, :scope => OTHER)
      log(:state, :after_lock_approved, kept && kept.id)
      log(:state, :after_lock_other, blocked.inspect)
      log(:state, :other_authenticated?, warden.authenticated?(OTHER))
      [200, { "Content-Type" => "text/plain" }, ["OK"]]
    end

    result = setup_rack(app).call(env_with_params)
    expect(result.first).to eq(200)
    expect(strategy_runs).to eq([[:strategy_run, :fake_grant, APPROVED]])
    expect($maintenance_log).to include([:state, :cached_identity, "u-maint", "u-maint"])
    expect($maintenance_log).to include([:state, :after_lock_approved, "u-maint"])
    expect($maintenance_log).to include([:state, :after_lock_other, "nil"])
    expect($maintenance_log).to include([:hook, :after_set_user, :authentication, APPROVED])
  end

  # --- 场景二：锁定前已有持久化用户（会话恢复） -------------------------
  it "已持久化用户：锁不阻止会话恢复，已核准 scope 仍可继续" do
    app = lambda do |env|
      warden = env["warden"]
      warden.lock!
      user = warden.authenticate!(:fake_grant, :scope => APPROVED)
      log(:state, :resumed, user && user.id)
      [200, { "Content-Type" => "text/plain" }, ["OK"]]
    end

    result = setup_rack(app).call(session_env("warden.user.maint.key" => "u-maint"))
    expect(result.first).to eq(200)
    expect(strategy_runs).to be_empty
    expect($maintenance_log).to include([:session, :deserialize, APPROVED, "u-maint"])
    expect($maintenance_log).to include([:hook, :after_set_user, :fetch, APPROVED])
    expect($maintenance_log).to include([:state, :resumed, "u-maint"])
  end

  # --- 场景三：没有任何身份 ---------------------------------------------
  it "没有身份：锁后 authenticate! 抛 :warden，由失败应用提交终态" do
    app = lambda do |env|
      env["warden"].lock!
      env["warden"].authenticate!(:fake_grant, :scope => APPROVED)
      [200, { "Content-Type" => "text/plain" }, ["UNREACHABLE"]]
    end

    result = setup_rack(app).call(env_with_params)
    expect(result.first).to eq(401)
    expect(result.last).to eq(["You Fail!"])
    expect(strategy_runs).to be_empty
    expect($maintenance_log).to include([:hook, :after_failed_fetch, APPROVED])
    expect($maintenance_log).to include([:hook, :before_failure, "unauthenticated", "/unauthenticated"])
  end

  it "锁后清理策略缓存不会清除已恢复的用户" do
    app = lambda do |env|
      warden = env["warden"]
      warden.lock!
      warden.clear_strategies_cache!(:scope => APPROVED)
      user = warden.user(APPROVED)
      log(:state, :after_clear_cache, user && user.id, warden.winning_strategies.keys)
      [200, { "Content-Type" => "text/plain" }, ["OK"]]
    end

    result = setup_rack(app).call(session_env("warden.user.maint.key" => "u-maint"))
    expect(result.first).to eq(200)
    expect(strategy_runs).to be_empty
    expect($maintenance_log).to include([:state, :after_clear_cache, "u-maint", []])
  end

  it "未认证时 session 抛 NotAuthenticated，不进入失败分派" do
    raised = nil
    app = lambda do |env|
      begin
        env["warden"].session(APPROVED)
      rescue => error
        raised = error
      end
      [200, { "Content-Type" => "text/plain" }, ["OK"]]
    end

    result = setup_rack(app).call(env_with_params)
    expect(result.first).to eq(200)
    expect(raised).to be_a(Warden::NotAuthenticated)
    log(:state, :session_raised, raised.class.name)
    expect(failure_entries).to be_empty
  end

  # --- 顺序差异 A：先核对会话、再限制策略 -------------------------------
  it "顺序 A（先会话后锁）：会话先恢复，锁只影响后续策略" do
    app = lambda do |env|
      warden = env["warden"]
      user = warden.user(APPROVED)
      log(:state, :read_before_lock, user && user.id)
      warden.lock!
      log(:state, :after_lock, warden.user(APPROVED) && warden.user(APPROVED).id)
      [200, { "Content-Type" => "text/plain" }, ["OK"]]
    end

    result = setup_rack(app).call(session_env("warden.user.maint.key" => "u-maint"))
    expect(result.first).to eq(200)
    expect($maintenance_log).to include([:state, :read_before_lock, "u-maint"])
    expect($maintenance_log).to include([:state, :after_lock, "u-maint"])
  end

  # --- 顺序差异 B：先限制策略、再决定读取范围 ---------------------------
  it "顺序 B（先锁后读）：锁不限制会话读取，未核准 scope 也会被恢复" do
    keys = {
      "warden.user.maint.key" => "u-maint",
      "warden.user.admin.key" => "u-admin"
    }
    app = lambda do |env|
      warden = env["warden"]
      warden.lock!
      approved = warden.user(APPROVED)
      leaked = warden.user(OTHER)
      log(:state, :locked_read, approved && approved.id, leaked && leaked.id)
      log(:state, :other_authenticated?, warden.authenticated?(OTHER))
      [200, { "Content-Type" => "text/plain" }, ["OK"]]
    end

    result = setup_rack(app).call(session_env(keys))
    expect(result.first).to eq(200)
    expect($maintenance_log).to include([:state, :locked_read, "u-maint", "u-admin"])
    expect($maintenance_log).to include([:state, :other_authenticated?, true])
    expect($maintenance_log).to include([:session, :deserialize, OTHER, "u-admin"])
  end

  # --- 锁不拦 set_user，也不拦非 bang 的静默失败 ------------------------
  it "锁后 set_user 仍可写入身份，且 authenticate 不抛错只返回 nil" do
    app = lambda do |env|
      warden = env["warden"]
      warden.lock!
      warden.set_user(SyntheticUser.new("u-forced"), :scope => APPROVED)
      injected = warden.user(APPROVED)
      silent = warden.authenticate(:fake_grant, :scope => OTHER)
      log(:state, :set_after_lock, injected && injected.id)
      log(:state, :silent_auth, silent.inspect, warden.authenticated?(OTHER))
      log(:state, :persisted_keys, env["rack.session"].keys.sort)
      [200, { "Content-Type" => "text/plain" }, ["OK"]]
    end

    env = env_with_params
    result = setup_rack(app).call(env)
    expect(result.first).to eq(200)
    expect($maintenance_log).to include([:state, :set_after_lock, "u-forced"])
    expect($maintenance_log).to include([:state, :silent_auth, "nil", false])
    expect(env["rack.session"].keys).to include("warden.user.maint.key")
    expect(strategy_runs).to be_empty
  end

  # --- 失败分派：action 的来源 -------------------------------------------
  it "authenticate! 的失败会带上 scope 的 action，裸 throw 的 scope 不会" do
    configurator = lambda do |config|
      config.scope_defaults(APPROVED, :strategies => [:fake_deny], :action => "maint_gate")
      config.scope_defaults(OTHER, :strategies => [:fake_grant], :action => "admin_gate")
    end

    bang_env = env_with_params("/origin")
    bang = setup_rack(lambda do |e|
      e["warden"].lock!
      e["warden"].authenticate!(:fake_grant, :scope => APPROVED)
    end, :configurator => configurator).call(bang_env)
    log(:state, :bang_action, bang_env["PATH_INFO"], bang_env["warden.options"][:action])
    expect(bang.first).to eq(401)
    expect(bang_env["PATH_INFO"]).to eq("/maint_gate")

    bare_env = env_with_params("/origin")
    bare = setup_rack(lambda do |e|
      throw(:warden, :scope => OTHER)
    end, :configurator => configurator).call(bare_env)
    log(:state, :bare_action, bare_env["PATH_INFO"], bare_env["warden.options"][:action])
    expect(bare.first).to eq(401)
    expect(bare_env["PATH_INFO"]).to eq("/unauthenticated")
  end

  # --- 同一 Rack 请求内的主动终止 ---------------------------------------
  it "应用主动 throw :warden 与策略失败走同一条失败分派路径" do
    env = env_with_params("/origin")
    app = lambda do |e|
      e["warden"].authenticate(:fake_grant, :scope => APPROVED)
      throw(:warden, :action => :maintenance, :message => "app stop")
    end

    result = setup_rack(app).call(env)
    expect(result.first).to eq(401)
    expect(env["PATH_INFO"]).to eq("/maintenance")
    expect(env["warden.options"][:attempted_path]).to eq("/origin")
    expect(env["warden.options"][:message]).to eq("app stop")
    expect($maintenance_log).to include([:hook, :before_failure, :maintenance, "/maintenance"])
    expect(strategy_runs).to eq([[:strategy_run, :fake_grant, APPROVED]])
  end

  # --- 同一 Rack 请求内未捕获异常 ---------------------------------------
  it "应用抛出未捕获异常时不会进入失败应用，异常原样上抛" do
    env = env_with_params("/origin")
    app = lambda do |e|
      e["warden"].lock!
      raise "unhandled application error"
    end

    expect { setup_rack(app).call(env) }.to raise_error(RuntimeError, "unhandled application error")
    expect(failure_entries).to be_empty
    expect(env["warden.options"]).to be_nil
    expect(env["PATH_INFO"]).to eq("/origin")
  end

  # --- 失败分派与响应提交边界 -------------------------------------------
  it "响应提交：下游 401 由 intercept_401 接管，custom_failure! 与应用自建 403 不被改写" do
    intercepted = setup_rack(lambda { |_e| [401, {}, ["app-401"]] }).call(env_with_params)
    log(:state, :intercepted_401, intercepted.first, intercepted.last)
    expect(intercepted.last).to eq(["You Fail!"])

    passthrough = setup_rack(lambda do |e|
      e["warden"].custom_failure!
      [401, {}, ["app-401"]]
    end).call(env_with_params)
    log(:state, :custom_failure, passthrough.first, passthrough.last)
    expect(passthrough.last).to eq(["app-401"])

    forbidden = setup_rack(lambda { |_e| [403, {}, ["app-403"]] }).call(env_with_params)
    log(:state, :passthrough_403, forbidden.first, forbidden.last)
    expect(forbidden.first).to eq(403)
    expect(forbidden.last).to eq(["app-403"])

    rack_401 = setup_rack(lambda { |_e| Rack::Response.new(["app-401"], 401, {}) }).call(env_with_params)
    log(:state, :rack_response_401, rack_401.class.name, rack_401.first, rack_401.last)
    expect(rack_401.first).to eq(401)
    expect(rack_401.last).to eq(["You Fail!"])

    rack_200 = setup_rack(lambda { |_e| Rack::Response.new(["app-200"], 200, {}) }).call(env_with_params)
    log(:state, :rack_response_200, rack_200.class.name, rack_200.status)
    expect(rack_200).to be_a(Rack::Response)
    expect(rack_200.status).to eq(200)
  end
end
