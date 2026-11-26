# OmniAuth 自定义 strategy 迁移：request / callback / test_mode 执行边界实验

本实验用纯 Rack 替身（不发任何真实网络请求）把这版 OmniAuth（见 lib/omniauth/strategy.rb
与 lib/omniauth/strategy/test_mode.rb）的两条运行路径、自定义 form、进入策略前停止和
失败保护全部跑成可重复的事件序列，用于替换公司自定义 OAuth strategy 时的迁移判定。

## 如何运行

```sh
# 详细事件轨迹（人工核对 hook 顺序与响应产生位置）
./.feedback/bundle-env exec ruby experiment/run.rb

# 机器可判定的 12 条迁移检查（CI/预发布可直接用，非零退出即阻断）
./.feedback/bundle-env exec ruby experiment/assertions.rb
```

- 依赖全部来自仓库自带的 .feedback/vendor，无需联网、无需 bundle install。
- 每个场景结束都会调用 reset_config，把 OmniAuth.config 全局状态还原，互不串扰。
- “提供方”是 Experiment::Provider（experiment/harness.rb）：request 阶段 302 到一个
  假的 provider.test，callback 阶段从回调参数构建 auth hash；test_mode 下提供方被
  mock_auth 整体替换。

## 三种入口的真实分发边界

Strategy#call（lib/omniauth/strategy.rb:86）先判断 passthrough?，否则 dup 后 call!。
call!（lib/omniauth/strategy.rb:97）要求 rack.session，随后：

1. OmniAuth.config.test_mode 为真 -> mock_call!（test_mode.rb:9），完全不经过
   phase_call / request_call / callback_call。
2. 否则 phase_call（strategy.rb:116）按优先级分发：
   options_call? -> request_call? -> on_callback_path? -> other_phase -> 交给 app。
3. 都不命中（路径不属于本策略，或方法不在 allowed_request_methods）-> @app.call(env)，
   即“进入策略之前停止”。

关键判定都在真实代码里：

- request_call?（strategy.rb:136）= 在 request 路径 且 方法属于
  allowed_request_methods（默认仅 :post，lib/omniauth.rb:47）。GET 落到 request 路径
  时该判定为假，请求直接透传给 app（场景 D2）。
- 真实 request 顺序 request_call（strategy.rb:168）：
  setup_phase -> host 校验 -> request_validation_phase -> 写 session['omniauth.params']
  -> before_request_phase -> request_response -> after_request_phase。
- test_mode request 顺序 mock_request_call（test_mode.rb:21）：
  setup_phase -> request_validation_phase -> 写 params -> before_request_phase
  -> store_origin -> redirect(callback_url) -> after_request_phase。
  注意它不调用 strategy 的 request_phase，因此不会跳到真实提供方，也不会执行
  remember_sign_in。
- 真实 callback callback_call（strategy.rb:224）：
  setup_phase -> host 校验 -> recall_sign_in -> 设 origin/params ->
  before_callback_phase -> callback_phase（构建 auth_hash 后 call_app!）。
- test_mode callback mock_callback_call（test_mode.rb:38）：
  setup_phase -> 取 origin/params -> OmniAuth.mock_auth_for(name) ->
  before_callback_phase -> 成功 call_app!，或 mock 为 Symbol 时 fail!。
  它不调用 strategy 的 callback_phase / auth_hash，身份是注入的。

## 事件对照表（实际运行 run.rb 的结果）

“身份来源”一列区分：哪些检查通过只是因为测试直接给了 mock 身份，哪些真正走过应用验证或
提供方回调。

| 场景 | 入口/模式 | 实际调用的 hook（按顺序） | 策略方法 | 响应产生位置 | 状态 | 身份来源 |
|---|---|---|---|---|---|---|
| A-req | 真实 request POST | setup -> request_validation(接受) -> before_request -> after_request | request_phase（remember_sign_in+redirect） | Strategy#redirect 302 到 provider | 302 | 尚未产生身份 |
| A-cb | 真实 callback GET | setup -> before_callback | callback_phase -> auth_hash（uid/info/credentials/extra 块）-> call_app! | 下游 app 收到 omniauth.auth 后返回 | 200 APP_OK 42 | 提供方回调参数，真实验证 |
| B-req | test_mode request POST | setup -> request_validation(接受) -> before_request -> after_request | 无 request_phase（mock_request_call 直接 redirect(callback_url)） | mock_request_call 内 302 到本站 callback | 302 | 无提供方 |
| B-cb | test_mode callback GET | setup -> before_callback | 无 callback_phase；mock_auth_for(:provider) 注入 | mock_callback_call 设 omniauth.auth 后 call_app! | 200 APP_OK 42 | mock_auth 直接注入，无验证 |
| B2 | test_mode + 伪造 token POST | setup -> request_validation(拒绝) | 无 | fail! -> FailureEndpoint 302 /auth/failure | 302 | 被拦 |
| C | 自定义 form（Rack endpoint）POST | setup -> request_validation(接受) -> before_request -> after_request | 无 request_phase；request_response 调 options.form.call(env) | form endpoint 自身返回 HTML | 200 自定义表单 | 尚未产生身份 |
| C2 | form: true POST | 同上 | 无 request_phase；request_response 走 call_app! | 下游 app 自己渲染 | 200 APP_PLAIN | 尚未产生身份 |
| D1 | 无关路径 GET | 无任何 hook/phase | 无（passthrough? 直接 @app.call） | 下游 app | 200 APP_PLAIN | - |
| D2 | request 路径 GET（默认仅 POST） | 无 | request_call? 为假，落到 @app.call | 下游 app | 200 APP_PLAIN | - |
| E | 真实 + 伪造 token POST | setup -> request_validation(拒绝) | request_phase 未到达 | fail!(:authenticity_error) -> FailureEndpoint | 302 /auth/failure?message=authenticity_error | 升级后保护拦截 |
| F | test_mode mock 失败 Symbol | setup -> before_callback | 无；mock 为 Symbol -> fail! | FailureEndpoint 302 | 302 invalid_credentials | 配置的失败标签，非真实拒识 |
| G | OPTIONS 预检 | before_options | options_call 返回 Allow | options_call（strategy.rb:161） | 200 Allow: POST | - |

### 两条得到相同 auth hash 的路径（A-cb 与 B-cb）

run.rb 用深比较断言 real_hash == mock_hash（输出 SAME AUTH HASH? true，键集合均为
credentials/extra/info/provider/uid）。相同结果，边界完全不同：

- 真实路径 A-cb：调用了 strategy#callback_phase 与 auth_hash，数据来自回调里的
  code/state/uid，并且 state 经 remember_sign_in / callback_sign_in_key 用
  Rack::Utils.secure_compare 复核（sign_ins.rb:63）。响应在下游 app（call_app! 之后）。
- test_mode B-cb：callback_phase / auth_hash 一次都没跑；OmniAuth.mock_auth_for
  直接把预置 AuthHash 放进 env。响应同样在下游 app，但身份未经任何提供方或应用校验。

结论：“测试里能拿到身份”只证明 env 装配与下游 app 行为正确，不证明 strategy 的
request_phase、state 校验、token 交换或 CSRF 保护在生产可用。

## 哪些通过来自 mock，哪些来自真实验证

- 仅由 mock 身份支撑（test_mode，test_mode.rb）：B 全部、F。它们不触达提供方，也不执行
  strategy 自己的 request_phase / callback_phase。
- 走过真实应用/提供方边界：A（真实 redirect、真实回调参数、auth_hash 块、state 复核、
  下游 app）、C/C2（真实 form 渲染分支）、E（真实 CSRF 拒绝）。
- 容易误判的一点：仓库测试套件 spec/helper.rb:26 全局设置
  OmniAuth.config.request_validation_phase = nil，即默认关闭 CSRF 验证。因此普通
  request 规格通过，并不代表 CSRF 保护生效。本实验在 B2/E 显式挂回
  AuthenticityTokenProtection 才观测到拒绝。

## 用失败证明升级后的保护仍在（场景 E，必须看到的观察）

仅当以下观察同时成立，才能证明 v2 的 POST-only + CSRF 保护在新 strategy 上仍生效；
任何一条缺失都说明保护被绕过或迁移有误：

1. 响应是 302 且 Location 含 /auth/failure，env['omniauth.error.type'] ==
   :authenticity_error（来自 authenticity_token_protection.rb:29 抛出的
   AuthenticityError，经 strategy.rb:178 的 rescue 调 fail!）。
2. 事件序列里 request_validation_phase REJECTED 出现在 before_request_phase、
   request_phase 之前。
3. strategy#request_phase 从未被调用（没有 provider redirect）。
4. 被拒请求的参数没有写进会话：session['omniauth.params'] 不存在。这对应
   CHANGELOG 2.1.x 的修复——验证先于写 session，攻击者参数无法落地。

对照场景 F：test_mode 也能产出 302 /auth/failure，但那是预置 Symbol 触发的
invalid_credentials，发生在 callback、且不带 authenticity_error，不能用来证明
CSRF 保护。只有 E（真实模式 + 伪造 token + request 阶段）才是有效证据。

## 保留有效旧接入的选择条件

替换自定义 strategy 时，满足以下条件的旧接入应保留其行为，不要在迁移中改变：

- HTTP 方法：旧接入若用 GET 链接发起登录，必须改成带 authenticity_token 的 POST
  表单（默认 allowed_request_methods = [:post]）。只有显式评估 CVE-2015-9284 风险后，
  才把 :get 加回，并处理 warn_if_using_get_on_request_path 的告警。
- CSRF 验证器：非 Rails 用默认 OmniAuth::AuthenticityTokenProtection；Rails 换成
  Rails 感知的验证器（README 推荐 omniauth-rails_csrf_protection 或带 key: :_csrf_token
  的实例）。token 的 session key / param 名必须与应用现有表单一致，否则旧表单会全部落 E。
- 自定义 form：旧代码若依赖“request 阶段先 call 到 app 渲染表单”，v2 已移除该隐式
  行为，必须显式用 :form（Rack endpoint 或 true）。C/C2 给出两种等价接法，且
  after_request_phase 依旧触发，依赖该 hook 的旧逻辑可保留。
- hook 顺序契约：依赖 before_request_phase 在验证之后、after_request_phase
  在响应之后、before_callback_phase 在 callback_phase 之前的旧逻辑，顺序与本版一致，
  可保留；但 test_mode 下不会跑 strategy 自身 phase，hook 仍跑——不要把策略方法放进这些
  hook 里假定其只在生产执行。
- host 与 origin：旧接入若依赖可伪造 Host 头拼 callback_url，需设置
  allowed_hosts 或 full_host（hosts.rb）；依赖 omniauth.origin 跳转的，注意
  javascript:/data:/vbscript: 与非 String origin 现被丢弃。
- 多标签登录（state/PKCE）：旧 OAuth2 接入若依赖 remember_sign_in，默认只保留
  最近 3 个 sign-in、每个 params 不超过 512 字节（sign_ins.rb，2.4.x 可调）。超出会静默丢
  params，需在迁移时核对会话容量。
- passthrough 性能契约：定义了 other_phase 或用 lambda 形式 request_path /
  callback_path 的旧 strategy 无法走快速透传（dispatch_by_path? 为假），保留这类
  写法即接受每条无关请求都 dup 一次的开销。

## 12 条迁移检查（assertions.rb，全部应 PASS）

1. 真实 request：合法 token -> 302 到提供方。
2. 真实 request：验证先于 before_request_phase，再先于 request_phase。
3. 伪造 token：302 /auth/failure + :authenticity_error。
4. 伪造 token：不触达 request_phase，参数不落地。
5. GET 到 request 路径：透传 app，无任何 phase hook。
6. 真实与 test_mode callback 产出深相等的 auth hash；且仅真实路径跑 callback_phase。
7. test_mode 下伪造 token 仍被拒绝（保护未因测试模式被旁路）。
8. mock 失败 Symbol 不产 omniauth.auth；自定义 form 跳过提供方但保留 after hook；
   无关路径零 hook 透传。
