# 读策略合并评审：跳过规则 × 动作别名 × 拒绝 reason

多套读策略（`DocumentPolicy` / `ReportPolicy` / `InvoicePolicy`）合并为一套
带通用前置检查的 `MergedReadPolicy` 的上线前评审与可执行证据。

## 运行

```sh
ruby merge_review/check_merge_safety.rb        # 上线前检查，全部通过时退出码 0
ruby merge_review/entry_point_differences.rb   # 各调用入口的可观察差异演示
```

（`vendor/` 下的 `ruby-next` 仅为离线环境的空 shim：Ruby ≥ 3.4 原生支持
ActionPolicy 用到的全部语法；生产环境使用真正的 gem，行为一致。）

## 一、三个机制是怎样合在一起的（代码依据）

1. **别名先于 pre_check 解析**。`authorize!`/`allowed_to?`/`apply` 都先走
   `resolve_rule`（`lib/action_policy/policy/aliases.rb:31`），再进
   `PreCheck#run_pre_checks`（`lib/action_policy/policy/pre_check.rb:104`）。
   所以 `pre_check ..., only: :preview?` 在 `alias_rule :preview?, to: :show?`
   存在时**永不命中**——过滤器看到的是 `:show?`。合并策略时按旧规则名写的
   only/except 清单必须按解析后的目标规则重写（检查 E2/E3 给出活证据）。
2. **skip_pre_check 作用于子类副本**。`pre_checks` 在继承时被 `dup`
   （`pre_check.rb:147`），子类跳过不影响父类；无参 `skip_pre_check` 整体删除，
   带 `only:/except:` 则是在副本上收窄（语义与字面直觉相反，需逐个核对）。
3. **别名会被同名方法静默删除**（`aliases.rb:70` 的 `method_added`）。合并后
   若把旧别名实现成了真方法，别名消失，依赖别名兜底的调用方行为改变。
4. **`default_rule :manage?` 来自 `Policy::Defaults`**
   （`lib/action_policy/policy/defaults.rb:16`）：继承 `ActionPolicy::Base` 的
   策略对**任意未知规则不抛 UnknownRule**，而是回落 `manage?` 并照常执行
   pre_check。与 allow! 型 pre_check 组合即"未声明动作被放行"——旧体系里
   `DocumentPolicy` 的 admin 对 `wipe?` 也是 allow。合并时若新策略不带同样的
   兜底委托，就会产生**未归因的收缩**；若新加了 allow! 型通用前置检查，则是
   **权限扩大**（对照组 F 演示了 20 处）。
5. **reason 只存在于结果对象通道**。`deny!`/`allow!` 底层是
   `throw :policy_fulfilled`，只在 `apply_r` 的 catch 内有效；直接调用规则
   方法会抛 `UncaughtThrowError` 且绕过全部 pre_check。
6. **委托合并 reason 需要 `inline_reasons: true`**
   （`lib/action_policy/policy/reasons.rb:190`）。默认只记录 `(子策略, 规则)`，
   子策略内部 `deny! :not_issuer` 这类具体 reason 会丢失；开启后子策略的
   FailureReasons 完整并入，客户端看到的标识符（`invoice` 等）保持不变。

## 二、上线前证据（check_merge_safety.rb）

对 8 类用户 × 6 条记录 × 4 个规则 = 192 个判定，逐格比对旧策略集合与合并策略：

- **A1/A2 无扩大**：`merged=allow ⇒ legacy=allow`；UnknownRule 边界一致。
- **B1/B2 收缩全部归因**：新增拒绝必须带 `merged_read: [:suspended_user]`
  reason（即来自 allowlist 化的通用前置检查），且确实发生（非死代码）。
- **C1 reason 兼容**：旧策略给出的 reason 标识符合并后全部保留
  （被通用前置检查短路的停用账号除外——这是已归因的可观察差别）。
- **D1–D7 逐项对齐**：子类跳过（admin 普通文档放行 / 机密文档被拒 /
  top clearance 放行）、旧别名 `preview?` 判定一致且不向非 Report 类型扩散、
  拒绝 reason 及 details 与旧策略逐字节一致。
- **E1–E3 pre_check 过滤器 lint**：正式策略无死过滤器；lint 能识别
  "only 引用别名"陷阱并有行为证据。
- **F 阴性对照**：故意加入 `allow!` 型通用前置检查的变体被矩阵判定为
  20 处扩大——证明检查有鉴别力，不是永远通过。

## 三、不同外部调用入口上的可观察安全差别

（`entry_point_differences.rb` 可复现）

- **直接调用规则方法 `policy.show?`**：绕过 pre_check（admin 直通丢失，
  返回 false），对含 `deny!`/`allow!` 的策略直接抛 `UncaughtThrowError`。
  任何"图方便直接调方法"的入口都与框架入口判定不一致。
- **`authorize!`**：抛 `ActionPolicy::Unauthorized`，异常携带
  `result.reasons.details`；Controller 内还有 `verify_authorized`
  after_action 兜底（漏调 `authorize!` 会报错）。
- **`allowed_to?`（视图/helper 常用）**：只剩布尔值，reason 被丢弃；
  且不增加 `authorize_count`，动作里只调它会让 `verify_authorized` 报错
  （失败方向是安全的）。
- **`allowance_to` / `apply_r`**：返回结果对象，reason 完整——需要向
  前端展示拒绝原因的入口必须走这里。
- **Channel（`lib/action_policy/rails/channel.rb`）**：没有任何
  `verify_authorized` 类兜底，忘记授权完全静默——合并切换期间建议对
  Channel 入口加临时审计日志。
- **合并策略自身的短路**：停用账号被通用 pre_check 拒绝时，子策略 reason
  （如 `invoice: [:not_issuer]`）不再产生，客户端只能看到
  `merged_read: [:suspended_user]`——这是有意的、已归因的差别。

## 四、文件

- `legacy_policies.rb` — 三套旧策略：子类跳过、旧别名、拒绝 reason 的实例
- `merged_policy.rb` — 过渡策略（通用 deny-only 前置检查 + 委托旧策略 +
  `inline_reasons` 保留 reason + `manage?` 兜底委托）
- `check_merge_safety.rb` — 上线前可执行检查（CI 可接入，退出码 0/1）
- `entry_point_differences.rb` — 入口差异演示
