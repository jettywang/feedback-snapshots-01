# oslo.policy 策略别名移除迁移评审与可执行演示

本目录用**假凭据 + 最小 YAML 配置**，完整演示移除站点里几条老策略别名（`DeprecatedRule`
改名 / `deprecated_for_removal` 待删项）的安全迁移路径。所有授权结论都来自真实的
`oslo_policy.policy.Enforcer.authorize()` 调用与官方 CLI，不依赖 Keystone、网络或真实密钥。

## 1. 三条代码路径（注册 → 加载 → 授权）

- **注册（policy-in-code）**：服务启动时调用 `enforcer.register_defaults(...)`，把
  `RuleDefault/DocumentedRuleDefault` 放进 `registered_rules`。改名关系通过构造参数
  `deprecated_rule=DeprecatedRule(name=旧别名, check_str=旧默认)` 声明；整条待删规则用
  `deprecated_for_removal=True` 声明。重复注册会抛 `DuplicatePolicyError`
  （`oslo_policy/policy.py:1161`）。
- **加载（站点文件叠加）**：`load_rules()` 先把 YAML 解析进 `file_rules`/`rules`
  （`_record_file_rules`，`policy.py:902`），再遍历 `registered_rules` 补默认值。
  别名的兼容逻辑集中在 `_handle_deprecated_rule`（`policy.py:729`）：
  - 站点文件里出现旧别名且其 check 与旧默认不同、且新名未被覆盖时，**旧别名的 check
    被直接搬给新规则**（`policy.py:776-782`）；
  - 若只是默认 check 变化且 `enforce_new_defaults=False`，返回
    `OrCheck([新check, 旧check])` 做平滑过渡（`policy.py:796-807`）；
  - `enforce_new_defaults=True`（本仓库版本的**默认值**，见 `opts.py`）时不再 OR 旧 check。
- **授权（求值）**：业务代码调 `authorize()`（先校验已注册，否则 `PolicyNotRegistered`，
  `policy.py:1209`）→ `enforce()` → `_checks._check`。规则名缺失时**fail-closed**：
  字符串规则名走 `policy.py:1087-1090`，`rule:` 引用走 `_checks.py:335-337`。
  `RoleCheck` 对 `creds['roles']` 做大小写不敏感匹配（`_checks.py:358`）。

## 2. 顺序结论：先改站点配置，后升级服务

**必须先迁移站点 `policy.yaml`（别名键 → 规范名键），在旧服务上验证授权矩阵不变，再升级
移除别名的新服务。** 原因是加载期的别名搬运只存在于“仍注册着 `DeprecatedRule` 的旧服务”。

- 先改配置（本演示 Phase A→B）：规范名在旧、新两版里都已注册，同一份文件两版都能加载，
  授权矩阵可在升级前逐格比对。
- 先升级服务（反例 `wrong_order_orphan_aliases.yaml`）：新服务的 `registered_rules` 里
  不再有别名，文件里的旧键变成**未注册的孤儿规则**——运行期不报错也不生效，规则回落到
  代码内新默认，授权被静默改写；`oslopolicy-validator` 才能事后报
  `Unknown rule found`（`generator.py:445`）。

## 3. 会“悄悄改变允许用户”的组合（迁移评审清单）

以下组合都不会在请求时报错，但授权结果会变，必须逐格核对：

1. **收紧型改名 + 站点覆盖的恰好是旧默认 check**：别名 check 等于 `DeprecatedRule.check`
   时，搬运分支不触发（`policy.py:778`）。END=True 下旧角色用户被静默拒绝。演示中
   Phase A（END=True）`widget:create` 对 `legacy-user(viewer)` 为 DENY；END=False 时
   因 OrCheck 为 ALLOW——同一个文件，仅一个配置位不同结果相反。
2. **`enforce_new_defaults` 翻档**：False→True（或新版本默认即 True）会去掉
   `OrCheck` 旧分支，所有“只满足旧 check、不满足新 check”的用户丢失权限
   （`policy.py:796-807`）。
3. **先升级服务留下孤儿别名**：见第 2 节反例。`legacy-user` 的 widget 权限、`ops-user`
   的 gizmo 权限双双静默丢失，`thing:admin` 变成未注册。
4. **`deprecated_for_removal` 规则被删除**：升级后该名不再注册，文件覆盖被静默忽略；
   旧服务阶段它已会打印 “may be silently ignored in the future”（`policy.py:711-727`），
   且与默认相同的覆盖会被 `list-redundant` 标为冗余。
5. **文件里写了 `rule:不存在的规则`**：解析不报错，求值时 fail-closed 拒绝；
   `check_rules()`/validator 会标 undefined（`policy.py:682`、`generator.py:434`）。
6. **策略文件缺失或 YAML 损坏**：文件缺失时静默回落到全部代码默认（`policy.py:599-608`）；
   YAML 语法错误在加载时抛 `ValueError`——已运行进程保留上一份内存规则，重启才会失败。

## 4. 三阶段演示（两个“保留旧解释”阶段 + 一个收尾阶段）

假服务两版注册集见 `fake_service.py`：OLD 含
`widget:create(别名 widget:post)`、`gizmo:update(别名 gizmo:edit)`、待删 `thing:admin`；
NEW 只剩两个规范名。假用户：`legacy-user(viewer,legacy-ops)`、`ops-user(ops-gizmo)`、
`member-user(member)`、`admin-user(admin)`、`nobody-user(reader)`。

### Phase A — 旧服务 + 站点仍用别名（保留旧解释，现状基线）
- 文件 `policies/phaseA_aliases.yaml`，命令：`.venv/bin/python demo/run_demo.py phaseA`
- 证据：加载期三条弃用告警（两条改名 + 一条 for-removal）；END=True 与 END=False
  各跑一次，展示 OrCheck 开关对 `legacy-user` 的真实差异。
- 回滚点：本阶段不改任何东西；基线本身即回滚目标，备份在
  `backups/phaseA_aliases.yaml.bak`。

### Phase B — 旧服务 + 站点已改写为规范名（保留旧解释，升级前缓冲区）
- 文件 `policies/phaseB_canonical.yaml`，命令：`.venv/bin/python demo/run_demo.py phaseB`
- 改名可由官方工具自动完成（只改键、保留 check 字符串，`generator.py:575-597`）：
  `.venv/bin/oslopolicy-policy-upgrade --namespace fakesvc_old --policy demo/policies/phaseA_aliases.yaml`
- 证据：END 取 True/False 的授权矩阵与 Phase A 的**目标语义逐格一致**（widget 对
  legacy ALLOW、gizmo 对 ops/admin ALLOW）；别名弃用告警消失，仅剩 for-removal 提示；
  `oslopolicy-validator --namespace fakesvc_old` 对该文件 rc=0。
- 回滚点：把 `phaseA_aliases.yaml` 拷回并 `load_rules(force_reload=True)`；
  `run_demo.py reload` 场景演示了同一进程内热替换与回滚，备份
  `backups/phaseA_aliases.yaml.bak`。

### Phase C — 新服务（别名已移除）+ 清理死覆盖（收尾）
- 文件 `policies/phaseC_cleanup.yaml`，命令：`.venv/bin/python demo/run_demo.py phaseC`
- 证据：两个规范名授权与 Phase B 完全一致；`thing:admin` 显示
  `NOT-REGISTERED`（`authorize` 抛 `PolicyNotRegistered`），其文件覆盖已删除；
  `oslopolicy-validator --namespace fakesvc_new` rc=0。
- 注意：`widget:create`/`gizmo:update` 的覆盖与代码默认**不同**，是承重配置，不能删；
  只有与默认相同的 `thing:admin` 才是 `list-redundant` 认定的可删冗余。
- 回滚点：服务回退到 OLD 发布 + 恢复 Phase B 文件（`backups/phaseB_canonical.yaml.bak`）。

### 反例与异常
- `.venv/bin/python demo/run_demo.py wrong-order`：先升级的静默锁死，配合
  `run_cli_evidence.sh` 第 1 步 validator rc=1。
- `.venv/bin/python demo/run_demo.py exceptions`：undefined 规则 fail-closed、
  坏 YAML 抛 `ValueError`、备份恢复后授权回到正常值。

## 5. 复跑方式

```bash
.venv/bin/python demo/run_demo.py all          # 三阶段 + 反例 + 热回滚 + 异常注入
./demo/run_cli_evidence.sh                     # 官方 CLI 证据（validator/upgrade/...）
```

CLI 依赖本 venv 已注册的 `fakesvc_old/fakesvc_new` entry point（通过
`.venv/lib/python3.12/site-packages/` 下的 `fakesvc.pth` 与
`fakesvc-0.0.1.dist-info/` 提供，未改动 oslo.policy 库代码）。最近一次完整输出留存于
`demo_output.txt` 与 `cli_evidence.txt`。
