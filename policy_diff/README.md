# oslo.policy 升级前策略差异检查工具

面向 OpenStack 服务升级 `policy-in-code` 默认策略的离线检查工具。输入本地的
升级前后默认策略、站点 `policy.yaml` 和一组凭据样例，输出：

- 每个动作（action）对每个凭据样例的**升级前 / 升级后允许结果**；
- 结果变化分类：权限新增（granted）、权限收回（revoked）、不变；
- 每个生效规则的**来源（provenance）**和文件行号，并能用 `--rule` 解释
  某个动作的有效策略是怎么一步步解析出来的；
- 重命名动作（`DeprecatedRule`）的前后名称配对。

工具直接复用仓库中的真实 `oslo_policy.policy.Enforcer` 完成规则装载、弃用
规则处理和鉴权计算，不自行实现一套“近似”策略引擎。

## 运行时安全保证

当前部署的 enforcer 完全不受影响：

1. 每次分析都 `new` 一个独立的 `oslo_config.cfg.ConfigOpts` 和
   `policy.Enforcer`，不写入也不读取服务的全局配置目录、环境变量；
2. 站点策略文件只以只读方式打开；无策略文件时在临时目录创建空文件，
   快照构建后立即删除（见 `engine._materialize_policy_file`）；
3. 所有 `enforce()` 都在这些一次性 enforcer 上执行，服务进程内的规则集
   不会被加载、替换或触发重载。

## 输入文件格式

### 1. 注册默认策略 YAML（升级前 / 升级后各一份）

描述服务在代码里注册的 `RuleDefault`。每条规则支持两种写法：

```yaml
# 裸字符串写法
simple_action: 'role:admin'

# 带弃用元数据的映射写法
widget:create:
  check_str: 'role:member'
  scope_types: [project]            # 可选
  deprecated_rule:
    # 只给 check_str：同名规则的默认 check 变化
    check_str: 'role:admin'
    deprecated_reason: 'member 即可创建'
    deprecated_since: '2026.2'

widget:share:
  check_str: 'role:member'
  deprecated_rule:
    # 给 name + check_str：规则改名
    name: 'old_widget:share'
    check_str: 'role:admin'
    deprecated_reason: '命名空间统一'
    deprecated_since: '2026.2'
```

### 2. 站点策略文件（可选）

标准 oslo.policy YAML，即部署目录下的 `policy.yaml` 本地副本：

```yaml
widget:list: 'role:owner'
old_widget:share: 'rule:admin_or_owner'
```

升级前后可以给不同文件（`--before-policy-file` /
`--after-policy-file`），用于模拟“清理弃用规则后再上线”。

### 3. 凭据样例 JSON

支持两种形态，可混放：

- Keystone token introspection 形态（与 `oslopolicy-checker` 一致）：
  顶层为 `{"token": {"roles": [...], "user": ..., "project"|"domain"|"system": ...}}`；
- 已经拍平的 policy creds 字典：`{"roles": ["member"], "project_id": ...}`。

参数接受文件列表或目录（目录读取其中全部 `*.json`，按文件名排序）。

### 4. target JSON（可选）

不传时默认使用第一个凭据的 `user_id` / `project_id`，与
`oslopolicy-checker` 的缺省行为一致。

## 三种样例场景

`policy_diff_examples/` 下的样例覆盖题目要求的三种情况：

| 场景 | 动作 | 有效策略来源 |
| --- | --- | --- |
| 保留站点覆盖 | `widget:list` | 升级前后都来自 `policy/policy.yaml` 的 `file_override`，注册默认变化不生效 |
| 接受新默认 | `widget:create` | 策略文件不写该动作，升级后来自新的 `registered_default`（`role:admin` → `role:member`） |
| 仍沿用弃用规则 | `widget:share`（旧名 `old_widget:share`） | 策略文件保留旧名，升级后标记为 `deprecated_name_override`，oslo.policy 继续套用站点旧值 |

另外 `widget:delete` 演示 `scope_types` 收紧后系统域 token 被拒绝；
`widget:rename` 演示纯改名配对。

## 使用方法

在仓库根目录、用自带 venv 执行：

```bash
.venv/bin/python -m policy_diff \
  --before-defaults policy_diff_examples/defaults/policy-before.yaml \
  --after-defaults policy_diff_examples/defaults/policy-after.yaml \
  --before-policy-file policy_diff_examples/policy/policy.yaml \
  --credentials policy_diff_examples/credentials \
  --target policy_diff_examples/targets/widget.json
```

模拟“清理策略文件后接受新默认”：

```bash
.venv/bin/python -m policy_diff \
  --before-defaults policy_diff_examples/defaults/policy-before.yaml \
  --after-defaults policy_diff_examples/defaults/policy-after.yaml \
  --before-policy-file policy_diff_examples/policy/policy.yaml \
  --after-policy-file policy_diff_examples/policy/policy-cleaned.yaml \
  --credentials policy_diff_examples/credentials
```

解释单个动作的有效策略来源（含 `rule:` 引用链）：

```bash
.venv/bin/python -m policy_diff \
  --before-defaults policy_diff_examples/defaults/policy-before.yaml \
  --after-defaults policy_diff_examples/defaults/policy-after.yaml \
  --before-policy-file policy_diff_examples/policy/policy.yaml \
  --credentials policy_diff_examples/credentials \
  --rule widget:share
```

查看升级过渡期的 OR 兼容策略（`enforce_new_defaults=False` 时新默认与
弃用 check 做逻辑或）：

```bash
.venv/bin/python -m policy_diff \
  --before-defaults policy_diff_examples/defaults/policy-before.yaml \
  --after-defaults policy_diff_examples/defaults/policy-after.yaml \
  --credentials policy_diff_examples/credentials \
  --no-after-enforce-new-defaults \
  --rule widget:create
```

机器可读输出加 `--format json`，其中每个动作都带完整 `trace` 引用链和
`provenance` / `source_line`。

## 来源（provenance）取值

| 标识 | 含义 |
| --- | --- |
| `file_override` | 动作名直接出现在站点策略文件，覆盖注册默认 |
| `registered_default` | 策略文件未提及，使用 policy-in-code 注册默认 |
| `deprecated_name_override` | 新名未覆盖，但弃用旧名在策略文件中，oslo.policy 沿用旧名的站点值 |
| `deprecated_or_compat` | `enforce_new_defaults=False` 时，新默认与弃用 check 组成 `OrCheck` 的过渡行为 |
| `fail_closed` | 动作未注册且无兜底规则，oslo.policy 拒绝（fail closed） |

## 测试

```bash
.venv/bin/python -m pytest policy_diff/tests -q
```

测试覆盖三类样例场景、OR 兼容判定、scope 拒绝、fail-closed、规则引用链
解释，以及“策略文件不被修改 / 两个快照使用彼此隔离的 enforcer 与 conf”
的运行时安全保证。
