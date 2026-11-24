# A/B 逐步对照表（由 evidence_lab.py 自动生成）

- dynaconf `3.3.6.dev0`（A/B 同版本）；Python `3.12.11`
- dynaconf 来源：`./dynaconf/__init__.py`
- 调查键：`security.require_mfa`；A/B 最终值：`True` / `True`
- A=`no-env`（环境不提供目标变量）；B=`env-same-value`（环境提供同值 `true`）

## 分歧定位（机器可读另见 `out/divergence.json`）

- 首次**输入证据**分歧：`S0` — 进程环境快照（Dynaconf 尚未初始化）
  - A: `{"dynaconf_env": {}}`
  - B: `{"dynaconf_env": {"DYNACONF_SECURITY__REQUIRE_MFA": "true"}}`
- 首次**有效值**分歧：无（两条轨迹每一步的有效值都相同，包括 S5a 的瞬时 false）
- 最终历史中首次**来源槽位**分歧（按 SourceMetadata 对齐，old-first）：`env_global/DYNACONF`，A 值=`—`，B 值=`True`

## 1. 逐步输入 × 有效值对照表

| 步骤 | A 实际收到的输入 | A: leaf 有效值 | B 实际收到的输入 | B: leaf 有效值 | 输入分歧 |
|---|---|---|---|---|---|
| S0 进程环境快照（Dynaconf 尚未初始化） | `实际收到的 DYNACONF_* 环境变量：{}` | `null` | `实际收到的 DYNACONF_* 环境变量：{"DYNACONF_SECURITY__REQUIRE_MFA": "true"}` | `null` | 差异字段: `dynaconf_env` |
| S1 加载本地 JSON 文件 + 初始化期 env loader | `Dynaconf(settings_files=['labwork/security.json'], merge_enabled=True)` | `true` | `Dynaconf(settings_files=['labwork/security.json'], merge_enabled=True)` | `true` | 差异字段: `process_env` |
| S2 运行时嵌套合并（merge=True，新增 policy.mfa_provider，兄弟键保留） | `s.set('SECURITY', {"policy": {"mfa_provider": "totp"}}, merge=True)` | `true` | `s.set('SECURITY', {"policy": {"mfa_provider": "totp"}}, merge=True)` | `true` |  |
| S3 运行时 set 写入与终值相同的值 true | `s.set('security.require_mfa', True)` | `true` | `s.set('security.require_mfa', True)` | `true` |  |
| S4a 同一个 env loader 再次加载（折叠探针第 1 次） | `os.environ['DYNACONF_LAB_PROBE']='pass-1'; env_loader.load(s)` | `true` | `os.environ['DYNACONF_LAB_PROBE']='pass-1'; env_loader.load(s)` | `true` | 差异字段: `dynaconf_env_at_pass` |
| S4b 同一个 env loader 再次加载（折叠探针第 2 次，同 SourceMetadata 槽位） | `os.environ['DYNACONF_LAB_PROBE']='pass-2'; env_loader.load(s)` | `true` | `os.environ['DYNACONF_LAB_PROBE']='pass-2'; env_loader.load(s)` | `true` | 差异字段: `dynaconf_env_at_pass` |
| S5a 绕过 Settings.set 的嵌套属性直改（历史不记录）：先改成 false | `s.security.require_mfa = False` | `false` | `s.security.require_mfa = False` | `false` |  |
| S5b 绕过 Settings.set 的嵌套属性直改：还原为 true（终值与两轨一致） | `s.security.require_mfa = True` | `true` | `s.security.require_mfa = True` | `true` |  |

## 2. 每步完整 `security` 有效值（嵌套合并证据）

| 步骤 | A `security` | B `security` | 相同 |
|---|---|---|---|
| S1 | `{"policy": {"issuer": "corp-local", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | `{"policy": {"issuer": "corp-local", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | ✓ |
| S2 | `{"policy": {"issuer": "corp-local", "mfa_provider": "totp", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | `{"policy": {"issuer": "corp-local", "mfa_provider": "totp", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | ✓ |
| S3 | `{"policy": {"issuer": "corp-local", "mfa_provider": "totp", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | `{"policy": {"issuer": "corp-local", "mfa_provider": "totp", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | ✓ |
| S4a | `{"policy": {"issuer": "corp-local", "mfa_provider": "totp", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | `{"policy": {"issuer": "corp-local", "mfa_provider": "totp", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | ✓ |
| S4b | `{"policy": {"issuer": "corp-local", "mfa_provider": "totp", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | `{"policy": {"issuer": "corp-local", "mfa_provider": "totp", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | ✓ |
| S5a | `{"policy": {"issuer": "corp-local", "mfa_provider": "totp", "min_password_length": 12}, "require_mfa": false, "session_timeout": 30}` | `{"policy": {"issuer": "corp-local", "mfa_provider": "totp", "min_password_length": 12}, "require_mfa": false, "session_timeout": 30}` | ✓ |
| S5b | `{"policy": {"issuer": "corp-local", "mfa_provider": "totp", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | `{"policy": {"issuer": "corp-local", "mfa_provider": "totp", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | ✓ |

## 3. `Settings.set` 边界追踪：入口处实际收到的 value（深拷贝固定）

| 轨迹 | 步骤 | depth | key | 入口 value | 解析来源 | merged 参数 |
|---|---|---:|---|---|---|---|
| A | S1 | 0 | `SECURITY` | `{"policy": {"issuer": "corp-local", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | `json \| labwork/security.json \| m=False` | `empty-sentinel(按配置默认)` |
| A | S2 | 0 | `SECURITY` | `{"policy": {"mfa_provider": "totp"}}` | `set_method \| undefined \| m=True` | `True` |
| A | S3 | 0 | `security.require_mfa` | `true` | `set_method \| undefined \| m=False` | `<not-passed>` |
| A | S3 | 1 | `security` | `{"policy": {"issuer": "corp-local", "mfa_provider": "totp", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | `set_method \| undefined \| m=False` | `empty-sentinel(按配置默认)` |
| A | S4a | 0 | `LAB_PROBE` | `pass-1` | `env_global \| DYNACONF \| m=False` | `empty-sentinel(按配置默认)` |
| A | S4b | 0 | `LAB_PROBE` | `pass-2` | `env_global \| DYNACONF \| m=False` | `empty-sentinel(按配置默认)` |
| B | S1 | 0 | `SECURITY` | `{"policy": {"issuer": "corp-local", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | `json \| labwork/security.json \| m=False` | `empty-sentinel(按配置默认)` |
| B | S1 | 0 | `SECURITY__REQUIRE_MFA` | `true` | `env_global \| DYNACONF \| m=False` | `empty-sentinel(按配置默认)` |
| B | S1 | 1 | `SECURITY` | `{"policy": {"issuer": "corp-local", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | `env_global \| DYNACONF \| m=False` | `empty-sentinel(按配置默认)` |
| B | S2 | 0 | `SECURITY` | `{"policy": {"mfa_provider": "totp"}}` | `set_method \| undefined \| m=True` | `True` |
| B | S3 | 0 | `security.require_mfa` | `true` | `set_method \| undefined \| m=False` | `<not-passed>` |
| B | S3 | 1 | `security` | `{"policy": {"issuer": "corp-local", "mfa_provider": "totp", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | `set_method \| undefined \| m=False` | `empty-sentinel(按配置默认)` |
| B | S4a | 0 | `SECURITY__REQUIRE_MFA` | `true` | `env_global \| DYNACONF \| m=False` | `empty-sentinel(按配置默认)` |
| B | S4a | 1 | `SECURITY` | `{"policy": {"issuer": "corp-local", "mfa_provider": "totp", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | `env_global \| DYNACONF \| m=False` | `empty-sentinel(按配置默认)` |
| B | S4a | 0 | `LAB_PROBE` | `pass-1` | `env_global \| DYNACONF \| m=False` | `empty-sentinel(按配置默认)` |
| B | S4b | 0 | `SECURITY__REQUIRE_MFA` | `true` | `env_global \| DYNACONF \| m=False` | `empty-sentinel(按配置默认)` |
| B | S4b | 1 | `SECURITY` | `{"policy": {"issuer": "corp-local", "mfa_provider": "totp", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}` | `env_global \| DYNACONF \| m=False` | `empty-sentinel(按配置默认)` |
| B | S4b | 0 | `LAB_PROBE` | `pass-2` | `env_global \| DYNACONF \| m=False` | `empty-sentinel(按配置默认)` |

> depth=1 通常是 dotted key 经 `_dotted_set` 重建嵌套 dict 后的重入写入；其 value 是重建后的顶层对象，不一定等于调用方原始输入。

## 4. 最终 `inspect -k security.require_mfa` 历史来源对齐（old-first）

| A# | B# | loader | identifier | env | merged | A value | B value |
|---:|---:|---|---|---|---|---|---|
| 0 | 0 | `json` | `labwork/security.json` | `default` | `False` | `true` | `true` |
| — | 1 | `env_global` | `DYNACONF` | `global` | `False` | `—` | `true` |
| 1 | 2 | `set_method` | `undefined` | `global` | `True` | `true` | `true` |
| 2 | 3 | `set_method` | `undefined` | `global` | `False` | `true` | `true` |

注意：行号不能直接逐行对比——B 多出的 env 槽位会把后续行整体错位；应按 `(loader, identifier, env, merged)` 这个 SourceMetadata 对齐。

## 5. 同 loader 再次加载的折叠证据（探针 P1，两轨相同）

- 两次实际输入：`[{"DYNACONF_LAB_PROBE": "first", "effective_after": "first", "pass": 1}, {"DYNACONF_LAB_PROBE": "second", "effective_after": "second", "pass": 2}]`
- 最终 `LAB_PROBE` 叶子历史：`[{"env": "global", "identifier": "DYNACONF", "loader": "env_global", "merged": false, "value": "second"}]`
- 幸存槽位：`{"data": {"LAB_PROBE": "second"}, "metadata": {"env": "global", "identifier": "DYNACONF", "loader": "env_global", "merged": false}}`
- 边界：最终 inspect/loaded_by_loaders 只剩 second；first 无法从最终历史恢复，只能靠当时的步骤日志或外部环境快照证明。

## 6. 其余证据边界探针

### P2 历史里的 value 不是“原始输入”：合并写入会被原地累积改写

- `input_object_before_set` = `{"policy": {"mfa_provider": "totp"}}`
- `history_slot_SECURITY_after_set` = `{"policy": {"issuer": "corp-local", "mfa_provider": "totp", "min_password_length": 12}, "require_mfa": true, "session_timeout": 30}`
- `leaf_history_entries_for_target_from_this_slot` = `[{"env": "global", "identifier": "undefined", "loader": "set_method", "merged": true, "value": true}]`
- **边界含义**：object_merge(old, new) 会把 old 合并进 new 并原地改写 new；因此该槽位最终 blob 含调用时并未显式给出的 require_mfa。叶子历史出现某来源，不等于该来源显式写过这个叶子。‘实际收到的输入’必须在 set 入口深拷贝固定。

### P3 嵌套属性直改不进历史：持续偏离会留下‘当前值≠历史值’矛盾，还原后无痕

- `history_leaf_values_before` = `[true]`
- `after_mutation_current` = `false`
- `history_leaf_values_during_mutation` = `[true]`
- `current_vs_history_mismatch_detectable` = `true`
- `after_restore_current` = `true`
- `history_leaf_values_after_restore` = `[true]`
- `restored_is_indistinguishable_in_history` = `true`
- **边界含义**：若当前值与全部历史叶子值都不一致，可证明存在历史未记录的写入，但不能确定主体/时间；若事后还原成与历史相容的值，最终 inspect 无异常。

### P4 真正完成加载后才出现的环境变量：不重新加载就不进 inspect

- `warmup_key` = `security.require_mfa`
- `env_var_added_after_warmup` = `{"DYNACONF_LATE_ONLY": "ghost-after-init"}`
- `effective_without_reload` = `null`
- `history_query_result` = `KeyNotFoundError: The requested key was not found: 'LATE_ONLY'`
- **边界含义**：最终 inspect 无法证明该环境变量曾存在；需要进程环境快照、shell/编排日志或重新加载后的 inspect 才能观察。

### P5 LazySettings 时间零点陷阱：首次 get 前注入的变量会被当作启动环境

- `setup_pending_before_first_get` = `true`
- `env_var_set_between_constructor_and_first_get` = `{"DYNACONF_LATE_ONLY": "ghost-before-first-get"}`
- `effective_on_first_get` = `ghost-before-first-get`
- `history` = `[{"env": "global", "identifier": "DYNACONF", "loader": "env_global", "merged": false, "value": "ghost-before-first-get"}]`
- **边界含义**：证据时间线的零点是首次真正访问/execute_loaders，而非 Dynaconf(...) 构造语句的位置；判断‘是否启动时已有此 env’需要知道进程内第一次访问 settings 的时点。

