# PySNMP community → 来源标签 → VACM 映射审查

针对"两组设备历史共用同一 community、网管靠来源标签（snmpCommunityTransportTag）
映射到不同权限"这一部署模式，对本仓库 PySNMP 7.1.32 的映射链路做了审查，
并给出可运行的发布前检查器与报文级演示。

## 映射链路（审查对象）

入站 v1/v2c 请求的授权链条：

1. `pysnmp/proto/mpmod/rfc2576.py:341` — MP 把 `(communityName, (transportDomain, transportAddress))` 交给安全模型；`transportAddress` 是**发送方的 (IP, 端口)**。
2. `pysnmp/proto/secmod/rfc2576.py:168` `_com2sec` — community + 来源标签 → `(securityName, contextEngineId, contextName)`：
   - 来源地址在 `snmpTargetAddrTable` 中 → 标签取**交集**（`:411`）；交集为空 → 拒绝；
   - 来源不在表中 → 仅当该 community 存在**空标签行**时回退到空标签行（`:415`），否则拒绝；
   - 候选身份可能多于一个 → `:431-444` 排序取第一个。
3. `pysnmp/entity/rfc3413/cmdrsp.py:276` — 以 `(securityModel, securityName, securityLevel=noAuthNoPriv, contextName)` 调 VACM。
4. `pysnmp/proto/acmod/rfc3415.py:145` `is_access_allowed` — context 检查 → `(securityModel, securityName)` 查 group → access 条目 → view → 最终允许/拒绝。

## 审查发现

### 映射层（`_com2sec`）

- **F1 同 community+tag 多身份 → 静默单选**。`rfc2576.py:431-444`：多个候选
  `(securityName, contextEngineId, contextName)` 时按
  `(不在 snmpTargetParamsTable, securityName 字典序)` 排序取第一。
  结果：字母序小的身份永远胜出，另一组设备永远拿不到预期权限；且
  **改动无关的 snmpTargetParamsTable（告警目标配置）会翻转胜者**（演示场景 2）。
- **F2 同 securityName 不同 contextName → 集合迭代顺序决定**。排序键相同，
  胜者取决于 Python set 迭代顺序（`rfc2576.py:370-377` 构造的是 set）。
  实测：同一配置正序/逆序加载得到不同 contextName（检查器 ORDER-DEPENDENT
  会触发）；engineID 是随机的，重启进程也可能翻转。
- **F3 来源匹配是 (IP, port) 精确匹配**。网管用临时源端口时标签永远不匹配，
  静默落到空标签行或被拒。把 targetAddress 端口写成 0/161/162 几乎必然是配置错误。
- **F4 空标签回退的不对称性**。已登记来源标签不相交 → 拒绝（无回退）；
  未登记来源 → 静默获得空标签行身份。即"已知但不对"比"未知"更严格，
  且任何未登记来源都能拿到回退身份（演示场景 3）。
- **F5 重叠来源取并集**。同一 (IP, port) 出现在多条 targetAddress 中，
  标签集合是并集（`rfc2576.py:236-247`），直接制造 F1 的多候选。

### VACM 层（`rfc3415.py`）

- **F6 v1/v2c 同名 securityName 是不同主体**。community 表被 securityModel 1
  和 2 共享，但 VACM 按 `(securityModel, securityName)` 查 group。同一
  community：v1 与 v2c 可得到完全不同的视图；只配一个模型时另一模型
  fail-closed（noGroupName）（演示场景 4）。**community 名相同 ≠ 同一已认证用户**。
- **F7 fuzzy access 查找与 RFC 3415 相反**。`rfc3415.py:133,140-142`：
  `candidates.sort()` 后取 `candidates[0]`（升序最小），而 RFC 3415
  vacmAccessTable 第 2 步要求：匹配的安全模型优先、精确 context 优先、
  最长前缀优先、**最高** securityLevel 优先——本实现全部相反
  （演示场景 6：短前缀视图战胜长前缀）。
- **F8 缺少 securityLevel ≤ 请求级过滤**。RFC 3415 第 1 步要求候选条目
  securityLevel 不高于请求级；本实现不过滤，导致仅配置了 authPriv 视图的
  group 会把该视图授予 noAuthNoPriv 的 community 请求（演示场景 5）。
  建议：community 可达的 securityName 必须显式配置 noAuthNoPriv 的
  exact 条目（`add_vacm_user` 默认即 exact），检查器对缺失情况报 ERROR。
- **F9 groupName 含 `hash(securityName)`**（`entity/config.py:830`）：
  进程间不稳定（PYTHONHASHSEED），不影响本进程内授权一致性，但不要把它
  写进任何外部配置/审计规则。

### 缓存与加载顺序

- secmod/VACM 的缓存都按 MIB `branchVersionId` 失效重建
  （`rfc2576.py:104,172,269,323`、`rfc3415.py:192,218,257,336`），
  检查器的 CACHE-STALE 测试（暖缓存后增删配置）验证通过：
  **修改后的缓存不会钉住旧授权**。
- 但对 F1/F2 类歧义配置，最终授权由内部 tie-break 决定，加载顺序、
  无关表变更、进程重启都可能改变结果——这类配置必须拒绝发布。

## 发布前检查器

```console
$ python sec-review/check_community_mapping.py sec-review/examples/safe_disjoint_tags.json
```

- 静态检查（与加载顺序无关）：AMB-IDENTITY / AMB-CONTEXT / AMB-OVERLAP(-SRC) /
  EMPTY-TAG-FALLBACK / PORT-SUSPECT / V1V2C-PARTIAL / VACM-NOGROUP /
  VACM-LEVEL / VACM-CONTEXT-MISMATCH；
- 动态决策矩阵：每个 (community × 来源 × v1/v2c × 探测 OID) 都跑真实的
  `_com2sec` + `is_access_allowed`，含"已登记 IP + 未登记端口"和未知来源；
- 确定性测试：正序/逆序加载矩阵必须一致（ORDER-DEPENDENT）；
  暖缓存后增删探针配置必须即时生效且可还原（CACHE-STALE）；
- 退出码：0 = 可发布；1 = 拒绝发布并列出冲突来源。
- 确需空标签回退的现存合法配置：在 JSON 里设 `"allowEmptyTagFallback": true`
  显式确认后降级为警告（见 `unsafe_empty_tag_fallback.json` 的用法）。

配置模式见 `sec-review/examples/`：

| 文件 | 结果 |
| --- | --- |
| `safe_disjoint_tags.json` | exit 0，标签互不重叠、端口固定、v1/v2c 都显式建模 |
| `unsafe_shared_community_overlap.json` | exit 1，来源重叠 → 多候选身份 |
| `unsafe_empty_tag_fallback.json` | exit 1，空标签回退使来源标签失去分区意义 |
| `unsafe_context_tie.json` | exit 1，同 securityName 不同 contextName，且实测加载顺序改变结果 |

## 报文级演示

```console
$ python sec-review/demo_packets.py
```

本地 BER 构造 v1/v2c GetRequest，经 loopback transport 注入
`receive_message`，逐报文打印 `[map]`（community+来源 → 身份）与
`[vacm]`（最终 VACM 决策）及响应 PDU：

1. **SAFE**：标签互斥 → A/B 各得其视图；未知来源、错误端口静默丢弃；v1 同样受控。
2. **UNSAFE-OVERLAP**：同一报文，仅因中间加了一条无关的 snmpTargetParams
   条目，身份从 nms-area-a 翻成 nms-area-b，DENY 变 ALLOW。
3. **UNSAFE-EMPTY-TAG**：未知来源、以及已登记 IP 换个端口，都静默变成
   nms-guest 并读到整个 9999 子树。
4. **V1-V2C**：同 community 同 securityName，v1 先被 noGroupName 拒绝；
   补上 model-1 组后 v1 反而拿到更宽视图。
5. **VACM-LEVEL**：仅配 authPriv 的视图被授予明文 community 请求（F8）。
6. **VACM-PREFIX**：短前缀视图战胜长前缀，与 RFC 3415 相反（F7）。

## 限制与声明

- 本方案**没有给 community 协议增加任何密码学认证**：community 仍是明文
  共享口令，来源标签只是路由/授权便利，UDP 源地址可伪造。**不得把来源
  标签映射宣传为 SNMPv3（USM）的替代**；需要认证、完整性、加密时必须用
  SNMPv3。
- 检查器与演示只覆盖读视图（read view）与 UDP 传输；write/notify 视图与
  IPv6 同理但未逐一演示。
- 检查器通过真实代码路径得出矩阵，因此反映的是本实现的实际行为
  （包括 F7/F8 与 RFC 的偏差），而不是 RFC 文本。
