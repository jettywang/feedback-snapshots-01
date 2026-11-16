# dissect.cobaltstrike 恢复 Malleable Profile 的保真边界分析

## 0. 结论速览（给调查报告的措辞建议）

`C2Profile.from_beacon_config()` 产出的是**从 Beacon 内嵌 TLV 配置反推的“兼容性子集 profile”**，不是原始部署 profile。
它在自己生成的文本上可以做到语法自洽（8/8 样本生成→再解析文本与字典完全一致），但**语法可解析不等于与原配置语义等价**。

- 8 个真实样本中，进入 profile 的设置占比约 **31/68（CS 4.12 样本，46%）到 25/48（DNS 4.3，52%）**；其余被显式丢弃或转换器根本没有分支。
- 三类内容必须在报告中分开表述：**可表达（expressed）**、**默认/占位值补足（synthesized）**、**无法还原（not recoverable）**。
- 最危险的两个“看起来对、其实不等价”的点：
  1. `.http-get.server.output` 的 `prepend/append` 在 Beacon 里**只存长度不存字节**，生成器用同数量的字面 `X` 占位（见 §3.1），绝不能写回真实报告当作原始混淆串。
  2. 含反斜杠的 HTTP 变换参数走 `latin-1` 转义分支，再解析会**静默丢字节**（见 §3.4），而 POST 分支用 `repr` 风格则可保真——两条路径不一致。

样本与版本（口令解压 `dissect.cobaltstrike`，来自 `tests/beacons/`）：

| 样本前 8 位 | CS 版本 | 协议 | 设置数 | profile 属性数 | 自洽再解析 |
|---|---|---|---|---|---|
| 4f571c0b | 4.2 | https | 39 | 24 | 是 |
| 3fdf9257 | 4.4 | https | 43 | 24 | 是 |
| a1573fe6 | 4.3 | dns | 48 | 25 | 是 |
| d972234f | 4.12 | dns(+DoH) | 68 | 31 | 是 |
| 124552cf | 4.10 | https(guardrails) | 52 | 22 | 是 |
| 其余 3 个 | 4.2–4.3 | http/https | 38–43 | 19–24 | 是 |

复现入口：`beacon-dump -t c2profile <beacon>` 与 `c2profile-dump -t properties <generated.profile>`。

---

## 1. 转换链路与“保留了什么”

代码路径：`dissect/cobaltstrike/c2profile.py:454 C2Profile.from_beacon_config()`。

1. `BeaconConfig` 先把去混淆后的配置块按 `index(u16) type(u16) length(u16) value` 解析成 `Setting` 元组（`beacon.py:699 iter_settings`）。
2. `settings_by_index` 经 `SETTING_TO_PRETTYFUNC` 做“类型化/美化”（TLV 原字节 → int / 去 NUL 字符串 / 结构化变换程序）。
3. `from_beacon_config` 用 47 个 `elif setting == ...` 分支把**部分**设置映射到 AST 块，再由 Lark `Reconstructor` 输出文本。

关键事实：**转换器只覆盖枚举的一个子集**。`grep -c "elif setting =="` 为 47，而 CS 4.12 枚举已到 91。没有分支的设置在循环里被静默跳过，不报错、不留痕。

三层数据形态（以 HTTP 变换为例，完整输出见 §3）：

- L0 原字节：`config_block` 中去 XOR 的 TLV `value`（大端）。
- L1 类型化：`parse_transform_binary()` 输出的 `(步骤名, 参数)` 程序，或 `parse_recover_binary()` 的长度元组。
- L2/L3 生成文本与再解析：`as_text()` → `C2Profile.from_text()` → `properties`。

L2→L3 自洽只证明“生成器输出的是合法 grammar”，不证明 L1→L2 无损。

---

## 2. 内容三分类总表（逐项）

### 2.1 可表达（expressed）：值能等价落到 profile 语法，再解析语义一致

| Beacon 设置 (index) | profile 位置 | 证据/备注 |
|---|---|---|
| SLEEPTIME(3) JITTER(5) | 全局 `set sleeptime/jitter` | int→字符串，保真 |
| USERAGENT(9) | `set useragent` | 去 NUL 字符串 |
| SPAWNTO_X86/X64(29/30) | `set spawnto_x86/x64` | 保真 |
| C2_VERB_GET/POST(26/27) | `http-get/post set verb` | 保真 |
| SUBMITURI(10) | `http-post set uri` | 保真 |
| C2_REQUEST(12) | `http-get.client` 头/参数/metadata 变换 | 步骤顺序与参数保留（反斜杠例外见 §3.4） |
| C2_POSTREQ(13) | `http-post.client` id/output 变换 | 同上，转义路径更安全 |
| DNS_BEACON_*(60–65) | `dns-beacon` 六个前缀 | 字符串保真，实测见 §4 |
| DNS_IDLE(19) DNS_SLEEP(20) MAXDNS(6) | `dns-beacon` | IDLE 把 u32 解释为 IPv4，保真 |
| PROCINJ_PERMS_I/PERMS(43/44) | `process-inject startrwx/userwx` | **枚举→布尔字符串重映射**（见 2.2 说明） |
| PROCINJ_MINALLOC(45) ALLOCATOR(52) | `process-inject` | 保真；allocator 0/1→VirtualAllocEx/NtMapViewOfSection |
| PROCINJ_TRANSFORM_X86/X64(46/47) | `transform-x86/x64 append/prepend` | 字节以 `\xNN` 转义保真 |
| PROCINJ_EXECUTE(51) | `execute` 块 | 枚举名+特殊 API 字符串保真 |
| GARGLE_NOOK(41) | `stage sleep_mask` | 非零才输出；值被原样转成字符串（实测 4.2/4.3 样本为 15 万级地址量，4.12 为 1），不是布尔 |
| CLEANUP(38) | `stage cleanup` | 保真 |
| DATA_STORE_SIZE(76) | `stage data_store_size` | 4.9+ |
| HTTP_DATA_REQUIRED(77) | `http-beacon data_required` | 4.10+，非零才输出 |
| BOF_ALLOCATOR(16) BOF_REUSE_MEM(48) | `process-inject` | 4.7+ |
| BEACON_GATE(78) | `stage beacon_gate` | 4.10+，结构体→WinAPI 名（见 §5） |
| obfuscate_settings（非 TLV，来自 stage） | `stage transform-obfuscate` | 只保留类型与 key_size（见 §5.2） |

### 2.2 被默认/占位/重映射补足（synthesized）：文本合法，但含 Beacon 中不存在的信息

| 项 | 现象 | 风险 |
|---|---|---|
| C2_RECOVER(11) 的 `prepend/append` | Beacon 仅存**长度**（u32），生成器渲染成同长度字面 `X`（`c2profile.py:510-513`） | 占位符不是原始字节，**禁止当作真实 server output 混淆** |
| PROCINJ_PERMS(43/44) | 数值 64/4/32 被翻译成 `"true"/"false"` 字符串 | 语义可用，但原始权限位含义被折叠，非 64/4/32 的值不输出任何项 |
| DNSRESOLVER(66) | 非空时输出 `# dns_resolver "..."` 注释（grammar 里就是注释产生式，非功能性指令） | 它是 **DNS Listener 配置**，不属于 malleable profile 生效项；空值被 `and value` 抑制 |
| BEACON_GATE(78) | 23 字节结构体经 `beacon_gate_options_string()` 归并为 `All/Comms/Core/...` 名称 | 归并是解释层动作；全零结构体整块跳过 |
| 空块抑制 | `set_non_empty_config_block` 保证不输出空 `dns-beacon{}` 等 | 输出里“缺失”不等于样本里没有该能力，可能只是值为空/0 |

### 2.3 完全无法还原（not recoverable / dropped）

A. 转换器有分支但**显式 `pass` 丢弃或只取部分**（信息在 L1 可见，L2 消失）：
MAXGET(4)、SPAWNTO(14, 已弃用)、C2_CHUNK_POST(28)、CFG_CAUTION(39)、HOST_HEADER(54)、HTTP_NO_COOKIES(50)、PROXY_BEHAVIOR(35)、EXIT_FUNK(55)、KILLDATE(40)、PROCINJ_STUB(53)。
其中 SETTING_DOMAINS(8) 的分支（`c2profile.py:478-480`）只执行 `http_get.set_option("uri", ", ".join(config.uris))`：**主机名与 host↔URI 配对关系全部丢弃，只保留 URI**（实测 3fdf9257 的 `group.ccb.com.dsa.dnsv1.com` 主机名即未进 profile）。代码层面，当存在多个 GET URI 时会被 `", ".join` 拼成单个逗号字符串（如 `"/a, /b"`），而 stock 多 URI 写法是同一 `set uri` 后空格并列；本 grammar 的 `http_get_options` 只接受单个 string，两种形态都需人工核对（本批 8 个夹具均为单 GET URI，该 join 分支未被真实数据触发，见 `multiuri.py`）。注意 profile 中出现的第二条 `set uri` 属于 `http-post`，来自 SETTING_SUBMITURI(10)，语义正确。

B. 转换器**没有分支**，随版本增长而扩大的缺口（实测 CS 4.12 样本 26 项）：

- 协议/密钥/标识：PROTOCOL(1)、PORT(2)、PUBKEY(7)、WATERMARK(37)、WATERMARKHASH(36)、MASKED_WATERMARK(74)、CRYPTO_SCHEME(31)、SYSCALL_METHOD(17)
- 域策略/重试：DOMAIN_STRATEGY 系列(67–70)、MAX_RETRY_STRATEGY 系列(71–73)
- 睡眠掩码区段：GARGLE_SECTIONS(42)
- **4.11 分块 POST 尺寸：C2_CHUNK_POST_PACKET_SIZE(79)、POST_SIZE(80)**
- **4.12 DoH 整块：DNS_DOH_ENABLED(81)、VERB(82)、USERAGENT(83)、PROXY_SERVER(84)、SERVERS(85)、ACCEPT(86)、HEADERS(87)**
- **4.12 进程注入：PROCINJ_DRIP_LOAD(88)、DRIP_LOAD_DELAY(89)**
- grammar 同样缺失：`c2profile.lark` 的 `dns_beacon_options` 无任何 `doh-*` 产生式，`process_inject_options` 无 drip 项。

> 注意区分：DoH 数据在 `BeaconConfig.settings_by_index` 里**已被完整、正确地类型化**（见 §5.1），缺口只在 profile 生成器与 grammar，不在解析器。

### 2.4 覆盖率量化（来自 `analysis/roundtrip_summary.json`）

| 样本 | 设置数 | expressed | synthesized | dropped(pass) | not-implemented |
|---|---|---|---|---|---|
| 4f571c0b (4.2) | 39 | 21 | 1 | 11 | 6 |
| a1573fe6 (4.3 DNS) | 48 | 26 | 1 | 11 | 10 |
| 124552cf (4.10) | 52 | 24 | 2 | 11 | 15 |
| d972234f (4.12) | 68 | 29 | 2 | 11 | 26 |

所有样本 `生成文本 == 再解析文本` 且 `properties` 字典相等——**自洽性 100%，但这与“等于原始 profile”是两回事**。

---

## 3. 专项一：HTTP 变换（样本 4f571c0b，CS 4.2）

### 3.1 L0 原字节 → L1 类型化（C2_REQUEST，节选）

TLV 原字节（`SETTING_C2_REQUEST`，大端）：
```
0000000a 00000011 "Connection: close"      # _HEADER, len 0x11
0000000a 00000016 "Accept-Language: en-US"  # _HEADER
00000007 00000000                           # BUILD metadata
0000000f ...                                # MASK
00000003 ...                                # BASE64
00000002 0000002b "wordpress_...="          # PREPEND + 43 字节参数
00000006 00000006 "Cookie"                  # HEADER 终止
```
L1 程序（保真，步骤顺序保留）：
```
('_HEADER', b'Connection: close'), ('_HEADER', b'Accept-Language: en-US'),
('BUILD','metadata'), ('MASK',True), ('BASE64',True),
('PREPEND', b'wordpress_ed1f617bbd6c004cc09e046f3c1b7148='), ('HEADER', b'Cookie')
```

### 3.2 L2 生成文本（与 L1 等价的部分）

```
client {
    header "Connection" "close";
    header "Accept-Language" "en-US";
    metadata {
        mask;
        base64;
        prepend "wordpress_ed1f617bbd6c004cc09e046f3c1b7148=";
        header "Cookie";
    }
}
```
这部分 L3 再解析得到的 `http-get.client.metadata` 与 L1 完全相等 → **可表达**。

### 3.3 同一样本的 server.output：典型“占位补足”

L0 `SETTING_C2_RECOVER`：`00000004(print) 00000002 000006e7(prepend,len=1767) 00000003(base64) 00000008(netbios)`。
L1：`('print',True), ('prepend',1767), ('base64',True), ('netbios',True)`——**只有长度 1767，没有那 1767 个字节**。
L2 输出：`prepend "XXXX...XXX";`（1767 个 X）。

结论：Beacon 运行时由 teamserver 下发真实填充，样本内不含该数据。报告中只能写
“server.output 含长度 1767 的 prepend（内容无法从样本恢复，工具以 X 占位）”，不能照抄 X 串。

### 3.4 转义不对称（GET 的 latin-1 路径会静默丢字节）

`c2profile.py:534`（REQUEST）用 `v.decode("latin-1")`，而 `:565`（POSTREQ）用 `repr(v)[2:-1]`。实测参数 `b"path\\to\\file"`：

| 路径 | 生成 token | 再解析结果 | 与原字节相等 |
|---|---|---|---|
| REQUEST/latin-1 | `"path\to\file"` | `b'pathtofile'`（`\t`、`\f` 被 `string_token_to_bytes` 当转义吃掉） | **False** |
| POSTREQ/repr | `"path\\to\\file"` | `b'path\\to\\file'` | True |

当前 8 个夹具的变换参数恰好都是可打印 ASCII、不含反斜杠，因此未触发；但这是潜伏的语义损坏路径。
另外该 grammar 的 `STRING` 正则对转义引号也较脆弱，复杂二进制参数应以 `\xNN` 形式统一转义（改进方案见 §6）。

---

## 4. 专项二：DNS 设置（a1573fe6 / d972234f）

### 4.1 可表达部分（a1573fe6，CS 4.3，xor key 0xaf）

| index | L0 原字节 | L1 类型化 | L2 profile | 分类 |
|---|---|---|---|---|
| 6 MAXDNS | `00fb` | 251 | `set maxdns "251";` | 可表达 |
| 19 DNS_IDLE | `13075bf1` | `19.7.91.241` | `set dns_idle "19.7.91.241";` | 可表达（u32→IP） |
| 20 DNS_SLEEP | `00000091` | 145 | `set dns_sleep "145";` | 可表达 |
| 60 BEACON | `736d74702e 00...` | `smtp.` | `set beacon "smtp.";` | 可表达 |
| 61–65 GET_A/AAAA/TXT,PUT_* | 前缀字符串+NUL | `up./box./lantern./test./answer.` | 对应 5 行 | 可表达 |
| 66 DNSRESOLVER | 全零 | `''` | 不输出（空值抑制） | 合成/条件 |

L3 再解析的 9 个 `dns-beacon.*` 属性与 L1 一致。这部分可以在报告中作为“恢复的 DNS 子域前缀与轮询参数”引用。

### 4.2 无法还原部分（d972234f，CS 4.12，DoH 全量存在但整块丢失）

L1 已正确解析（说明解析器支持）：
```
81 DNS_DOH_ENABLED       = 1
83 DNS_DOH_USERAGENT     = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)'
84 DNS_DOH_PROXY_SERVER  = 'http://inet-proxy-a.adns.ubs.net:8085'
85 DNS_DOH_SERVERS       = 'doh.opendns.com'
86 DNS_DOH_ACCEPT        = 'application/dns-message'
87 DNS_DOH_HEADERS       = 'Content-Type: application/dns-message\r\nheader-1: h1-value'
```
生成的 `dns-beacon{}` 块里**以上 6 项一项都没有**（`c2profile.py` 无 81–87 分支，grammar 无产生式）。
调查报告若只看生成 profile，会错误地得出“该 DNS Beacon 未启用 DoH”的结论——事实是 `DNS_DOH_ENABLED=1`。
同类：`DNS_DOH_VERB(82)` 枚举、`C2_CHUNK_POST_*`(79/80)、`PROCINJ_DRIP_LOAD*`(88/89) 全部静默缺失。

---

## 5. 专项三：未知/版本相关设置

### 5.1 DoH（4.12）——解析器已支持、生成器未跟进
见 §4.2。属于“数据可得但表达层缺口”，是性价比最高的补全点。

### 5.2 transform-obfuscate（4.11+，来自 stage 而非 TLV）
d972234f 的 stage 携带 5 个 `StageObfuscateSettings`，生成：
```
transform-obfuscate { base64; xor "64"; rc4 "128"; lznt1; }
```
- 保留：算法类型与 **key_size**（XOR=64、RC4=128 字节）。
- 丢失：真实 XOR/RC4 密钥字节、original/payload 尺寸等（这些不在 malleable profile 模型内，本就无法用 profile 表达）。
- 报告可写“采用 base64+XOR(64B key)+RC4(128B key)+LZNT1 组合”，不可声称恢复了密钥。

### 5.3 beacon_gate（4.10，结构体→名称归并）
d972234f 的 23 字节结构体仅 3 个非零位 → `beacon_gate { VirtualAllocEx; InternetConnectA; VirtualAlloc; }`。
124552cf（guardrails）该结构体全零，整块不输出。归并函数 `beacon_gate_options_string()` 还会把成组 API 折叠成 `All/Comms/Core/Cleanup`，属于解释性重映射，引用时应回贴原始结构体字节。

### 5.4 版本判定本身
`BeaconConfig.version` 优先用 PE export timestamp，回退到 `max_setting_enum`。枚举复用（如 16/17/36/48 在不同版本含义不同）由 `iter_settings` 的弃用规则处理；恢复 profile 时应同时记录 `version` 与 `max_setting_enum`，避免脱离版本解读索引。

---

## 6. 改进方案（按优先级，含可行性证据）

1. **统一字节安全转义（高、低风险）**：让 REQUEST 分支与 POSTREQ 一致，对 `bytes` 参数统一 `repr` 风格转义。
   原型验证（`improvement_prototype.py`）：4 个含反斜杠/引号/控制字节/普通串用例再解析全部 `equal=True`。
   改动点：`c2profile.py:534` 附近，将 `v.decode("latin-1")` 替换为统一的 bytes→escaped-string 助手。
2. **显式标注不可还原项（高、零行为变更）**：C2_RECOVER 的长度占位改为可识别形式（如 `prepend "X"*1767;` 不被 grammar 接受，则在 AST/侧车 JSON 输出 `{"unrecoverable": {"http-get.server.output.prepend_length":1767}}`），
   并提供 `from_beacon_config(..., emit_coverage=True)` 返回“已表达/丢弃/未实现”索引清单，杜绝静默跳过。
3. **补齐版本缺口（中）**：为 79/80（chunk 尺寸）、81–87（DoH）、88/89（drip-load）在 `c2profile.lark` 增加产生式并在 `from_beacon_config` 加分支。
   可行性已验证：这些值在 `BeaconConfig.settings_by_index` 全部就绪，无需改解析器。
4. **保留 host/URI 配对（中）**：`SETTING_DOMAINS` 当前只取 `config.uris`；建议在侧车结构里保留 `domain_uri_pairs`，因为 malleable 语法本身不承载 host，这部分应明确归为“部署/监听信息”而非 profile。
5. **回归测试（配合每项）**：当前 `tests/test_c2profile.py` 25 项全过、全量 108 项通过（`test_client.py` 因环境缺 `pytest_httpserver` 跳过，与本库逻辑无关）。
   应新增反斜杠/引号变换参数往返测试、DoH/drip 生成测试、coverage 清单快照测试。

---

## 7. 复现实验清单（本报告全部数字可重跑）

工作区虚拟环境：`.venv/bin/python`。脚本位于 `$TMPDIR/fb25/`，生成物位于 `analysis/*.profile` 与 `analysis/roundtrip_summary.json`。

```bash
# 解压夹具（口令 dissect.cobaltstrike）
# 三层 HTTP 对照 / DNS 对照 / 未知项 / 覆盖率 / 转义原型
python $TMPDIR/fb25/http_triple.py
python $TMPDIR/fb25/dns_triple.py
python $TMPDIR/fb25/unknown_triple.py
python $TMPDIR/fb25/coverage_matrix.py
python $TMPDIR/fb25/escape_semantic4.py
python $TMPDIR/fb25/improvement_prototype.py
# CLI
.venv/bin/beacon-dump -t c2profile <beacon> -x 0xaf
.venv/bin/c2profile-dump -t properties <generated.profile>
```

## 8. 给调查报告的推荐表述模板

- 可表达：“从样本 TLV `SETTING_DNS_BEACON_GET_A(61)` 恢复的 DNS A 记录查询前缀为 `up.`，与生成 profile 的 `dns-beacon.get_A` 再解析值一致。”
- 占位补足：“样本 `SETTING_C2_RECOVER(11)` 仅记录 server.output prepend 长度 1767；工具生成的 1767 个 `X` 为占位符，原始字节不在样本中，无法恢复。”
- 无法还原：“样本 `SETTING_DNS_DOH_ENABLED(81)=1` 且含 DoH 服务器/UA/头字段，但当前 profile 生成器无对应分支，生成的 malleable profile 不包含任何 DoH 配置；该项以 BeaconConfig 类型化值为准。”
