# 服务间协议选型的消息级分析：NNpsk0 / XX / IK

基于本仓库 `noiseprotocol`（Python，Curve25519 + ChaChaPoly + SHA256）的实际实现，
而不是 Noise 模式名字面含义。所有结论均由 `security_lab/lab1..4` 四个纯内存实验复现。

核心源码位置：
- token 执行：`noise/state.py:292`（写）、`noise/state.py:351`（读）
- 密钥编排：`mix_key` / `mix_key_and_hash` / `encrypt_and_hash`，`noise/state.py:127-186`
- 传输密钥派生与状态销毁：`split()` / `handshake_done()`，`noise/state.py:188-217`、`noise/noise_protocol.py:52`
- PSK 修饰符注入位置：`noise/functions/patterns.py:35-52`

记号：发起方 I、应答方 R；`e/s` 本地临时/静态私钥，`re/rs` 对端公钥；
`MixKey(DH(...))` 把共享秘密喂入 HKDF 链；`EncAndHash` 用当前链密钥做 AEAD 并把密文并入会话哈希 `h`。

---

## 1. 逐 token 的消息级分析

### 1.1 Noise_NNpsk0：`[psk0, e]` → `[e, ee, psk1?]`（本库 psk0 修饰符插在第一条消息最前）

**消息 1（I→R）**
1. `psk0`：`mix_key_and_hash(PSK)`，`noise/state.py:338`。`ck/temp_k` 由 PSK 经 HKDF 派生，
   同时 `temp_h` 混入 `h`。此刻 CipherState 已拿到非空密钥。
2. `e`：生成临时密钥对，公钥 32B **明文**上线路并 `mix_hash`；PSK 模式下还额外 `mix_key(e.pub)`（`state.py:309-310`）。
3. payload：`EncAndHash(payload)`，用 PSK 派生密钥加密，带 16B Poly1305 tag。

**消息 2（R→E 方向，R→I）**
1. `e`：R 的临时公钥明文上线；
2. `ee`：`MixKey(DH(e, re))`，临时-临时 DH 注入链；
3. payload 再做一次 `EncAndHash`；无剩余模式 → `split()` 派生两条传输 CipherState。

- **加密依据**：msg1 的保密性只来自 PSK；msg2 起加入 `ee` 临时 DH。
- **身份依据**：没有任何静态 token。PSK 是**组共享秘密**，证明的是“持有同一个 32 字节 PSK 的成员”，
  无法区分组内具体是哪一个服务。任何持 PSK 者都能冒充组内任意角色。
- **被动窃听**：无 PSK 的窃听者看到的是 `e(32B 明文)+密文`，无法解密（实验 1e 同构验证）。
- **主动冒充**：持 PSK 的攻击者可任意发起/中间人，库层面不会报错；不持 PSK 者改一个字节即 `InvalidTag`（lab3 [2c]）。
- **静态钥匙泄露**：不存在静态钥匙。PSK 泄露时，**历史 msg1 可被离线解密**（lab4 EXP5 实测可解出
  `psk-msg1-secret`）；但 msg2 及之后的传输消息因含 `ee` 临时 DH，只要当时的临时私钥已销毁，仍保密。
- **身份隐藏**：没有身份可泄露，线上只有临时公钥；代价是也没有实体身份。

### 1.2 Noise_XX：`[e]` → `[e, ee, s, es]` → `[s, se]`

**消息 1（I→R）：只有 `e`**
1. 临时公钥 32B 明文上线、`mix_hash`。此时 CipherState 密钥为空
   （`has_key()==False`，lab1 实测），`EncAndHash` 在无密钥时**原样返回明文**（`state.py:52-53`）。
2. 因此 **msg1 的 payload 是明文**，lab1 实测 marker `b'cleartext-payload'` 原样出现在线路字节里。

**消息 2（R→I）：`e, ee, s, es`**
1. R 的 `e` 明文上线；
2. `ee`：`MixKey(DH(e,re))`，双向临时 DH —— 从此刻起 CipherState 有密钥；
3. `s`：R 的静态公钥用当前链密钥 `EncAndHash`（32B 公钥+16B tag=48B），**被动观察者看不到 R 的身份**（lab4 EXP6）；
4. `es`：应答方侧执行 `DH(s, re)`（`state.py:324-325`），把 R 的静态私钥加入链，给 R 的静态钥匙提供绑定；
5. payload 被加密。

**消息 3（I→R）：`s, se`**
1. `s`：I 的静态公钥在 `ee+es` 建立的密钥下加密上线；
2. `se`：发起方侧 `DH(s, re)`，把 I 的静态私钥加入链，绑定 I 身份；
3. payload 加密后 `split()`。

- **身份依据**：双方静态公钥都在握手内传输，**库不做任何“是否是预期公钥”的判断**。
  实验 1c 实测：Mallory 用自己的静态钥匙分别与客户端、服务端各做一次完整 XX，两端
  `handshake_finished=True`，各自学到的 `rs` 都是 Mallory 的公钥，全程无异常。
- **已知远端公钥部署**：XX 不消费预置 `rs`（`get_required_keypairs` 对 XX 不要求 rs）。
  即使你事先知道对方公钥，XX 也不会自动比对——必须应用层在握手后拿 `rs` 自行校验。
- **仅有 TOFU 部署**：首次接触必须接受线上发来的 `s`。主动攻击者在首次连接即可中间人（lab 1c），
  TOFU 只能保护“首次之后”的连接，且信任锚是应用自己存下来的那 32 字节。
- **被动窃听**：msg1 之外全部加密；两个静态公钥均加密，身份对被动观察者隐藏（EXP6）。
- **主动冒充/篡改**：无预置信任时可完整 MITM；但不知道相应私钥时无法逐字节篡改，
  翻一个字节即 `InvalidTag`（lab 1d），即 AEAD 完整性始终在线，缺的是**实体认证**。
- **前向保密**：`ee` 在第二条消息就进入链，传输密钥派生自含临时 DH 的 `ck`。
  静态私钥事后泄露无法重建历史会话（lab4 EXP4：`split()` 后 `handshake_state` 与临时 `e` 被
  `handshake_done()` 删除，进程内只留传输 CipherState）。
- **首消息重放**：msg1 无认证无加密，重放只会让对端生成一个新会话，库无任何重放记忆（见 §3）。

### 1.3 Noise_IK：预置 R 静态公钥，`[e, es, s, ss]` → `[e, ee, se]`

预消息：R 的静态公钥 `rs` 必须在握手前由 I 持有，并在初始化时 `mix_hash(rs)`（`state.py:284`）。

**消息 1（I→R）：`e, es, s, ss`**
1. `e`：I 临时公钥明文上线；
2. `es`：发起方侧 `DH(e, rs)`（`state.py:322-323`）——**I 凭预置的 `rs` 即刻与“它认为的 R”共享秘密**，
   CipherState 在此之后有密钥；
3. `s`：I 的静态公钥被 `es` 派生密钥加密上线（48B），被动观察者看不到 I 身份（EXP6）；
4. `ss`：`DH(s, rs)`，双向静态 DH，把双方静态钥匙都加入链；
5. payload 在 `es+ss` 派生密钥下加密——**msg1 即可承载机密且带认证 tag**（lab1 实测 118B）。

**消息 2（R→I）：`e, ee, se`**
1. R 临时公钥上线；
2. `ee`：临时-临时 DH，提供前向保密根；
3. `se`：应答方侧 `DH(e, rs)`（`state.py:331-332`）；
4. payload 加密后 `split()`。

- **I 对 R 的认证（已知 `rs`）**：强。冒充 R 者没有 R 的静态私钥，`es/ss` 全部算错，
  msg1 的 tag 在 R 侧即失败——lab2 [1a] 实测配置错误 `rs` 时第一条消息就 `InvalidTag`。
- **R 对 I 的认证——本实现的关键坑**：I 的静态公钥是 msg1 里**在线传输**的，R 侧读到
  `s` token 时直接 `self.rs = from_public_bytes(...)` **覆盖**预置值（`state.py:381-383`），
  库从不把它与 R 预置的 `rs` 做比较。lab2 [1b] 实测：R 预置了错误的发起方公钥，
  msg1、msg2 全部解析成功，两端 `handshake_finished=True`。也就是说，**R 侧对 I 的静态认证
  在本库里不是自动生效的**，应用必须在 `split()` 之前自行抓取 `handshake_state.rs` 并与本地信任库比对。
- **TOFU-only 部署**：IK 的前提就是 I 预先持有 R 公钥，纯 TOFU 场景应先用 XX 完成首次接触、
  固化 R 公钥后再切 IK；否则 IK 无法初始化（`validate()` 要求 `rs` 非空，`noise_protocol.py:80-82`）。
- **被动窃听**：msg1 起全程加密，I 的身份加密，R 的身份根本不上线（`rs` 只是本地 pin）。
- **前向保密**：`ee` 在 msg2 注入，静态泄露不暴露历史传输消息（EXP4）；但注意 msg1 的密钥只含
  `es+ss`（静态成分 + I 的临时 `e`），R 的临时钥匙要到 msg2 才出现。
- **静态钥匙泄露**：拿到 I 或 R 静态私钥可在**未来**会话冒充（EXP4 实测伪造新会话被接受），
  但历史会话因 `ee` 临时 DH 仍保密；泄露后应轮换静态钥匙，被冒充期间的新会话不可信。

---

## 2. 四个部署视角的横向对照

| 维度 | NNpsk0 | XX | IK |
|---|---|---|---|
| msg1 保密性 | 有（PSK 派生密钥） | **无，明文 payload** | 有（es+ss 派生密钥） |
| msg1 实体认证 | 仅“PSK 组成员” | 无 | I 认证 R（凭预置 rs）；R 认证 I 需应用补 |
| 被动窃听下身份 | 无身份概念 | 静态公钥均加密，隐藏 | 双方身份均不上明文，隐藏最好 |
| 主动冒充（无预置信任） | 持 PSK 即可冒充 | 首次即可 MITM，库不报错 | I 侧 pin 错误在 msg1 即 `InvalidTag` |
| 已知对端公钥 | 不使用公钥 | 不自动校验，须应用比对 | 原生消费 rs；R 侧仍需应用比对收到的 s |
| 前向保密 | msg2 起（ee） | msg2 起（ee） | msg2 起（ee） |
| 静态泄露的历史影响 | 无静态；PSK 泄露则历史 msg1 失守 | 历史传输仍保密 | 历史传输仍保密，仅未来冒充 |
| 首消息重放 | 新实例照常接受 | 新实例照常接受 | 新实例照常接受（认证≠抗重放） |

---

## 3. 首消息重放：三个模式都不防

Noise 握手只保证消息的**完整性与（在 pin 成立时的）实体认证**，不包含序列号/时间戳/会话记忆。
lab3 EXP3 实测：
- 重放进同一个状态机对象：`NoiseHandshakeError`——这只是 `_next_fn` 顺序校验（`connection.py:103-106`），
  不是安全机制；
- 重放进一个**全新**应答方实例（服务重启、多副本、无共享重放缓存）：NNpsk0 与 IK 的 msg1 都被正常解密，
  业务 payload（如 `amount=1000` 的转账请求）原样取出，应答方还会继续派生传输密钥；
- 实验给出最小应用层防线：以 msg1 前 32 字节临时公钥 `e` 为键做去重缓存（lab3 [3d]），
  生产中应改为“时间戳 + 随机 nonce + 持久化/分布式重放缓存”，并对业务请求做幂等键。

结论：**任何要放在握手消息里的业务请求，应用都必须自带抗重放与幂等**；库不保存任何跨连接状态。

---

## 4. 业务载荷应从第几条消息开始

- **NNpsk0**：保密性从 msg1 就有，但只有组级 PSK 认证、无实体身份、无抗重放。
  非敏感、可幂等的预热/路由信息可放 msg1；**真实业务载荷建议放在 `split()` 后的第 1 条传输消息**，
  并在应用层完成“PSK 绑定的服务身份 + 重放缓存 + 幂等键”之后。
- **XX**：**msg1 绝对不能放敏感数据（明文）**。msg2 起有加密但实体认证尚未完成
  （I 到 msg3 才递交身份，R 身份要靠应用比对）。建议业务载荷从**握手完成后的传输消息**开始；
  首次 TOFU 连接在应用确认并持久化对端 `rs` 之前，只允许跑注册/换 pin 这类引导流量。
- **IK**：msg1 已机密且 I 侧对 R 的认证在 tag 中成立，**I→R 方向的首条业务载荷可以随 msg1 发送**
  （0-RTT 风格），前提是：(a) `rs` 来自可信分发而非裸 TOFU；(b) 该请求带应用层 nonce/幂等键防重放；
  (c) R 侧在处理前自行校验收到的 I 静态公钥。R→I 方向的保密应答从 msg2 开始；
  不含上述前提时，统一等 `split()` 后再发业务最稳妥。

---

## 5. 库负责的保证 vs 应用必须保存的信任状态

**库（noiseprotocol）在正确使用下保证**
- 严格按规范执行 token 序列、HKDF 链与 `h` 会话哈希；每条握手/传输消息是带 AD=`h` 的 AEAD，
  篡改即 `InvalidTag` / `NoiseInvalidMessage`（lab 1d、2c）。
- `split()` 从含临时 DH 的 `ck` 派生**每会话独立**的双向传输密钥（lab1：同静态钥匙、两次会话密钥不同），
  并在 `handshake_done()` 删除握手状态与临时私钥，为前向保密提供工程条件（EXP4）。
- 加密静态 token 与 payload，提供对被动观察者的身份隐藏（EXP6）。
- prologue/协议名不匹配会让 `h` 分叉、tag 失败（版本与上下文绑定）。

**库不负责、必须由应用承担**
- **信任决策**：XX/IK 中收到的静态公钥与本地预期是否一致，库不比对（IK 的 R 侧 `rs` 还会被线上 `s` 覆盖）。
  应用必须在 `split()` 前从 `handshake_state.rs` 抓取公钥并校验；注意握手完成后该对象被删除，
  且 `NoiseConnection` 没有公开 getter，需要在握手过程中快照或封装一层。
- **TOFU 信任库的持久化**：首次公钥的固化、更新、吊销（pin 轮换）完全是应用状态，库不跨连接记忆任何对端。
- **抗重放与幂等**：缓存握手 nonce/临时公钥、业务请求幂等键（§3）。
- **PSK/静态私钥的全生命周期**：PSK 是组共享秘密，泄露即失守 msg1 历史与组成员冒充边界；
  静态私钥泄露后的轮换与影响面评估；密钥存储安全库内不涉及。
- **传输阶段的长期使用纪律**：nonce 耗尽（`NoiseMaxNonceError`）前 rekey/重协商、
  会话级别的授权与租户隔离，均需应用编排。

## 6. 选型建议（服务间）

1. 能做公钥分发/轮换：首选 **IK**（msg1 即可机密上行、身份隐藏最好、前向保密完整），
   并补上 R 侧公钥校验与应用层抗重放；首次引导用 **XX + TOFU 固化**，之后切 IK。
2. 只能预置共享秘密、且接受组级信任：用 **NNpsk0**，业务载荷延后到传输阶段，
   并明确 PSK 泄露会使历史 msg1 可离线解密。
3. 任何模式都不要因为“用了 Noise”就省略重放缓存、幂等键和对端公钥 pin 的持久化。

---

### 复现方式

```
.venv/bin/python security_lab/lab1_baseline.py      # 线路布局与密钥可用时点
.venv/bin/python security_lab/lab2_static.py        # 错误静态钥匙 / MITM / 篡改
.venv/bin/python security_lab/lab3_psk_replay.py    # 错误 PSK / 首消息重放
.venv/bin/python security_lab/lab4_pfs.py           # 静态泄露、前向保密、身份隐藏
```
