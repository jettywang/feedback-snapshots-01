# 服务端 Macaroon 撤销示例（标准库 SQLite + 并发请求）

运行：

```bash
python3 examples/revocation/server_revocation_demo.py
```

仅使用 Python 标准库（`hmac`、`hashlib`、`sqlite3`、`threading`、`secrets` 等），
内置一个与 `pymacaroons` 同构的极简一阶 macaroon（HMAC-SHA256 签名链、可追加 caveat），
不需要启动网络服务即可复现两个并发请求的完整行为。SQLite 文件默认建在 `$TMPDIR` 下，
每次运行自动重建。

## 撤销模型：定位的是“签发者 + 根标识”，不是 token

- 撤销表 `revocations` 的主键是 `(issuer, root_id)`，只保存撤销版本号与时间戳；
  不保存任何序列化 token、签名或根密钥。
- 根 macaroon 与所有衰减副本共享同一个 `root_id`。追加 caveat 只会延伸 HMAC 链、
  改变最终签名，不会改变 `root_id`，所以一条撤销记录覆盖整棵派生树。
- 为什么 token/签名黑名单不成立，演示里给出了直接证据：
  - 根签名与衰减副本签名不同；
  - v1（`MV1-`）与 v2（`MV2.`）两种线格式字节不同、签名相同；
  - 把 location 改成攻击者域名后线格式又变一次。
  按字节或根签名拉黑，以上三种变体都会漏掉。
- `location` 不参与 HMAC（macaroon 规范即如此），它只是路由提示；
  授权判定从不读取 location，因此改 location 既不能越权也不能逃逸撤销。

## 签发者必须来自认证通道

- 管理端（签发/撤销）通过 API Key 认证，服务端反查出 `issuer`（`authenticate_issuer`，
  `hmac.compare_digest` 常量时间比较）；生产环境对应 mTLS 主体或认证网关的 vhost。
- `issuer` 绝不取自 token 内的自报字段。两个签发者即使使用相同 `root_id`，
  在 `root_keys` 与 `revocations` 中也是各自独立的行；
  alpha 撤销 `(alpha, rid-42)` 不会影响 `(beta, rid-42)`，反之亦然。
- 用 alpha 的入口凭据提交 beta 命名空间的操作，会因为查不到对应密钥行而被通用错误拒绝。

## 验证与操作之间的版本检查 / 事务边界

示例采用**单事务串行化（serializable write transaction）**边界：

```
BEGIN IMMEDIATE
  1. 密码学签名链校验（在事务内重新读取 root_key）
  2. revocations 存在性检查（事务快照内的当前撤销版本）
  3. caveat 求值（未知 caveat fail-closed）
  4. 业务写入（余额扣减 + 流水）
COMMIT
```

- 撤销接口 `revoke()` 同样用 `BEGIN IMMEDIATE` 写同一数据库。SQLite 的写锁使
  业务事务与撤销事务全局互斥，结果只有一个线性顺序，不存在“先验证后撤销”的漏判窗口。
- 场景 1：业务事务先持锁 → 本次扣款成功提交，撤销事务排队随后生效；之后请求全部拒绝。
- 场景 2：请求先通过了纯密码学预检查（`verify_signature_offline`），等待期间撤销落盘；
  真正的 `debit` 在自己的事务内复查到撤销记录而回滚。这说明预检查只是“token 未被篡改”
  的瞬时证明，**不能缓存成长期有效的成功布尔值**；授权结论只在事务内、只对本次操作有效。
- 替代方案（读版本模式，适合无单一写库的部署）：认证网关缓存
  `current_revocation_version()`，在请求开始时记录版本 `v`；业务行带乐观锁列
  `checked_version >= v` 提交，若期间有撤销使全局版本前进则提交失败并重试/拒绝。
  无论哪种模式，版本检查与业务提交必须共享同一事务或同一乐观锁，不允许分两次调用。

## 拒绝路径与持久化

- 所有授权失败对外只返回通用文案 `authorization denied`；异常类型仅供服务内部区分。
- 根密钥仅存在于内存与 `root_keys` 表中，日志只打印 SHA-256 指纹；
  演示结尾断言全部输出中不出现根密钥的 hex/base64 原文。
- 撤销行持久化在 SQLite。场景 4 关闭并重开所有连接模拟进程重启，
  重启后 alpha、beta 的已撤销 token 仍然被拒。

## 演示覆盖的行为矩阵

| 变体 | 撤销前 | 撤销后 |
| --- | --- | --- |
| 根 macaroon | 放行 | 拒绝（`RevokedMacaroon`） |
| 追加 `account=alice` 的衰减副本 | 放行 | 拒绝（共享 root_id） |
| 衰减副本操作其他账户 | 拒绝（caveat） | 拒绝 |
| 篡改 location 的副本 | 放行（location 不参与签名） | 拒绝 |
| v1 / v2 重新序列化 | 放行 | 拒绝 |
| 翻转签名一位 | 拒绝（`BadMacaroon`） | 拒绝 |
| 另一 issuer 的同名 token | 放行 | 继续放行，直到它自己被撤销 |
| 重启进程后重放 | — | 撤销仍生效 |
