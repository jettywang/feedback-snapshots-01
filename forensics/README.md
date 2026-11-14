# forensics：RADIUS 承载 EAP-TLS 的离线与只读重组

基于 pyrad 的取证组件，不打开套接字、不接触真实认证服务器。输入为抓包
得到的 RADIUS 报文字节、接收时刻和仅用于校验的测试共享秘密。

## 用法

```python
from forensics.eap_tls_reassembly import EapTlsReassembler

captures = [(raw_bytes, received_at), ...]  # 顺序任意，按接收时刻排序
report = EapTlsReassembler(b'test-shared-secret').process(captures)
print(report.render())
```

## 处理流程

1. **逐包验真**：Access-Request 校验 Message-Authenticator；应答先按
   RADIUS Identifier 匹配请求，再校验 Response Authenticator 与
   Message-Authenticator（pyrad `VerifyReply`）。验真失败的包不参与重组；
   无法验真的包（缺 Message-Authenticator、找不到匹配请求）默认仍重组但
   标记 `unverifiable`，可用 `require_message_authenticator=True` 改为丢弃。
2. **EAP 拼接**：同一包内多个 EAP-Message 属性按原始顺序串接（RFC 3579）。
3. **RFC 5216 分片重组**：按会话与方向处理 L/M/S 标志、TLS Message
   Length、空片段确认（ACK）、EAP Identifier 连续性和 State 一致性。
   - 重复传输（RADIUS 层同 code/id/authenticator，或 EAP 层同 Identifier
     同负载）绝不追加两次；
   - 丢包/乱序只标记为截断或关联不明，绝不猜测补齐；
   - 会话数、单消息字节、全局重组字节均有上限（`max_sessions`、
     `max_message_bytes`、`max_total_bytes`）。

## 输出

`report.sessions` 中每条 TLS 消息带有 `complete` / `truncated` /
`unattributable` 状态；每个字节段（`Segment`）记录来源包序号、RADIUS
Identifier、EAP Identifier 及 EAP-Message 属性的字节范围（`AttrSpan`）。
无法归属会话的字节进入 `sessions[None]`。`render()` 输出人读报告。

## 范围声明

RADIUS 验真通过且 TLS 字节重组完整，**不等于**已验证客户端证书或 TLS
Finished：离线重组不校验证书链、握手签名与密钥协商。

## 测试

```sh
.venv/bin/python -m pytest forensics
```

测试用 pyrad 离线构造两个交错会话、一次重复片段、一个伪造包、一条截断
消息和一段孤儿片段（`forensics/tests/test_eap_tls_reassembly.py`）。
