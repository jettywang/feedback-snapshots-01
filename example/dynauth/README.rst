RFC 5176 CoA / Disconnect 服务端策略适配器
==========================================

本目录在 pyrad 之上实现一个可运行的动态授权（Dynamic Authorization）服务端
策略适配器，处理 RADIUS CoA-Request（43）与 Disconnect-Request（40）。它解决
“共享秘密校验通过不等于授权”的问题：密码学校验只证明报文来源，真正的控制范围
由发送端策略决定。

运行
----

进程内传输（无需绑定端口，仍执行真实 RADIUS 签名与校验）::

    python -m example.dynauth.demo

真实 UDP 传输（监听 RFC 3799，需要绑定端口权限）::

    python -m example.dynauth.demo --udp

单元测试::

    python -m pytest pyrad/tests/test_dynauth_policy.py

模块组成
--------

``constants.py``
    RADIUS 属性码、报文码与 RFC 5176 Error-Cause 常量。
``session_store.py``
    内存会话表，按 ``(NAS-IP, Acct-Session-Id)`` 建键，按显式标识组合定位。
``policy.py``
    策略引擎：发送端授权、会话定位、原子变更、幂等缓存、审计日志。
``transport.py``
    接收路径。先做 RADIUS 认证，再进入策略引擎；提供 UDP 与进程内两种传输。
``client.py``
    构造已签名请求并校验回复认证（``VerifyReply``）的客户端辅助类。
``fixtures.py``
    演示用会话表、发送端与授权策略；``dictionary`` 增补了 Error-Cause。
``demo.py``
    端到端演示，打印会话表前后状态与审计轨迹。

安全语义
--------

1. 认证与授权分离。传输层用共享秘密校验 RFC 5176 Request Authenticator，存在
   Message-Authenticator 时校验 HMAC-MD5；未注册发送端或秘密错误的报文按协议
   静默丢弃。认证通过后，策略引擎再按发送端绑定的 NAS 与操作（CoA/Disconnect）
   授权，越权返回 NAK 并带 Error-Cause 501（Administratively-Prohibited）。
2. 显式会话标识。必须携带 NAS-IP-Address，并至少给出一个会话级标识
   （Acct-Session-Id、Framed-IP-Address、Calling-Station-Id 等）。仅靠
   User-Name 一律拒绝（402 Missing-Attribute），不允许按用户名广播断线。
3. 唯一目标。标识命中多个会话时拒绝：Disconnect 返回 508
   Session-Context-Not-Removable，CoA 返回 503 Session-Context-Not-Found；
   命中零个会话返回 503。
4. 原子性。所有校验（授权、定位、属性可支持性）在任何状态修改之前完成；NAK 路径
   不触碰会话，审计条目的 before/after 快照相同，可证明无控制副作用。
5. 幂等。缓存按“发送端 + Identifier + 原始报文 MD5”记录已处理结果；重传报文
   直接返回原 ACK/NAK，不会二次修改会话，审计标记为 replay。
6. 协议化错误原因。NAK 携带 RFC 5176 Error-Cause（401/402/407/501/503/508），
   回复用 Response Authenticator 签名，客户端校验失败即拒绝该回复。

演示场景（见 ``demo.py`` 输出）
------------------------------

* 合法 CoA 属性变更（Filter-Id、Session-Timeout）；
* 同一报文重放，返回原 ACK 且不二次变更；
* 按 Framed-IP-Address 的合法断线；
* 跨 NAS 断线被发送端策略拒绝（501）；
* 仅允许 CoA 的发送端发起断线被拒绝（501）；
* 仅 User-Name 的断线被拒绝（402）；
* 共享 Calling-Station-Id 命中两个会话的歧义请求被拒绝（508）；
* 未知会话（503）、不支持的 CoA 属性（401）、无变更属性（402）；
* 错误共享秘密与未注册发送端的报文被静默丢弃。
