# Argon2 Python 绑定秘密内存所有权审计

- 审计对象：argon2-cffi（仓库开发版 0.1.dev629）+ argon2-cffi-bindings 26.2.0 + cffi 2.1.1，CPython 3.12.11 / macOS arm64
- 审计方式：受控替身（tracking FFI + fake native lib）+ 一条真实 native 成功对照；仅使用合成 bytes/bytearray/str
- 记录边界：只记录对象类别、长度、生命周期事件（allocated / native-enter / backend-failed / zeroized / cffi-reclaimed / collected）。不打印秘密内容、不做内容比较、不扫描进程内存
- 复现：`.venv/bin/python audit/ownership_audit.py`（人读）、`--check`（仅断言）、`--json`（机读记录）；`.venv/bin/python -m pytest tests/test_secret_ownership_audit.py`

## 1. 接口分层与所有权边界

| 层 | 入口（真实接口） | 接收类型 | CFFI 输入由谁分配 | context/flags 由谁控制 |
|---|---|---|---|---|
| 高层 | PasswordHasher.hash/verify | str 或 bytes | 低层函数内部 ffi.new | 不可达；固定走便捷 API |
| 低层 | hash_secret / hash_secret_raw / verify_secret | bytes（类型注解强制） | 函数自身内联 ffi.new 临时对象 | 不可达；便捷 API 无 flags 形参 |
| Core | core(context, type) -> argon2_ctx | 调用方自建的 argon2_context 指针 | 调用方分配并保活 | 调用方设置 flags、allocate_cbk/free_cbk |

源码事实（src/argon2/low_level.py）：

- 三个便捷函数都用内联 `ffi.new("uint8_t[]", secret)` / `ffi.new("uint8_t[]", salt)` 构造一次性 C 数组，没有命名引用、没有 ffi.gc、没有 memset/清零调用。
- hash_secret 的输出 buf、hash_secret_raw 的输出 buf 同样是内联 ffi.new；返回值分别是 ffi.string(buf)（新 bytes）和 bytes(ffi.buffer(buf, hash_len))（拷贝出的新 bytes）。
- core() 是纯透传 lib.argon2_ctx(context, type)，docstring 明确警告 clearing buffers 由调用方负责。
- 绑定经 CFFI 仅导出 5 个函数：argon2_ctx、argon2_hash、argon2_verify、argon2_encodedlen、argon2_error_message；未导出任何 free/zeroize 原语。

## 2. 关键常量事实（运行期读取，非推断）

- ARGON2_DEFAULT_FLAGS == 0：便捷 API 内部的 argon2_hash/argon2_verify 不接受 flags，native 侧按 0 处理，即不请求清除密码/密钥。
- ARGON2_FLAG_CLEAR_PASSWORD == 1、ARGON2_FLAG_CLEAR_SECRET == 2 已通过 CFFI 暴露，但只有自建 argon2_context 的 core() 调用方能设置。
- native 动态库内存在 _clear_internal_memory 符号与 ARGON2_FLAG_CLEAR_* 字符串，说明清零能力在 native 层、由 flags 触发；绑定层在便捷路径上从不触发它。

## 3. 对象类别 x 长度 x 生命周期（合成输入，长度可复核）

合成基准：密码 SYNTHETIC_PASSWORD = 11 字节、盐 16 字节、hash_len=24。CFFI 对数组初始化器额外追加 1 个 NUL 元素，故 11 字节 bytes 的 C 后备长度为 12。

| 对象类别 | 长度（字节） | 所有者 | 生命周期 | 调用方能否清零 |
|---|---|---|---|---|
| 输入 bytes（直接传 bytes） | 11 | 调用方 | 调用期间被引用；不可变 | 否（TypeError，bytes 不可原地改） |
| str 经 _ensure_bytes 产出的 bytes | 按编码长度 | 高层封装临时对象 | hash/verify 返回后即无引用、可回收 | 否，但可用后即弃 |
| ffi.new uint8 密码 C 数组 | 12（含 NUL） | CFFI（内联临时） | 仅本次 native 调用；返回即由 CFFI 回收，回收不清零 | 否（无命名句柄） |
| ffi.new uint8 盐 C 数组 | 17（含 NUL） | CFFI | 同上 | 否 |
| 编码输出 char[]（hash_secret） | argon2_encodedlen(...)+1 = 84 | CFFI | 调用内；ffi.string 拷出后回收 | 否（编码哈希非秘密，但同样不可控） |
| 原始输出 uint8[]（hash_secret_raw） | 24 | CFFI | 调用内；bytes(ffi.buffer) 拷贝后回收 | 否 |
| 返回的 Python bytes/str | 82（str）/ 24（raw） | 调用方 | 由调用方引用计数/GC 决定 | 否（不可变）；改持 bytearray 后可清零 |
| core() 的 ctx.pwd/salt/out | 调用方指定 | 调用方 | 调用方保活，成功与失败都可读可写 | 是（命名 CData，可逐字节写 0） |
| native 工作内存（Argon2 内存块） | memory_cost KiB 级 | native 库 | 仅在 native 调用栈内 | 否；清零只由库实现与 flags 保证，Python 无句柄 |

## 4. 三种结局下仍可观测的对象

### 4.1 成功（场景 C0/S1/S4/S8，21 条不变量全 PASS）

- 调用返回后，所有内联 CFFI 数组（含密码的 12 字节副本）已脱离 Python 可观测句柄；S10 用自定义分配器证明它们在调用返回时被 CFFI 回收，回收事件 zeroized_before_free=False，全记录 zeroized 为空。
- 仍可观测的只有调用方自持的对象：原始输入 bytes、返回的 bytes/str；core() 路径下还有调用方命名的 ctx 及各缓冲区。
- native 工作内存的清零只能由库实现保证：便捷路径 flags=0，不触发 _clear_internal_memory 对密码区的处理；Python 绑定对此无承诺、无 API。

### 4.2 后端失败（S2/S5/S6/S9）

- 失败发生在进入 native 之后：事件序列固定为 allocated -> native-enter -> backend-failed。密码长度的 C 数组（12 字节）确实抵达 native 边界（S2 不变量）。
- 便捷 API 把非 OK 码转成 HashingError/VerificationError/VerifyMismatchError；异常路径同样没有任何清零，zeroized 为空，CFFI 临时数组照常回收、不清零。
- core() 失败时不抛异常，返回错误码（实测 -4）。因缓冲区归调用方所有，S9 证明失败后 ctx.pwd 仍可读（内容仍在）且调用方可自行逐字节清零成功。

### 4.3 调用方提前丢弃结果（S7/S10）

- hash_secret_raw 返回的是独立 Python bytes（24），与 CFFI 后备缓冲已脱钩；提前 del 后经 gc.collect，通过可弱引用持有者观测到回收事件 returned-raw-bytes。
- 但 bytes 不可原地清零（赋值抛 TypeError），调用方对已存在的 bytes 副本只能解除引用、等待回收；回收是否抹掉物理内存由分配器/GC 决定，API 层无法承诺。
- 可证明的替代：拷贝到 bytearray 后可原地写 0（S7 bytearray_zeroized_len=24）。这只能清零 bytearray 那份，原始 bytes 副本仍不可清零。

## 5. 因所有权 / API 边界无法承诺的清理

1. 便捷 API 的密码 C 副本：内联 ffi.new 无命名句柄，调用方拿不到，绑定也不 memset；清零与否取决于 CFFI 释放与 native 库内部行为，绑定层不承诺。
2. str 输入的编码副本：str.encode 产生不可变 bytes，调用方无法原地清零；寿命受 Python 对象模型约束。
3. 返回的 bytes/str：不可变，调用方只能丢引用，不能保证物理擦除；解释器内部还可能因子串/编码产生额外副本，库无法约束。
4. native 工作内存与跨线程残留：Python 侧无指针、无 free/zeroize 导出；只能依赖 Argon2 上游实现。free_cbk/allocate_cbk 仅在 core() 的 context 上可替换，便捷 API 固定为 NULL（native 默认分配器）。
5. 失败路径：便捷 API 无 flags、无 finally 清理，后端失败不改变上述 1-4。

## 6. 给现有调用方的清理责任与可替换接口建议

责任划分（可直接据此写安全说明）：

- 用 PasswordHasher / hash_secret* / verify_secret：调用方负责自己传入的 Python 对象与返回值的引用寿命；不要期待库清零密码 C 副本或 native 内存。
- 用 core()：调用方全权负责 context 内每个缓冲区的分配、保活与清零（与 docstring 一致），成功和失败路径都要在 finally 中处理。

可落地的做法：

- 优先传 bytes 而非 str，避免额外编码副本；若必须接 str，在边界编码后尽快丢弃字符串引用。
- 需要显式擦除的秘密，改用 core() 加命名 CData，在 finally 中对 ctx.pwd/ctx.salt/ctx.out 逐字节写 0（S9 已证明失败后仍可做）。
- 想让 native 帮你清密码/密钥区：在自建 context 上设置 flags = ARGON2_FLAG_CLEAR_PASSWORD | ARGON2_FLAG_CLEAR_SECRET（S8 证明 CLEAR_PASSWORD 会把 ctx.pwd 精确按 pwdlen 清零）；它清的是 context 指向的缓冲，便捷 API 无法使用。
- 需要自定义内存管理：通过 context 的 allocate_cbk/free_cbk 注入分配器，在 free_cbk 内先清零再释放；这是唯一能把释放即清零延伸到 native 工作内存的接口，便捷 API 不暴露。
- 对必须维持 bytes 返回的现有调用：保留 hash_secret_raw(...) -> bytes 签名不变；新增一个并列的显式管理接口（例如接收调用方预分配的可写缓冲作为输出，内部走 core() 写入并由调用方清零），让高保障场景有可选路径，而不破坏现有 bytes 调用方。
- 不要试图对 bytes 做原地清零，也不要把 gc.collect() 当安全擦除手段；这两点在 S7/S10 已被证伪或限定。

## 7. 证据与文件

- 审计脚本：audit/ownership_audit.py（11 个场景 + 21 条跨场景不变量断言，全部通过）
- 回归测试：tests/test_secret_ownership_audit.py（11 项，pytest 全绿；仓库全量 89 项通过）
- 真实对照 C0：对真实 native 库完成一次成功 hash/verify/raw，确认替身与真实往返共存、flags 常量读取自安装包而非硬编码
