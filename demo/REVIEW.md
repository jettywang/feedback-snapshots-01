# 两个规则服务复用 `referencing` 检索代码的安全评审与生命周期方案

## 1. 背景与威胁模型

- 两个规则服务：`pricing`（可读合作方 schema）与 `billing`（不可读）。
- 二者要共用同一套进程内检索/解析代码，但**授权边界不同**。
- 核心风险是**跨调用者的缓存泄露（confused-deputy / cache poisoning）**：
  高权限调用者把合作方 schema 读进共享缓存后，低权限调用者命中同一缓存，
  授权回调不再被执行，于是越权读到数据。

结论先行：**能共享的是无状态的纯逻辑；带状态的缓存与 Registry 必须按调用者隔离。**

## 2. 各对象能否安全复用

| 对象 | 内部是否持有按调用者的状态 | 能否跨调用者共享 | 说明 |
| --- | --- | --- | --- |
| `Specification` / `Resource` | 否（不可变值对象） | 可共享 | 纯数据 + 行为，不含调用者信息。 |
| `fetch_document` / `build_resource` 等纯函数 | 否 | 可共享 | 授权判定作为入参 `caller` 显式传入，不闭包全局身份。 |
| `to_cached_resource` 产生的 retriever | **是**：底层是模块级 `lru_cache`，键只有 URI | **不可共享** | 见 `referencing/retrieval.py:77`，缓存不区分调用者。 |
| `Registry` 实例 | **是**：`_resources`/`_anchors`/`_uncrawled` 会累积检索与爬取结果 | **不可共享** | 见 `referencing/_core.py:317` 与 `get_or_retrieve`（`:405`），命中 `_resources` 时直接返回，**不再调用 retrieve，授权被绕过**。 |
| `Resolver` | 持有指向某个 Registry 的引用 + base_uri/previous | 不可跨调用者共享 | 它本身不可变、可按请求廉价创建；安全与否完全取决于它指向的 Registry。 |
| `Retrieved` / `Resolved` | 单次结果值对象 | 可共享（只读） | 不要把它回写进别的调用者的 Registry。 |

要点：`Registry` 是**不可变**的（每次变更返回新实例），这让"每调用者一份"
在实现上很自然——隔离不会产生同步问题，但也意味着**绝不能把两个调用者的
Registry `combine()` 到一起**（`combine` 会合并 `_resources`，`:545`）。

## 3. 在哪一层区分调用者

分两层，授权只放在组合/授权层：

1. **纯逻辑层（共享，无状态）**
   - `fetch_document(caller, uri)`、`build_resource(serialized)`、`resolve_one(ctx, ref)`。
   - 不持有缓存；`caller` 作为显式参数，便于测试与审计。

2. **组合/授权层（每调用者一份，`CallerContext`）**
   - 每个规则服务一个实例，内部新建**私有 `lru_cache` + 私有 `Registry`**。
   - retrieve 回调以闭包绑定该实例的 `caller`，授权（ACL）只在这里、且只在
     真正发生后端读取时执行。
   - `Resolver` 在每次解析时由该 context 的 Registry 派生，用完即弃。

这样即使两个服务跑在同一进程，缓存命名空间也互不可见；共享的只是函数代码。

## 4. 三种结果在复用时的差别（演示已验证）

| 结果 | retrieve 行为 | 是否进缓存 | 复用后的表现 |
| --- | --- | --- | --- |
| 成功 success | 返回 `Resource` | 是（lru_cache 与 Registry 都记） | 同调用者第二次命中缓存、不再回源；**跨调用者不可见** |
| 不可读 denied | 抛 `AccessDenied`（非约定异常） | 否 | 每次都重新鉴权；异常链为 `Unresolvable → Unretrievable → AccessDenied`，需遍历因果链识别，不能与 missing 混淆 |
| 找不到 missing | 抛 `NoSuchResource` | 否 | 每次都重新回源确认；在 `lookup` 中被归一为 `Unresolvable` |

两个关键的负面结果都**不被缓存**（异常不会写入 `lru_cache`，Registry 也只在
成功路径 `with_resource`，见 `_core.py:432`）。这天然避免了"一次无权/不存在
被永久缓存成否定结论"，但代价是否定结果每次都会重新执行鉴权/回源。

`denied` 与 `missing` 必须可区分：授权按**命名空间前缀**判定，与具体 URI 是否
存在无关。无权者连"文档是否存在"都不应得知，因此无权访问不存在的 URI 也返回 denied。

## 5. 可部署的生命周期安排

- **启动/装配（composition root）**：为每个规则服务各建一个 `CallerContext`
  （单例，生命周期 = 服务生命周期）。共享纯函数模块，但不共享 context。
- **请求处理**：从 context 取私有 Registry，按需 `resolver()` 派生 Resolver；
  Resolver 不跨请求缓存。成功结果进入该调用者私有缓存。
- **并发**：`lru_cache` 单 key 原子、`Registry` 不可变，线程安全；
  多线程/协程共享同一 context 不需要额外锁。
- **容量**：无界 `lru_cache` 与 Registry 会随 URI 增长，生产环境应给 `lru_cache`
  设 `maxsize`（TTL 需自行封装），并对 Registry 大小做监控/上限。

### 哪些前提失效时必须清缓存（`invalidate()` = `cache_clear()` + 重建 Registry）

1. **授权/ACL 变更**：权限授予或收回。最敏感——否则旧的成功值会让被收回权限的
   调用者继续读到数据（演示场景 C 已复现并验证修复）。
2. **合作方 schema 内容变更**：同一 URI 的文档更新，而缓存键只有 URI、不带版本。
   优先让上游使用**版本化 URI / ETag**；做不到时，收到变更事件就清该 URI（或整域）缓存。
3. **调用者身份或信任边界变化**：服务账户切换、租户合并/拆分、密钥轮换后。
4. **检索后端故障/数据损坏被部分缓存**：`CannotDetermineSpecification` 等不被缓存，
   但若上层曾把降级结果写入 Registry，需要在后端恢复后清理。
5. **进程/配置热更新**：修改了 retrieve 闭包捕获的 ACL、endpoint、序列化方式时，
   旧闭包仍在旧缓存里，必须重建 context。

清缓存的粒度建议：能定位到 URI 就只清该 key（`lru_cache` 支持 `cache_discard`
需自行包装；Registry 用 `remove(uri)`），定位不到（如 ACL 大范围变更）再整 context 重建。

## 6. 运行方式

```sh
# 演示三种结果 + 越权反例 + 失效处理
PYTHONPATH=demo .venv/bin/python demo/run_demo.py

# 回归测试
PYTHONPATH=demo .venv/bin/python -m pytest -q demo/test_lifecycle.py
```

文件：
- `demo/shared_retrieval.py`：分层的共享检索代码与 `CallerContext`。
- `demo/run_demo.py`：成功/不可读/找不到、共享反例、缓存失效三组演示。
- `demo/test_lifecycle.py`：5 条断言式回归测试。
