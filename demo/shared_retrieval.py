"""
共享的进程内检索代码（两个规则服务复用的部分）。

设计要点
========
两个规则服务：
  * ``billing``  —— 无权读取合作方 schema（partner schema）。
  * ``pricing``  —— 有权读取合作方 schema。

它们要复用同一套 ``referencing`` 检索/解析代码，但权限不同。
本模块刻意把代码分成两层：

1. 与调用者无关的纯逻辑层（可安全共享，无状态）：
   ``fetch_document`` / ``build_resource`` / ``resolve_one``。
   这些对象里不持有任何按调用者缓存的数据。

2. 组合/授权层（每个调用者一份，禁止共享）：
   ``CallerContext`` 持有该调用者专属的 Registry 与 lru_cache。
   授权判定（ACL）只在这里、并且只在真正的 retrieve 回调里发生。
"""

from __future__ import annotations

from functools import lru_cache
from dataclasses import dataclass, field

from referencing import Registry, Resource
from referencing import exceptions

# ---------------------------------------------------------------------------
# 假的合作方后端 + ACL。真实系统里这是网络/DB 调用与权限服务。
# ---------------------------------------------------------------------------

# URI -> 序列化 JSON 文档（模拟合作方 schema 存储）
BACKEND_DOCUMENTS: dict[str, str] = {
    "https://partner.example/schemas/order.json": (
        '{"$schema": "https://json-schema.org/draft/2020-12/schema",'
        ' "$id": "https://partner.example/schemas/order.json",'
        ' "type": "object", "properties": {"sku": {"type": "string"}}}'
    ),
}

# 调用者 -> 允许访问的 URI 前缀（模拟授权范围 / 合作方命名空间）。
# 授权按"范围"判定，与某个具体 URI 当前是否存在无关，这样才能区分
# 「无权访问」(denied) 与「有权但该文档不存在」(missing)。
ACL: dict[str, tuple[str, ...]] = {
    # pricing 可以读整个合作方 schema 命名空间（含其中尚不存在的 URI）
    "pricing": ("https://partner.example/schemas/",),
    # billing 对合作方命名空间没有任何授权
    "billing": (),
}


class AccessDenied(Exception):
    """规则服务自身的授权失败，区别于 NoSuchResource。"""


def is_authorized(caller: str, uri: str) -> bool:
    return any(uri.startswith(prefix) for prefix in ACL.get(caller, ()))


def fetch_document(caller: str, uri: str) -> str:
    """
    纯逻辑：从合作方后端取原始文档，并在此处强制执行授权。

    - 不可读 -> AccessDenied（调用者无权，绝不能缓存成"不存在"）
    - 找不到 -> NoSuchResource（后端确实没有这个 URI）
    """
    if not is_authorized(caller, uri):
        raise AccessDenied(caller, uri)
    try:
        return BACKEND_DOCUMENTS[uri]
    except KeyError:
        # 按 referencing 的约定：retrieve 回调抛 NoSuchResource 表示"确实没有"
        raise exceptions.NoSuchResource(ref=uri) from None


def build_resource(serialized: str) -> Resource:
    """纯逻辑：反序列化并构造 Resource。与调用者无关，可安全共享。"""
    import json

    return Resource.from_contents(json.loads(serialized))


# ---------------------------------------------------------------------------
# 组合/授权层：每个调用者独立一份，内部缓存互不可见
# ---------------------------------------------------------------------------


@dataclass
class CallerContext:
    """
    一个调用者（规则服务）的检索生命周期容器。

    每个调用者新建一个实例，因此：
      * ``_cache`` 是该调用者私有的 lru_cache；
      * ``Registry`` 也是该调用者私有的，retrieve 回调闭包绑定了 caller；
      * Registry 内的 ``_resources``（爬取/检索后写入的内存缓存）天然隔离。
    """

    caller: str
    retrieval_count: int = 0
    denied_count: int = 0
    missing_count: int = 0
    _registry: Registry = field(init=False)

    def __post_init__(self) -> None:
        # 每个调用者一个全新的 lru_cache：缓存键只有 URI，
        # 但因为缓存对象本身按调用者隔离，所以不会跨调用者串数据。
        @lru_cache(maxsize=None)
        def cached_retrieve(uri: str) -> Resource:
            self.retrieval_count += 1
            try:
                serialized = fetch_document(self.caller, uri)
            except AccessDenied:
                self.denied_count += 1
                raise
            except exceptions.NoSuchResource:
                self.missing_count += 1
                raise
            return build_resource(serialized)

        self._cached_retrieve = cached_retrieve
        self._registry = Registry(retrieve=cached_retrieve)

    @property
    def registry(self) -> Registry:
        return self._registry

    def resolver(self, base_uri: str = ""):
        # Resolver 是不可变值对象，按请求/调用现场创建；它内部指向的
        # 仍是本调用者私有的 Registry，因此不会把别的调用者的缓存带进来。
        return self._registry.resolver(base_uri=base_uri)

    def cache_info(self):
        return self._cached_retrieve.cache_info()

    def invalidate(self) -> None:
        """前提失效时调用：清掉本调用者的全部缓存并重建 Registry。"""
        self._cached_retrieve.cache_clear()
        self.__post_init__()


# ---------------------------------------------------------------------------
# 纯逻辑：一次解析。Resolver/Registry 由调用者传入，函数本身无状态。
# ---------------------------------------------------------------------------


def resolve_one(ctx: CallerContext, ref: str):
    """
    返回 (outcome, detail)。
    outcome ∈ {"success", "denied", "missing"}。
    把三类异常归一成稳定结果，便于上层区分"不可读"和"找不到"。
    """
    resolver = ctx.resolver()
    try:
        resolved = resolver.lookup(ref)
    except exceptions.Unresolvable as error:
        # 异常可能被包两层，需要沿因果链判断根因：
        #   授权失败: Unresolvable -> Unretrievable -> AccessDenied
        #   确实没有: Unresolvable（根因是 retrieve 抛的 NoSuchResource）
        cause = error
        while cause is not None:
            if isinstance(cause, AccessDenied):
                return (
                    "denied",
                    "caller is not authorized for this partner schema",
                )
            cause = cause.__cause__
        return "missing", "the partner backend has no such URI"
    return "success", resolved.contents
