"""
本地假检索器演示：成功 / 不可读 / 找不到 三种结果在复用时的差别。

运行：.venv/bin/python demo/run_demo.py
"""

from __future__ import annotations

from referencing import Registry
from referencing import exceptions

from shared_retrieval import (
    CallerContext,
    build_resource,
    resolve_one,
)

ORDER_URI = "https://partner.example/schemas/order.json"
GONE_URI = "https://partner.example/schemas/does-not-exist.json"


def section(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def show(ctx: CallerContext, ref: str) -> None:
    outcome, detail = resolve_one(ctx, ref)
    print(f"  [{ctx.caller:>7}] {outcome:<7} {ref}  -> {detail}")


# ---------------------------------------------------------------------------
# 场景 A：按调用者隔离（推荐，可部署）
# ---------------------------------------------------------------------------

def demo_isolated() -> None:
    section("A. 每个调用者独立 CallerContext（缓存/Registry 私有，安全）")
    pricing = CallerContext("pricing")
    billing = CallerContext("billing")

    print("\n-- 第一次访问：三种结果 --")
    show(pricing, ORDER_URI)   # success：有权且文档存在
    show(billing, ORDER_URI)   # denied ：无权（授权先于存在性判断）
    show(pricing, GONE_URI)    # missing：有权，但后端没有该 URI
    show(billing, GONE_URI)    # denied ：无权者连"是否存在"都不应得知

    print("\n-- 第二次访问同一 URI：观察谁被真正缓存 --")
    show(pricing, ORDER_URI)   # 命中缓存，retrieval 不再增加
    show(billing, ORDER_URI)   # 仍是 denied：失败没被缓存成"不存在"
    show(pricing, GONE_URI)    # 仍是 missing：NoSuchResource 不被 lru_cache 缓存

    print("\n-- 缓存/调用计数 --")
    print(f"  pricing: {pricing.cache_info()}  "
          f"retrievals={pricing.retrieval_count} denied={pricing.denied_count} missing={pricing.missing_count}")
    print(f"  billing: {billing.cache_info()}  "
          f"retrievals={billing.retrieval_count} denied={billing.denied_count} missing={billing.missing_count}")

    print("\n-- 关键隔离断言：billing 拿不到 order，即使 pricing 已缓存它 --")
    outcome, _ = resolve_one(billing, ORDER_URI)
    assert outcome == "denied", outcome
    print("  OK: pricing 的成功缓存对 billing 不可见（无跨调用者泄露）。")


# ---------------------------------------------------------------------------
# 场景 B：错误地共享一个缓存/Registry（反例，展示越权）
# ---------------------------------------------------------------------------

def demo_shared_is_dangerous() -> None:
    section("B. 反例：两个调用者共用同一个 Registry + 同一个 lru_cache")

    # 用一个不带调用者、且不做授权的"全局" retriever —— 这正是把授权层
    # 漏在共享代码之外时会出现的形状。
    from functools import lru_cache

    def _raw(uri: str):
        # 直接绕过 ACL 取文档，模拟"共享检索代码忘了带调用者身份"
        from shared_retrieval import BACKEND_DOCUMENTS
        if uri not in BACKEND_DOCUMENTS:
            raise exceptions.NoSuchResource(ref=uri)
        return build_resource(BACKEND_DOCUMENTS[uri])

    @lru_cache(maxsize=None)
    def global_retrieve(uri: str):
        # 注意：这里没有任何 caller/ACL 判定，缓存键也只有 URI
        return _raw(uri)

    shared_registry = Registry(retrieve=global_retrieve)

    print("\n-- pricing 先正常读取并写入共享缓存 --")
    pricing_resolver = shared_registry.resolver()
    pricing_resolved = pricing_resolver.lookup(ORDER_URI)
    print(f"  [pricing] success -> {pricing_resolved.contents.get('type')}")

    print("\n-- billing 通过同一个 Registry 解析同一 URI --")
    billing_resolver = shared_registry.resolver()  # 看着是"新" resolver，
    billing_resolved = billing_resolver.lookup(ORDER_URI)  # 但底层是同一份缓存
    print(f"  [billing] 竟然 success -> {billing_resolved.contents.get('type')}")
    print("  !!! 越权：billing 本应 denied，却读到了合作方 schema。")
    print("  根因：Registry._resources 与 lru_cache 是进程级共享的，且")
    print("        retrieve 闭包里没有调用者身份，授权层被整体绕过。")


# ---------------------------------------------------------------------------
# 场景 C：缓存前提失效后的失效处理
# ---------------------------------------------------------------------------

def demo_invalidation() -> None:
    section("C. 前提失效：权限被收回 / 文档更新后清缓存")
    pricing = CallerContext("pricing")

    print("\n-- 填充缓存 --")
    show(pricing, ORDER_URI)
    before = pricing.cache_info()
    print(f"  缓存状态: {before}")

    print("\n-- 模拟权限被收回（ACL 变更），调用 invalidate() --")
    from shared_retrieval import ACL
    ACL["pricing"] = ()  # 收回整个命名空间的访问权
    pricing.invalidate()
    outcome, detail = resolve_one(pricing, ORDER_URI)
    print(f"  失效后再访问: {outcome} -> {detail}")
    assert outcome == "denied"
    print("  OK: 清缓存 + 重建 Registry 后，授权被重新评估，旧成功值不再放行。")


if __name__ == "__main__":
    demo_isolated()
    demo_shared_is_dangerous()
    demo_invalidation()
    print("\n全部场景演示完成。")
