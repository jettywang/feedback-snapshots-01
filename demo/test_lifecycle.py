"""
回归测试：三种检索结果在按调用者隔离的缓存下的复用行为。

运行（在仓库根目录）：
    PYTHONPATH=demo .venv/bin/python -m pytest -q demo/test_lifecycle.py
"""

from __future__ import annotations

import pytest

from shared_retrieval import (
    ACL,
    CallerContext,
    resolve_one,
)

ORDER_URI = "https://partner.example/schemas/order.json"
GONE_URI = "https://partner.example/schemas/does-not-exist.json"


@pytest.fixture
def pricing():
    return CallerContext("pricing")


@pytest.fixture
def billing():
    return CallerContext("billing")


def test_success_is_cached_within_caller(pricing):
    outcome, _ = resolve_one(pricing, ORDER_URI)
    assert outcome == "success"
    assert pricing.retrieval_count == 1

    outcome2, _ = resolve_one(pricing, ORDER_URI)
    assert outcome2 == "success"
    # 第二次命中 lru_cache，没有再次触发 retrieve
    assert pricing.retrieval_count == 1
    assert pricing.cache_info().hits == 1


def test_denied_is_never_cached(billing):
    for _ in range(3):
        outcome, _ = resolve_one(billing, ORDER_URI)
        assert outcome == "denied"
    # 失败不写入 lru_cache，每次都重新执行授权判断
    assert billing.cache_info().currsize == 0
    assert billing.denied_count == 3


def test_missing_is_distinct_from_denied(pricing, billing):
    # 有权但文档不存在 -> missing
    assert resolve_one(pricing, GONE_URI)[0] == "missing"
    assert pricing.missing_count == 1
    # 无权者访问同一 URI -> denied（不暴露存在性）
    assert resolve_one(billing, GONE_URI)[0] == "denied"


def test_no_cross_caller_cache_leak(pricing, billing):
    # pricing 先把成功结果放进自己的缓存
    assert resolve_one(pricing, ORDER_URI)[0] == "success"
    assert pricing.cache_info().currsize == 1
    # billing 拥有独立缓存，仍然被拒绝
    assert resolve_one(billing, ORDER_URI)[0] == "denied"
    assert billing.cache_info().currsize == 0


def test_invalidation_re_evaluates_authorization(pricing, monkeypatch):
    assert resolve_one(pricing, ORDER_URI)[0] == "success"

    monkeypatch.setitem(ACL, "pricing", ())  # 权限被收回
    pricing.invalidate()

    assert resolve_one(pricing, ORDER_URI)[0] == "denied"
    assert pricing.cache_info().currsize == 0
