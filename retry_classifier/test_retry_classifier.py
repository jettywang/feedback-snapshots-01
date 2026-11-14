"""可重跑场景：本地对端在不同处理时刻关闭连接，校验分类与副作用一致。"""

import h2.errors

from retry_classifier.classifier import Action, Category
from retry_classifier.harness import Sim


def make_sim_with_requests(specs):
    """specs: [(method, path, idempotency_key), ...]，提交并送达服务器。"""
    sim = Sim()
    sids = []
    for method, path, key in specs:
        sids.append(sim.client.submit(method, path, idempotency_key=key))
    sim.roundtrip()
    return sim, sids


def assert_consistent(sim):
    """不变量：凡被证明"未处理/未发送/被拒绝"的流，绝不能有副作用。"""
    for v in sim.client.classifier.classify_all():
        if v.category in (Category.NOT_SENT, Category.NOT_PROCESSED, Category.REFUSED):
            assert v.stream_id not in sim.server.side_effects, (
                f"stream {v.stream_id} 分类为 {v.category.value} 但服务器已产生副作用"
            )


def test_goaway_boundary_proves_unprocessed():
    """GOAWAY(3)：流 5 在边界之外，协议保证未处理，可直接重放。"""
    sim, (s1, s3, s5) = make_sim_with_requests(
        [("POST", "/write", None)] * 3
    )
    sim.server.apply(s1)
    sim.server.apply(s3)
    sim.server.respond(s1)
    sim.server.respond(s3)
    sim.server.goaway(last_stream_id=s3)
    sim.server.flush()
    sim.deliver_server_to_client()
    sim.cut()

    verdicts = {v.stream_id: v for v in sim.client.classifier.classify_all()}
    assert verdicts[s1].category is Category.COMPLETED
    assert verdicts[s3].category is Category.COMPLETED
    assert verdicts[s5].category is Category.NOT_PROCESSED
    assert verdicts[s5].action is Action.REPLAY
    assert_consistent(sim)


def test_counterexample_post_processed_then_goaway_no_response():
    """反例：POST 已执行、GOAWAY 已发但响应未发——"没响应"≠"没执行"。

    朴素策略"把所有未完成流放回队列"会导致写操作执行两次；
    分类器对裸 POST 必须给出 ASK_APPLICATION。
    """
    sim, (s1,) = make_sim_with_requests([("POST", "/charge", None)])
    sim.server.apply(s1)  # 写操作已生效
    sim.server.goaway(last_stream_id=s1)  # last_stream_id 覆盖 s1："可能已处理"
    sim.server.flush()
    sim.deliver_server_to_client()
    sim.cut()

    (v,) = sim.client.classifier.classify_all()
    assert v.category is Category.MAYBE_PROCESSED
    assert v.action is Action.ASK_APPLICATION  # 绝不自动重放

    # 演示朴素策略的后果：把未完成流直接重放到新连接
    naive_sim = Sim()
    replayed = naive_sim.client.submit("POST", "/charge")
    naive_sim.roundtrip()
    naive_sim.server.apply(replayed)
    total_effects = len(sim.server.side_effects) + len(naive_sim.server.side_effects)
    assert total_effects == 2, "朴素重放导致同一笔写执行了两次（反例成立）"


def test_connection_reset_without_goaway_inflight_is_maybe():
    """无 GOAWAY 直接断连：在途 POST 无法证明，未刷出的流可安全重放。"""
    sim = Sim()
    s1 = sim.client.submit("POST", "/charge")
    sim.roundtrip()
    sim.server.apply(s1)
    s3 = sim.client.submit("POST", "/charge2")  # 已注册但尚未刷到导线
    sim.cut()

    verdicts = {v.stream_id: v for v in sim.client.classifier.classify_all()}
    assert verdicts[s1].category is Category.MAYBE_PROCESSED
    assert verdicts[s1].action is Action.ASK_APPLICATION
    assert verdicts[s3].category is Category.NOT_SENT
    assert verdicts[s3].action is Action.REPLAY
    assert_consistent(sim)


def test_refused_stream_means_not_processed():
    """RST_STREAM(REFUSED_STREAM) 是对端'未处理'的显式声明，POST 也可重放。"""
    sim, (s1,) = make_sim_with_requests([("POST", "/charge", None)])
    sim.server.reset(s1, h2.errors.ErrorCodes.REFUSED_STREAM)
    sim.server.flush()
    sim.deliver_server_to_client()

    (v,) = sim.client.classifier.classify_all()
    assert v.category is Category.REFUSED
    assert v.action is Action.REPLAY
    assert_consistent(sim)


def test_rst_cancel_is_not_a_refusal():
    """RST_STREAM(CANCEL) 只表示流被中止：已执行的写不能当作没发生。"""
    sim, (s1,) = make_sim_with_requests([("POST", "/charge", None)])
    sim.server.apply(s1)  # 服务器处理后又中止了流
    sim.server.reset(s1, h2.errors.ErrorCodes.CANCEL)
    sim.server.flush()
    sim.deliver_server_to_client()

    (v,) = sim.client.classifier.classify_all()
    assert v.category is Category.MAYBE_PROCESSED
    assert v.action is Action.ASK_APPLICATION
    assert "REFUSED" in v.reason  # 原因中明确区分两种 RST 语义


def test_multiple_goaways_take_minimum_bound():
    """多个 GOAWAY 边界取最小值（RFC 允许调低；取最小最保守）。"""
    sim, (s1, s3, s5, s7) = make_sim_with_requests(
        [("POST", "/write", None)] * 4
    )
    sim.server.apply(s1)
    sim.server.goaway(last_stream_id=s5)
    sim.server.goaway(last_stream_id=s1)  # 追加 GOAWAY 调低边界
    sim.server.flush()
    sim.deliver_server_to_client()
    sim.cut()

    verdicts = {v.stream_id: v for v in sim.client.classifier.classify_all()}
    assert verdicts[s1].category is Category.MAYBE_PROCESSED
    for sid in (s3, s5, s7):
        assert verdicts[sid].category is Category.NOT_PROCESSED
        assert verdicts[sid].action is Action.REPLAY
    assert_consistent(sim)


def test_partial_response_means_processed():
    """响应已开始但未完整：请求已被处理，裸 POST 禁止自动重放。"""
    sim, (s1,) = make_sim_with_requests([("POST", "/charge", None)])
    sim.server.apply(s1)
    sim.server.respond_headers_only(s1)
    sim.server.flush()
    sim.deliver_server_to_client()
    sim.cut()

    (v,) = sim.client.classifier.classify_all()
    assert v.category is Category.PARTIAL_RESPONSE
    assert v.action is Action.ASK_APPLICATION


def test_safe_method_maybe_processed_can_replay():
    """同样的 MAYBE_PROCESSED，GET 因方法幂等可自动重放——依据来自应用声明。"""
    sim, (s1,) = make_sim_with_requests([("GET", "/balance", None)])
    sim.server.apply(s1)
    sim.cut()

    (v,) = sim.client.classifier.classify_all()
    assert v.category is Category.MAYBE_PROCESSED
    assert v.action is Action.REPLAY


def test_idempotency_key_allows_post_replay():
    """应用提供幂等键的 POST：MAYBE_PROCESSED 也可重放（服务端按键去重）。"""
    sim, (s1,) = make_sim_with_requests(
        [("POST", "/charge", "txn-2026-0001")]
    )
    sim.server.apply(s1)
    sim.cut()

    (v,) = sim.client.classifier.classify_all()
    assert v.category is Category.MAYBE_PROCESSED
    assert v.action is Action.REPLAY


def test_completed_response_needs_no_retry():
    """完整响应送达后断连：直接交付，不涉及重试。"""
    sim, (s1,) = make_sim_with_requests([("POST", "/charge", None)])
    sim.server.apply(s1)
    sim.server.respond(s1)
    sim.server.flush()
    sim.deliver_server_to_client()
    sim.cut()

    (v,) = sim.client.classifier.classify_all()
    assert v.category is Category.COMPLETED
    assert v.action is Action.DELIVER
