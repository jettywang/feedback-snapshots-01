"""演示：对端在不同处理时刻断连，打印副作用日志与分类结果对照。

运行：.venv/bin/python -m retry_classifier.demo
"""

from retry_classifier.harness import Sim
import h2.errors


def show(title, sim):
    print(f"\n=== {title} ===")
    print(f"  服务器副作用日志（已执行的写）: {sim.server.side_effects}")
    for v in sim.client.classifier.classify_all():
        print(
            f"  stream {v.stream_id}: {v.category.value:<16} -> "
            f"{v.action.value:<15} | {v.reason}"
        )


def main():
    # 场景 1：GOAWAY 边界之外，协议保证未处理
    sim = Sim()
    s1 = sim.client.submit("POST", "/charge")
    s3 = sim.client.submit("POST", "/charge")
    s5 = sim.client.submit("POST", "/charge")
    sim.roundtrip()
    sim.server.apply(s1)
    sim.server.apply(s3)
    sim.server.goaway(last_stream_id=s3)
    sim.server.flush()
    sim.deliver_server_to_client()
    sim.cut()
    show("GOAWAY(last=3) 后断连：s5 未被处理，可重放", sim)

    # 场景 2：处理后、响应前断连（反例核心）
    sim = Sim()
    s1 = sim.client.submit("POST", "/charge")
    sim.roundtrip()
    sim.server.apply(s1)
    sim.cut()
    show("写已执行、无 GOAWAY 直接断连：裸 POST 必须业务决策", sim)

    # 场景 3：同样的断连，但应用给了幂等键
    sim = Sim()
    s1 = sim.client.submit("POST", "/charge", idempotency_key="txn-001")
    sim.roundtrip()
    sim.server.apply(s1)
    sim.cut()
    show("同上，但带幂等键：可自动重放（服务端按键去重）", sim)

    # 场景 4：REFUSED_STREAM vs CANCEL
    sim = Sim()
    s1 = sim.client.submit("POST", "/charge")
    s3 = sim.client.submit("POST", "/charge")
    sim.roundtrip()
    sim.server.apply(s3)  # s3 已执行才被 RST
    sim.server.reset(s1, h2.errors.ErrorCodes.REFUSED_STREAM)
    sim.server.reset(s3, h2.errors.ErrorCodes.CANCEL)
    sim.server.flush()
    sim.deliver_server_to_client()
    show("RST_STREAM：REFUSED_STREAM 可重放，CANCEL 不可混用", sim)


if __name__ == "__main__":
    main()
