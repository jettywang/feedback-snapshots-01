# AMQP 连接/通道共用评审的内存替身

无 socket、无 broker 进程的 Pika 分派与确认模型。

- `inmemory_amqp.py`：`Broker`/`Connection`/`Channel`，复刻 blocking 单 IOLoop 与
  pooled 每通道 worker 两种分派，关闭原因复用 `pika.exceptions` 的真实异常类。
- `run_scenarios.py`：四类场景（阻塞、主动关停、确认与重投、连接级身份），对比
  SHARED（一条连接两条通道）与 SPLIT（两条连接）。
- `REVIEW.md`：代码评审、观察取舍表与最终配置建议。

运行：

```
python3 -m amqp_topology_review.run_scenarios
```
