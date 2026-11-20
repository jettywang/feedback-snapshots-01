"""Drive the in-memory AMQP model through the three effects in the review.

Topologies:
  SHARED  - two security domains' consumers on ONE connection, two channels
  SPLIT   - one connection per security domain, one channel each

Each scenario prints what the affected side does and what the other side
observably does, for both dispatch models (blocking single IOLoop vs pooled
per-channel worker). Run: python3 amqp_topology_review/run_scenarios.py
"""

from __future__ import annotations

import threading
import time

from pika.exceptions import ChannelWrongStateError

from amqp_topology_review.inmemory_amqp import (
    Broker,
    Connection,
    MODEL_BLOCKING,
    MODEL_POOLED,
)

LINE = '=' * 78


def heading(title: str) -> None:
    print(f'\n{LINE}\n{title}\n{LINE}')


def make_broker() -> Broker:
    broker = Broker('lab')
    # A shared connection must carry ONE identity. Granting it both domains
    # means that identity holds the union of both consumers' privileges.
    broker.acl = {
        'payments': {'svc-pay', 'svc-shared'},
        'telemetry': {'svc-tel', 'svc-shared'},
    }
    broker.queue_declare('payments.settle')
    broker.queue_declare('telemetry.events')
    return broker


_RUN = {'n': 0}


def fresh_queues(broker: Broker) -> tuple[str, str]:
    """Unique queue names per run so subscriptions never bleed across cases."""
    _RUN['n'] += 1
    suffix = f'r{_RUN["n"]}'
    pay_q = f'payments.settle.{suffix}'
    tel_q = f'telemetry.events.{suffix}'
    broker.queue_declare(pay_q)
    broker.queue_declare(tel_q)
    return pay_q, tel_q


def build_shared(model: str, **kw) -> tuple[Broker, Connection, object, object]:
    broker = make_broker()
    conn = Connection(broker,
                      identity='svc-shared',
                      vhost='/prod',
                      model=model,
                      **kw)
    pay_ch = conn.channel()
    tel_ch = conn.channel()
    return broker, conn, pay_ch, tel_ch


def build_split(model: str, **kw):
    broker = make_broker()
    pay_conn = Connection(broker, 'svc-pay', '/prod', model, **kw)
    tel_conn = Connection(broker, 'svc-tel', '/prod', model, **kw)
    return broker, pay_conn, tel_conn, pay_conn.channel(), tel_conn.channel()


# --------------------------------------------------------------------------
# Scenario 1: one side blocks inside its delivery handler.
# --------------------------------------------------------------------------
def scenario_blocking(model: str, shared: bool) -> None:
    label = 'SHARED one connection, two channels' if shared else 'SPLIT two connections'
    heading(f'1. BLOCKING HANDLER  [{model}]  {label}')
    kw = {}
    if model == MODEL_POOLED:
        # Small queue so an overflow is reached without a 30 s wait.
        kw = {'work_queue_maxsize': 3, 'work_queue_put_timeout': 0.5}
    if shared:
        broker, conn, pay_ch, tel_ch = build_shared(model, **kw)
        pay_conn = tel_conn = conn
    else:
        broker, pay_conn, tel_conn, pay_ch, tel_ch = build_split(model, **kw)

    blocker = threading.Event()
    observed = {'tel_processed': 0, 'pay_processed': 0, 'hb_inside': None}
    stall = threading.Event()

    def pay_handler(ch, delivery):
        observed['pay_processed'] += 1
        if model == MODEL_BLOCKING:
            # On the single-IOLoop model the handler occupies the connection's
            # only dispatch thread; record that heartbeats stop for the stall.
            observed['hb_inside'] = pay_conn.heartbeat_running
            stall.wait(0.4)
        else:
            # The pooled model runs this on the channel's own worker, so a
            # block leaves the IOLoop free for the sibling until released.
            blocker.wait(1.5)

    def tel_handler(ch, delivery):
        observed['tel_ran_at'] = time.monotonic()
        observed['tel_processed'] += 1
        ch.basic_ack(delivery.tag)

    pay_ch.basic_qos(2)
    tel_ch.basic_qos(2)
    pay_q, tel_q = fresh_queues(broker)
    pay_ch.basic_consume(pay_q, pay_handler)
    tel_ch.basic_consume(tel_q, tel_handler)

    if model == MODEL_BLOCKING:
        def publish_telemetry():
            # Enqueues onto the connection's single worker; the handler cannot
            # start until the payments handler releases that worker.
            observed['tel_enqueued_at'] = time.monotonic()
            broker.publish(tel_q, 'tel-0', tel_conn)

        broker.publish(pay_q, 'pay-0', pay_conn)  # enters the 0.6 s stall
        t = threading.Thread(target=publish_telemetry)
        t.start()
        time.sleep(0.2)
        print('  payments handler holds the single connection IOLoop:')
        print(f'    payments processed : {observed["pay_processed"]}')
        print(f'    telemetry processed mid-stall: '
              f'{observed["tel_processed"]}  (0 = sibling starved)')
        print(f'    heartbeat observed inside the handler: '
              f'{observed["hb_inside"]} (False = no heartbeats for the stall)')
        t.join()
        time.sleep(0.45)  # wait for the stall to end and the worker to drain
        delay = observed.get('tel_ran_at', 0) - observed.get(
            'tel_enqueued_at', 0)
        print(f'    sibling delivery waited ~{delay:.2f}s behind the lock, '
              f'drained after release = {observed["tel_processed"] == 1}')
    else:
        broker.publish(pay_q, 'pay-0', pay_conn)
        time.sleep(0.2)  # let the payments worker enter its block
        broker.publish(tel_q, 'tel-0', tel_conn)
        time.sleep(0.3)
        print('  payments worker is blocked on its own per-channel thread:')
        print(f'    payments processed : {observed["pay_processed"]}')
        print(f'    telemetry processed: {observed["tel_processed"]}  '
              '(1 = sibling kept its own worker and the IOLoop)')
        print(f'    IOLoop free / heartbeat running: '
              f'{pay_conn.heartbeat_running}')

    if shared:
        print(f'    same connection object for both domains: '
              f'{pay_conn is tel_conn}')
    else:
        print(f'    telemetry on its own connection; heartbeat running: '
              f'{tel_conn.heartbeat_running}')

    if model == MODEL_POOLED and shared:
        # Flood the slow channel past its bounded queue to force overflow.
        for i in range(10):
            broker.publish(pay_q, f'flood-{i}', pay_conn)
        time.sleep(0.8)
        print('  after flooding the blocked channel past work_queue_maxsize:')
        print(f'    connection open: {conn.is_open}')
        print(f'    close reason: {type(conn.close_reason).__name__} '
              f'(an AMQPConnectionError, so it is connection-wide)')
        print(f'    telemetry channel still open: {tel_ch.is_open}')
        print(f'    telemetry processed after overflow: '
              f'{observed["tel_processed"]}')
        blocker.set()

    if model == MODEL_POOLED:
        # Release the payments worker in the split case so it does not hold
        # its full wait out past the scenario.
        blocker.set()
        time.sleep(0.2)


# --------------------------------------------------------------------------
# Scenario 2: one side is actively shut down.
# --------------------------------------------------------------------------
def scenario_shutdown(model: str, shared: bool) -> None:
    label = 'SHARED one connection, two channels' if shared else 'SPLIT two connections'
    heading(f'2. ACTIVE SHUTDOWN  [{model}]  {label}')
    if shared:
        broker, conn, pay_ch, tel_ch = build_shared(model)
        pay_conn = tel_conn = conn
    else:
        broker, pay_conn, tel_conn, pay_ch, tel_ch = build_split(model)

    tel_seen = []

    def handler(ch, delivery):
        tel_seen.append(delivery.body)
        ch.basic_ack(delivery.tag)

    pay_q, tel_q = fresh_queues(broker)
    pay_ch.basic_consume(pay_q, handler)
    tel_ch.basic_consume(tel_q, handler)
    broker.publish(pay_q, 'pay-0', pay_conn)
    broker.publish(tel_q, 'tel-0', tel_conn)
    time.sleep(0.2)

    if shared:
        print('  payments side closes its CHANNEL only:')
        pay_ch.close()
        print(f'    payments channel open: {pay_ch.is_open} '
              f'({type(pay_ch.close_reason).__name__})')
        print(f'    connection still open: {conn.is_open}')
        print(f'    telemetry channel still open: {tel_ch.is_open}')
        before = len(tel_seen)
        broker.publish(tel_q, 'tel-1', tel_conn)
        time.sleep(0.25)
        print(f'    telemetry deliveries before/after channel close: '
              f'{before} -> {len(tel_seen)} (sibling unaffected)')

        print('  payments side then closes the whole CONNECTION:')
        conn.close()
        print(f'    connection open: {conn.is_open} '
              f'({type(conn.close_reason).__name__})')
        print(f'    telemetry channel open after connection close: '
              f'{tel_ch.is_open}')
        try:
            tel_ch.basic_ack(99)
        except ChannelWrongStateError as exc:
            print(f'    ack on the now-closed channel raises: '
                  f'{type(exc).__name__}')
    else:
        print('  payments side closes its own CONNECTION:')
        pay_conn.close()
        print(f'    payments connection open: {pay_conn.is_open} '
              f'({type(pay_conn.close_reason).__name__})')
        print(f'    telemetry connection still open: {tel_conn.is_open}')
        print(f'    telemetry channel still open: {tel_ch.is_open}')
        before = len(tel_seen)
        broker.publish(tel_q, 'tel-1', tel_conn)
        time.sleep(0.25)
        print(f'    telemetry deliveries before/after the other connection '
              f'closed: {before} -> {len(tel_seen)} (fully isolated)')


# --------------------------------------------------------------------------
# Scenario 3: acknowledgement scope and redelivery.
# --------------------------------------------------------------------------
def scenario_ack(model: str, shared: bool) -> None:
    label = 'SHARED one connection, two channels' if shared else 'SPLIT two connections'
    heading(f'3. ACK SCOPE AND REDELIVERY  [{model}]  {label}')
    if shared:
        broker, conn, pay_ch, tel_ch = build_shared(model)
        pay_conn = tel_conn = conn
    else:
        broker, pay_conn, tel_conn, pay_ch, tel_ch = build_split(model)

    pay_q, tel_q = fresh_queues(broker)
    hold_q = f'{tel_q}.hold'
    broker.queue_declare(hold_q)

    # --- 3a. tags are per-channel integers; nack requeues with a new tag ----
    seen_tags = []

    def pay_handler(ch, delivery):
        seen_tags.append(delivery.tag)
        if len(seen_tags) == 1:
            ch.basic_nack(delivery.tag, requeue=True)
        else:
            ch.basic_ack(delivery.tag)

    pay_ch.basic_consume(pay_q, pay_handler)
    broker.publish(pay_q, 'pay-0', pay_conn)
    time.sleep(0.3)
    print(f'  3a nack(requeue=True): delivery tags on the payments channel = '
          f'{seen_tags}')
    print(f'     same logical message, two channel-scoped tags (1 then 2); '
          f'unacked now = {len(pay_ch._unacked)}')

    # --- 3b. an ack for another channel's tag cannot touch its message ------
    other_tags = []

    def tel_handler(ch, delivery):
        other_tags.append(delivery.tag)
        # Deliberately do NOT ack: leave the message unacked on tel_ch.
    tel_ch.basic_consume(tel_q, tel_handler)
    broker.publish(tel_q, 'tel-hold', tel_conn)
    time.sleep(0.3)
    held_tag = other_tags[0]
    before = len(tel_ch._unacked)
    # The payments channel has no message with this tag; the ack matches
    # nothing there instead of acknowledging telemetry's held message.
    pay_ch.basic_ack(held_tag)
    after = len(tel_ch._unacked)
    print(f'  3b telemetry holds tag {held_tag} unacked ({before} unacked); '
          f'pay_ch.basic_ack({held_tag}) leaves it unacked = {after == before}')

    # --- 3c. closing a channel with unacked work returns it for redelivery --
    hold_ch = tel_conn.channel()

    def hold_handler(ch, delivery):
        pass  # never acks

    hold_ch.basic_consume(hold_q, hold_handler)
    broker.publish(hold_q, 'tel-held-msg', tel_conn)
    time.sleep(0.3)
    held_unacked = len(hold_ch._unacked)
    hold_ch.close()
    time.sleep(0.2)

    redelivered = []
    recv_ch = tel_conn.channel()

    def recv_handler(ch, delivery):
        redelivered.append(delivery.body)
        ch.basic_ack(delivery.tag)

    recv_ch.basic_consume(hold_q, recv_handler)
    time.sleep(0.3)
    print(f'  3c hold_ch had {held_unacked} unacked at close; a fresh channel '
          f'received redelivered bodies = {redelivered}')


# --------------------------------------------------------------------------
# Scenario 4: security identity is connection-scoped.
# --------------------------------------------------------------------------
def scenario_identity() -> None:
    heading('4. SECURITY IDENTITY IS FIXED PER CONNECTION  [model-independent]')
    broker = make_broker()
    pay_conn = Connection(broker, 'svc-pay', '/prod', MODEL_POOLED)
    ch = pay_conn.channel()
    print('  svc-pay opens a second channel and tries to consume telemetry:')
    ch.basic_consume('telemetry.events', lambda c, d: None)
    print(f'    channel open after ACCESS_REFUSED: {ch.is_open}')
    print(f'    close reason: {type(ch.close_reason).__name__} '
          f'{ch.close_reason.reply_code if ch.close_reason else ""}')
    print(f'    broker recorded denial: {broker.permission_denials}')
    print('  a channel cannot carry a different user/vhost/TLS identity from '
          'its connection, so the high-privilege domain cannot be reached by '
          'opening another channel on the low-privilege connection')


def main() -> None:
    for model in (MODEL_BLOCKING, MODEL_POOLED):
        scenario_blocking(model, shared=True)
        scenario_blocking(model, shared=False)
    for model in (MODEL_BLOCKING, MODEL_POOLED):
        scenario_shutdown(model, shared=True)
        scenario_shutdown(model, shared=False)
    for model in (MODEL_BLOCKING, MODEL_POOLED):
        scenario_ack(model, shared=True)
    scenario_identity()


if __name__ == '__main__':
    main()
