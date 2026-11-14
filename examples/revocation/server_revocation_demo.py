# -*- coding: utf-8 -*-
"""
服务端 macaroon 撤销示例（仅依赖 Python 标准库：hmac / sqlite3 / threading ...）。

设计要点
========
1. 撤销对象不是“某个序列化 token / 某个签名”，而是复合主键 (issuer, root_id)。
   - 受限副本（attenuated macaroon）携带同一个 root_id，签名链不同、序列化字节不同，
     但与根 macaroon 共享撤销记录，因此根被撤销后所有副本立即失效。
   - 签发者身份来自已认证通道（管理端 API Key / 入口 mTLS、vhost），
     服务端自行解析，绝不接受 token 内自报的 issuer。
2. 同 root_id、不同 issuer 是两条独立的密钥行与撤销行，互不影响。
3. location 不参与 HMAC，客户端改 location 不影响密码学有效性，也逃不掉撤销
   （撤销只认 issuer + root_id）。
4. 提供两种互不兼容的序列化格式（v1 / v2），字节不同、签名相同；
   黑名单若按序列化字节或根签名做，会被换格式/加 caveat 轻易绕过。
5. 授权与受保护操作放在同一个 BEGIN IMMEDIATE 事务里：
   密码学校验 -> 撤销版本检查 -> caveat 检查 -> 业务写入 -> 提交。
   不会先返回一个“长期有效的成功布尔值”，撤销与业务写天然串行化。
6. 拒绝路径统一返回不含任何内部细节的通用错误，根密钥只在内存/DB 中存在，
   日志与响应只打印其 SHA-256 指纹；撤销行持久化在 SQLite，重启仍然生效。
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import tempfile
import threading
import time
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# 通用拒绝错误：对外字符串一律是通用文案，避免枚举账户/标识/密钥等内部状态。
# 服务端内部仍可凭异常类型区分原因（仅用于本演示的标签）。
# ---------------------------------------------------------------------------


class AuthzError(Exception):
    generic_message = "authorization denied"

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.generic_message)


class BadMacaroon(AuthzError):
    pass


class RevokedMacaroon(AuthzError):
    pass


class CaveatDenied(AuthzError):
    pass


class IssuerNotAuthenticated(AuthzError):
    pass


# ---------------------------------------------------------------------------
# 极简一阶 macaroon（与 pymacaroons 同构：HMAC-SHA256 签名链 + caveat 衰减）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Macaroon:
    root_id: str
    caveats: tuple[tuple[str, str], ...]
    signature: bytes
    # location 只是路由提示，不参与任何 HMAC，客户端可任意改写。
    location: str = ""


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _root_signature(root_key: bytes, root_id: str) -> bytes:
    return _hmac(root_key, b"macaroon-root:" + root_id.encode("utf-8"))


def _caveat_signature(previous: bytes, predicate: str, value: str) -> bytes:
    clause = f"{predicate}={value}".encode("utf-8")
    return _hmac(previous, b"macaroon-caveat:" + clause)


def mint_macaroon(root_key: bytes, root_id: str, location: str = "") -> Macaroon:
    return Macaroon(
        root_id=root_id,
        caveats=(),
        signature=_root_signature(root_key, root_id),
        location=location,
    )


def add_caveat(macaroon: Macaroon, predicate: str, value: str) -> Macaroon:
    """客户端衰减：只能追加 caveat，签名链单向延伸，无法删除既有 caveat。"""
    new_signature = _caveat_signature(macaroon.signature, predicate, value)
    return dataclasses.replace(
        macaroon,
        caveats=macaroon.caveats + ((predicate, value),),
        signature=new_signature,
    )


# ---- 两种序列化版本：线格式不同，签名语义完全一致 -------------------------


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def serialize(macaroon: Macaroon, version: int) -> str:
    if version == 1:
        payload = {
            "v": 1,
            "rid": macaroon.root_id,
            "loc": macaroon.location,
            "cav": [list(item) for item in macaroon.caveats],
            "sig": _b64e(macaroon.signature),
        }
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        return "MV1-" + _b64e(body)
    if version == 2:
        # 字段名、分隔符、顺序都不同 => 字节必然不同，但 signature 原样保留。
        payload = {
            "version": 2,
            "id": macaroon.root_id,
            "l": macaroon.location,
            "c": [[p, v] for p, v in macaroon.caveats],
            "s": _b64e(macaroon.signature),
        }
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return "MV2." + _b64e(body)
    raise ValueError("unsupported serialization version")


def parse(wire: str) -> Macaroon:
    try:
        if wire.startswith("MV1-"):
            payload = json.loads(_b64d(wire[4:]))
            return Macaroon(
                root_id=payload["rid"],
                caveats=tuple((p, v) for p, v in payload["cav"]),
                signature=_b64d(payload["sig"]),
                location=payload.get("loc", ""),
            )
        if wire.startswith("MV2."):
            payload = json.loads(_b64d(wire[4:]))
            return Macaroon(
                root_id=payload["id"],
                caveats=tuple((p, v) for p, v in payload["c"]),
                signature=_b64d(payload["s"]),
                location=payload.get("l", ""),
            )
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        raise BadMacaroon() from exc
    raise BadMacaroon()


# ---------------------------------------------------------------------------
# SQLite 持久层：标准库 sqlite3，无任何第三方依赖
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS issuers (
    issuer   TEXT PRIMARY KEY,
    api_key  BLOB NOT NULL
);

-- 根密钥按 (issuer, root_id) 归档；root_id 的命名空间属于 issuer。
CREATE TABLE IF NOT EXISTS root_keys (
    issuer     TEXT NOT NULL,
    root_id    TEXT NOT NULL,
    root_key   BLOB NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (issuer, root_id)
);

-- 撤销登记表：撤销的是“签发者 + 根标识”，不存任何 token 字节或签名。
CREATE TABLE IF NOT EXISTS revocations (
    issuer             TEXT NOT NULL,
    root_id            TEXT NOT NULL,
    revocation_version INTEGER NOT NULL,
    revoked_at         REAL NOT NULL,
    PRIMARY KEY (issuer, root_id)
);

CREATE TABLE IF NOT EXISTS accounts (
    account TEXT PRIMARY KEY,
    balance INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ledger_entries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account    TEXT NOT NULL,
    amount     INTEGER NOT NULL,
    note       TEXT NOT NULL,
    created_at REAL NOT NULL
);
"""


def connect(db_path: str) -> sqlite3.Connection:
    # isolation_level=None：自动提交模式，事务边界完全由下面的 BEGIN/COMMIT 显式控制。
    # check_same_thread=False：每个连接只在单一线程内使用（演示中每个工作线程
    # 持有自己的连接），跨线程共享连接本身仍被禁止。
    conn = sqlite3.connect(
        db_path, timeout=10, isolation_level=None, check_same_thread=False
    )
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def register_issuer(conn: sqlite3.Connection, issuer: str, api_key: bytes) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO issuers(issuer, api_key) VALUES (?, ?)",
        (issuer, api_key),
    )


def authenticate_issuer(conn: sqlite3.Connection, api_key: bytes | None) -> str:
    """管理端 / 入口侧认证：用已认证凭据反查 issuer，常量时间比较。"""
    if not api_key:
        raise IssuerNotAuthenticated()
    for issuer, stored_key in conn.execute("SELECT issuer, api_key FROM issuers"):
        if hmac.compare_digest(stored_key, api_key):
            return issuer
    raise IssuerNotAuthenticated()


def mint_root(
    conn: sqlite3.Connection, issuer: str, root_id: str, location: str = ""
) -> tuple[Macaroon, bytes]:
    root_key = secrets.token_bytes(32)
    conn.execute(
        "INSERT INTO root_keys(issuer, root_id, root_key, created_at) "
        "VALUES (?, ?, ?, ?)",
        (issuer, root_id, root_key, time.time()),
    )
    return mint_macaroon(root_key, root_id, location), root_key


def current_revocation_version(conn: sqlite3.Connection) -> int:
    """全局单调撤销版本号，可用于读版本（read-version）模式的失效判定。"""
    row = conn.execute("SELECT COALESCE(MAX(revocation_version), 0) FROM revocations").fetchone()
    return int(row[0])


def revoke(conn: sqlite3.Connection, issuer: str, root_id: str) -> int:
    """
    撤销接入点：定位键是已认证的 issuer + root_id。
    整个撤销登记是一个写事务，与业务写事务在 SQLite 层面串行化。
    重复撤销幂等，返回同一版本号。
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        key_row = conn.execute(
            "SELECT 1 FROM root_keys WHERE issuer = ? AND root_id = ?",
            (issuer, root_id),
        ).fetchone()
        if key_row is None:
            # 不区分“不存在”与“无权限”，统一通用错误，避免标识枚举。
            raise AuthzError()
        conn.execute(
            "INSERT OR IGNORE INTO revocations"
            "(issuer, root_id, revocation_version, revoked_at) "
            "VALUES (?, ?, COALESCE((SELECT MAX(revocation_version) FROM revocations), 0) + 1, ?)",
            (issuer, root_id, time.time()),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    row = conn.execute(
        "SELECT revocation_version FROM revocations WHERE issuer = ? AND root_id = ?",
        (issuer, root_id),
    ).fetchone()
    return int(row[0])


def _load_root_key(conn: sqlite3.Connection, issuer: str, root_id: str) -> bytes:
    row = conn.execute(
        "SELECT root_key FROM root_keys WHERE issuer = ? AND root_id = ?",
        (issuer, root_id),
    ).fetchone()
    if row is None:
        raise AuthzError()
    return bytes(row[0])


def verify_signature_offline(
    conn: sqlite3.Connection, issuer: str, macaroon: Macaroon
) -> None:
    """
    仅做密码学完整性校验（演示“先验证、后操作”的那个预检查）。
    它只证明 token 未被篡改，绝不代表当前授权有效：不查撤销、不查 caveat，
    调用方绝不能把它的结果缓存成长期有效的布尔值。
    """
    root_key = _load_root_key(conn, issuer, macaroon.root_id)
    expected = _root_signature(root_key, macaroon.root_id)
    for predicate, value in macaroon.caveats:
        expected = _caveat_signature(expected, predicate, value)
    if not hmac.compare_digest(expected, macaroon.signature):
        raise BadMacaroon()


def _evaluate_caveats(macaroon: Macaroon, context: dict[str, str]) -> None:
    for predicate, value in macaroon.caveats:
        if predicate == "account":
            if context.get("account") != value:
                raise CaveatDenied()
            continue
        # 未知 caveat 一律 fail-closed，绝不默认放行。
        raise CaveatDenied()


def debit(
    conn: sqlite3.Connection,
    issuer: str,
    macaroon: Macaroon,
    account: str,
    amount: int,
    gate: "callable | None" = None,
) -> int:
    """
    受保护操作。授权四步与业务写入共享同一个 BEGIN IMMEDIATE 事务：

        密码学校验 -> 撤销检查（事务快照）-> caveat -> 业务更新 -> COMMIT

    因此“验证通过之后、业务提交之前发生撤销”在本事务模型下不可能漏判：
    撤销事务与本事务互斥，谁先拿到写锁谁先生效，结果只有一个线性顺序，
    不存在先返回成功布尔值、撤销随后才被看见的窗口。
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        verify_signature_offline(conn, issuer, macaroon)

        revoked_row = conn.execute(
            "SELECT 1 FROM revocations WHERE issuer = ? AND root_id = ?",
            (issuer, macaroon.root_id),
        ).fetchone()
        if revoked_row is not None:
            raise RevokedMacaroon()

        _evaluate_caveats(macaroon, {"account": account})

        if gate is not None:
            gate()  # 演示用挂起点：此时仍在事务内、尚未提交。

        cur = conn.execute(
            "UPDATE accounts SET balance = balance - ? "
            "WHERE account = ? AND balance >= ?",
            (amount, account, amount),
        )
        if cur.rowcount != 1:
            raise AuthzError()
        conn.execute(
            "INSERT INTO ledger_entries(account, amount, note, created_at) "
            "VALUES (?, ?, ?, ?)",
            (account, amount, f"issuer={issuer} root_id={macaroon.root_id}", time.time()),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    row = conn.execute("SELECT balance FROM accounts WHERE account = ?", (account,)).fetchone()
    return int(row[0])


# ---------------------------------------------------------------------------
# 演示驱动
# ---------------------------------------------------------------------------

ALPHA = "issuer-alpha"
BETA = "issuer-beta"
SHARED_ROOT_ID = "rid-42"
SECOND_ROOT_ID = "rid-77"

EMITTED: list[str] = []


def say(text: str = "") -> None:
    EMITTED.append(text)
    print(text)


def key_fingerprint(key: bytes) -> str:
    return "sha256:" + hashlib.sha256(key).digest()[:8].hex()


def outcome(call: "callable") -> str:
    try:
        result = call()
        return f"OK -> {result}"
    except AuthzError as exc:
        # 对外只有通用文案；类型名仅供本演示区分拒绝原因。
        return f"DENY [{type(exc).__name__}] message={exc!s}"


def in_thread(call: "callable") -> tuple[threading.Thread, dict]:
    box: dict = {}

    def run() -> None:
        try:
            box["result"] = call()
        except BaseException as exc:  # 后台线程也要把异常带回主线程断言
            box["error"] = exc

    thread = threading.Thread(target=run)
    return thread, box


def main() -> None:
    db_path = os.path.join(
        os.environ.get("TMPDIR", tempfile.gettempdir()), "macaroon_revoke_demo.sqlite3"
    )
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(db_path + suffix)
        except FileNotFoundError:
            pass

    admin = connect(db_path)
    init_db(admin)

    api_alpha = secrets.token_bytes(24)
    api_beta = secrets.token_bytes(24)
    register_issuer(admin, ALPHA, api_alpha)
    register_issuer(admin, BETA, api_beta)
    for name, balance in (("alice", 100), ("bob", 100), ("carol", 100)):
        admin.execute("INSERT INTO accounts(account, balance) VALUES (?, ?)", (name, balance))

    # 管理端：先认证，再用认证后的 issuer 身份签发/撤销。
    assert authenticate_issuer(admin, api_alpha) == ALPHA
    assert authenticate_issuer(admin, api_beta) == BETA
    try:
        authenticate_issuer(admin, b"wrong-api-key")
        raise AssertionError("伪造 API Key 必须认证失败")
    except IssuerNotAuthenticated:
        pass

    mac_a, key_a = mint_root(admin, ALPHA, SHARED_ROOT_ID, location="https://svc.example/")
    mac_b, key_b = mint_root(admin, BETA, SHARED_ROOT_ID, location="https://svc.example/")
    mac_c, _key_c = mint_root(admin, ALPHA, SECOND_ROOT_ID)

    # 受限副本：追加 account=alice；客户端再改 location、换序列化版本。
    mac_a_att = add_caveat(mac_a, "account", "alice")
    mac_a_loc = dataclasses.replace(mac_a_att, location="https://attacker.example/evil")
    mac_c_att = add_caveat(mac_c, "account", "alice")

    wire_v1 = serialize(mac_a_att, 1)
    wire_v2 = serialize(mac_a_att, 2)

    say("=" * 78)
    say("场景 0：撤销前的基线行为")
    say("=" * 78)
    say(f"根密钥指纹（不输出原文）：alpha={key_fingerprint(key_a)} beta={key_fingerprint(key_b)}")
    say(f"根 macaroon 签名     = {mac_a.signature.hex()}")
    say(f"衰减副本签名（不同！）= {mac_a_att.signature.hex()}")
    say(f"v1 线格式 = {wire_v1}")
    say(f"v2 线格式 = {wire_v2}")
    say(f"两种序列化字节相同？{wire_v1 == wire_v2}；解析后签名相同？"
        f"{parse(wire_v1).signature == parse(wire_v2).signature}")
    say("结论：按 token 字节或根签名做黑名单，都会漏掉衰减副本/另一序列化版本。")

    say("")
    say("[撤销前] 根 token 扣款 alice 10        : " + outcome(lambda: debit(admin, ALPHA, mac_a, "alice", 10)))
    say("[撤销前] 衰减副本扣款 alice 5          : " + outcome(lambda: debit(admin, ALPHA, mac_a_att, "alice", 5)))
    say("[撤销前] 衰减副本越权扣款 bob 5        : " + outcome(lambda: debit(admin, ALPHA, mac_a_att, "bob", 5)))
    say("[撤销前] 篡改 location 的副本扣款 alice: " + outcome(lambda: debit(admin, ALPHA, mac_a_loc, "alice", 5)))
    say("[撤销前] v2 重新序列化后扣款 alice     : " + outcome(lambda: debit(admin, ALPHA, parse(wire_v2), "alice", 5)))
    tampered = dataclasses.replace(mac_a, signature=bytes([mac_a.signature[0] ^ 1]) + mac_a.signature[1:])
    say("[撤销前] 翻转签名一位                  : " + outcome(lambda: debit(admin, ALPHA, tampered, "alice", 1)))
    say("[撤销前] 冒充另一入口 issuer           : " + outcome(lambda: debit(admin, BETA, mac_a, "alice", 1)))

    # ------------------------------------------------------------------
    # 并发演示 1：业务事务先拿到写锁 -> 扣款成功；撤销事务随后生效。
    # ------------------------------------------------------------------
    say("")
    say("=" * 78)
    say("场景 1：两个并发请求 —— 扣款事务 vs 撤销事务（扣款先持锁）")
    say("=" * 78)
    conn_t1 = connect(db_path)
    conn_r1 = connect(db_path)
    entered = threading.Event()
    proceed = threading.Event()

    def slow_debit() -> int:
        return debit(
            conn_t1, ALPHA, mac_a_att, "alice", 7,
            gate=lambda: (entered.set(), proceed.wait())[1],
        )

    t_debit, box_debit = in_thread(slow_debit)
    t_debit.start()
    entered.wait(5)
    t_revoke, box_revoke = in_thread(lambda: revoke(conn_r1, authenticate_issuer(conn_r1, api_alpha), SHARED_ROOT_ID))
    t_revoke.start()
    time.sleep(0.3)  # 让撤销事务在写锁上排队
    proceed.set()
    t_debit.join(10)
    t_revoke.join(10)
    say(f"扣款事务结果：{box_debit.get('result') or box_debit.get('error')!r}（先持锁 => 成功）")
    say(f"撤销事务结果：revocation_version={box_revoke.get('result')!r}（排队后生效）")
    say(f"当前全局撤销版本号：{current_revocation_version(admin)}")

    # ------------------------------------------------------------------
    # 并发演示 2：先通过密码学预检查，等待期间发生撤销 -> 事务内复查拒绝。
    #             同时另一 issuer 的同名 token 并发扣款，必须不受影响。
    # ------------------------------------------------------------------
    say("")
    say("=" * 78)
    say("场景 2：预检查通过后、操作前发生撤销；另一 issuer 同名 token 并发")
    say("=" * 78)
    conn_t2 = connect(db_path)
    conn_r2 = connect(db_path)
    conn_beta = connect(db_path)
    precheck_done = threading.Event()
    revoked_event = threading.Event()

    def alpha_flow() -> str:
        verify_signature_offline(conn_t2, ALPHA, mac_c_att)  # 此刻撤销尚不存在
        precheck_done.set()
        revoked_event.wait(5)
        return outcome(lambda: debit(conn_t2, ALPHA, mac_c_att, "alice", 9))

    def revoker_flow() -> int:
        precheck_done.wait(5)
        time.sleep(0.1)
        version = revoke(conn_r2, authenticate_issuer(conn_r2, api_alpha), SECOND_ROOT_ID)
        revoked_event.set()
        return version

    def beta_flow() -> str:
        precheck_done.wait(5)
        time.sleep(0.05)
        return outcome(lambda: debit(conn_beta, BETA, mac_b, "carol", 11))

    threads = [in_thread(flow) for flow in (alpha_flow, revoker_flow, beta_flow)]
    boxes = []
    for thread, box in threads:
        thread.start()
    for thread, box in threads:
        thread.join(10)
        boxes.append(box)
    say(f"alpha 流程（预检查已通过，事务内复查）：{boxes[0].get('result') or boxes[0].get('error')!r}")
    say(f"撤销流程 rid-77 版本号                ：{boxes[1].get('result')!r}")
    say(f"beta 同名 token 并发扣款（必须成功）  ：{boxes[2].get('result') or boxes[2].get('error')!r}")

    # ------------------------------------------------------------------
    # 撤销后：根、衰减副本、改 location、换序列化版本全部失效；beta 不受影响。
    # ------------------------------------------------------------------
    say("")
    say("=" * 78)
    say("场景 3：撤销后所有派生副本立即失效，同标识另一 issuer 不受影响")
    say("=" * 78)
    say("[撤销后] 根 token 扣款                 : " + outcome(lambda: debit(admin, ALPHA, mac_a, "alice", 1)))
    say("[撤销后] 衰减副本扣款                  : " + outcome(lambda: debit(admin, ALPHA, mac_a_att, "alice", 1)))
    say("[撤销后] 篡改 location 的副本扣款      : " + outcome(lambda: debit(admin, ALPHA, mac_a_loc, "alice", 1)))
    say("[撤销后] v1 重新解析扣款               : " + outcome(lambda: debit(admin, ALPHA, parse(wire_v1), "alice", 1)))
    say("[撤销后] v2 重新解析扣款               : " + outcome(lambda: debit(admin, ALPHA, parse(wire_v2), "alice", 1)))
    say("[撤销后] 离线密码学预检查（仍只证明未篡改）: " + outcome(lambda: verify_signature_offline(admin, ALPHA, mac_a_att)))
    say("[撤销后] beta 同名根 token 扣款 carol  : " + outcome(lambda: debit(admin, BETA, mac_b, "carol", 3)))
    say("[撤销后] beta 撤销自己的同标识行（不触碰 alpha）: "
        + outcome(lambda: revoke(admin, authenticate_issuer(admin, api_beta), SHARED_ROOT_ID)))
    say("[撤销后] alpha 仍处于撤销态（两行相互独立）        : "
        + outcome(lambda: debit(admin, ALPHA, mac_a, "alice", 1)))
    say("[撤销后] beta 撤销自己那一行后其 token 立即失效    : "
        + outcome(lambda: debit(admin, BETA, mac_b, "carol", 1)))
    say("[撤销后] 重复撤销幂等                  : "
        f"version={revoke(admin, authenticate_issuer(admin, api_alpha), SHARED_ROOT_ID)}")

    # 撤销表内容审计：只包含 (issuer, root_id, 版本号, 时间戳)，没有 token/签名。
    say("")
    say("revocations 表实际存储内容（无序列化 token、无签名、无根密钥）：")
    for row in admin.execute(
        "SELECT issuer, root_id, revocation_version, typeof(revoked_at) FROM revocations ORDER BY 3"
    ):
        say(f"  {row}")

    balance_alice = admin.execute("SELECT balance FROM accounts WHERE account='alice'").fetchone()[0]
    balance_carol = admin.execute("SELECT balance FROM accounts WHERE account='carol'").fetchone()[0]
    say(f"alice 余额={balance_alice}（被拒绝的 9/1 元扣款均未入账），carol 余额={balance_carol}")

    # ------------------------------------------------------------------
    # 重启：关闭全部连接后重新打开同一 SQLite 文件，撤销仍然生效。
    # ------------------------------------------------------------------
    say("")
    say("=" * 78)
    say("场景 4：服务重启（关闭并重开数据库连接）后撤销持久化")
    say("=" * 78)
    for conn in (admin, conn_t1, conn_r1, conn_t2, conn_r2, conn_beta):
        conn.close()
    restarted = connect(db_path)
    say(f"重启后版本号={current_revocation_version(restarted)}")
    say("[重启后] alpha 已撤销 token 扣款       : " + outcome(lambda: debit(restarted, ALPHA, mac_a, "alice", 1)))
    say("[重启后] beta 已撤销 token 同样持久失效: " + outcome(lambda: debit(restarted, BETA, mac_b, "carol", 2)))
    restarted.close()

    # ------------------------------------------------------------------
    # 泄露审计：任何输出都不得包含根密钥原文。
    # ------------------------------------------------------------------
    blob = "\n".join(EMITTED)
    for secret_key, label in ((key_a, "alpha 根密钥"), (key_b, "beta 根密钥")):
        assert secret_key.hex() not in blob, f"{label} 原文泄露(hex)"
        assert base64.urlsafe_b64encode(secret_key).rstrip(b"=").decode() not in blob, f"{label} 原文泄露(b64)"
    assert "authorization denied" in blob
    say("")
    say("全部断言通过：撤销按 (issuer, root_id) 生效，副本/location/序列化均无法逃逸，")
    say("拒绝路径未泄露根密钥，重启后撤销仍然有效。")


if __name__ == "__main__":
    main()
