# -*- coding: utf-8 -*-
"""Three small graphs: plain certification, restricted delegation, trust ring."""

from trustgraph import (FULL_TRUST, Cert, Evaluator, Key, Root, Uid,
                        VALID, INSUFFICIENT, UNKNOWN, TARGET_INVALID)

NOW = 1_700_000_000.0


def show(title, verdict, evaluator):
    print(f"  {title}")
    print(f"    结论: {verdict.status}  "
          f"(悲观流={verdict.pessimistic_flow}, 乐观流={verdict.optimistic_flow}, "
          f"阈值={verdict.threshold})")
    for amount, metas in verdict.paths:
        hops = []
        for meta in metas:
            if meta[0] == "root":
                hops.append(f"根[{evaluator.roots[meta[1]].key[:8]}]")
            else:
                hops.append(f"认证[{meta[1]}]")
        print(f"    路径 +{amount}: " + " -> ".join(hops))
    if verdict.paths:
        ok = evaluator.verify_paths(verdict)
        print(f"    路径独立复核: {'通过' if ok else '失败'}")
    for cid, reason in verdict.dropped:
        print(f"    丢弃 {cid}: {reason}")
    for cid in verdict.unknown_scope:
        print(f"    范围表达式无法可靠解释: {cid}")
    print()


def scenario_a():
    print("场景 A: 普通认证 —— 直接认证与两位独立介绍人")
    keys = [
        Key("ROOT", "root-admin"),
        Key("ALICE", "alice"),
        Key("INTRO1", "carol"),
        Key("INTRO2", "dan"),
        Key("BOB", "bob"),
    ]
    uid_bob = "Bob <bob@example.org>"
    uid_alice = "Alice <alice@example.org>"
    certs = [
        Cert("c-root-alice", "ROOT", "ALICE", uid_alice),
        Cert("c-i1-bob", "INTRO1", "BOB", uid_bob),
        Cert("c-i2-bob", "INTRO2", "BOB", uid_bob),
    ]
    # A1: root directly certifies Alice; full ownertrust on root, threshold 120.
    ev = Evaluator(keys, certs, [Root("ROOT", FULL_TRUST, 1)], NOW)
    show("A1 根直接认证 Alice (阈值 120)",
         ev.evaluate("ALICE", uid_alice, FULL_TRUST), ev)
    # A2: two independent marginal introducers (60 each) both certify Bob.
    ev = Evaluator(keys, certs,
                   [Root("INTRO1", 60, 0), Root("INTRO2", 60, 0)], NOW)
    show("A2 两位独立介绍人各出 60, 合计达标 (阈值 120)",
         ev.evaluate("BOB", uid_bob, FULL_TRUST), ev)
    # A3: only one of them -> below threshold.
    ev = Evaluator(keys, certs, [Root("INTRO1", 60, 0)], NOW)
    show("A3 只有一位介绍人, 流量不足 (阈值 120)",
         ev.evaluate("BOB", uid_bob, FULL_TRUST), ev)


def scenario_b():
    print("场景 B: 受限转授权 —— 信任量、委托深度与名称范围")
    keys = [
        Key("ROOT", "root-admin"),
        Key("CORPCA", "corp-ca"),
        Key("SUBCA", "corp-sub-ca"),
        Key("BOB", "bob"),
        Key("MALLORY", "mallory"),
        Key("DAVE", "dave"),
    ]
    uid_bob = "Bob <bob@corp.example>"
    uid_mal = "Mallory <mallory@evil.example>"
    uid_dave = "Dave <dave@corp.example>"
    uid_subca = "Corp Sub CA <subca@corp.example>"
    scope = r"[^<]+<[^@]+@corp\.example>"
    certs = [
        # Root delegates to the corporate CA: full amount, depth 1, scoped to
        # @corp.example names only.
        Cert("c-root-ca", "ROOT", "CORPCA", "Corp CA <ca@corp.example>",
             trust_amount=FULL_TRUST, trust_depth=1, trust_regex=scope),
        Cert("c-ca-bob", "CORPCA", "BOB", uid_bob),
        Cert("c-ca-mal", "CORPCA", "MALLORY", uid_mal),
        # The CA tries to sub-delegate; root only granted depth 1, so the
        # chain ROOT -> CORPCA -> SUBCA -> DAVE is one hop too long.
        Cert("c-ca-subca", "CORPCA", "SUBCA", uid_subca,
             trust_amount=FULL_TRUST, trust_depth=1),
        Cert("c-subca-dave", "SUBCA", "DAVE", uid_dave),
        # A scope regex outside the interpretable subset (backreference).
        Cert("c-root-dave", "ROOT", "DAVE", uid_dave,
             trust_amount=FULL_TRUST, trust_depth=0,
             trust_regex=r"([^@]+)@\1\.example"),
    ]
    roots = [Root("ROOT", FULL_TRUST, 1)]
    ev = Evaluator(keys, certs, roots, NOW)
    show("B1 CA 在名称范围内认证 bob@corp.example (阈值 120)",
         ev.evaluate("BOB", uid_bob, FULL_TRUST), ev)
    show("B2 同一 CA 认证域外名称 mallory@evil.example",
         ev.evaluate("MALLORY", uid_mal, FULL_TRUST), ev)
    certs_no_dave = [c for c in certs if c.cid != "c-root-dave"]
    ev = Evaluator(keys, certs_no_dave, roots, NOW)
    show("B3 超出委托深度的二级代理 (ROOT深度1, 链长2)",
         ev.evaluate("DAVE", uid_dave, FULL_TRUST), ev)
    # B4: keep only the weird-regex cert.
    certs2 = [c for c in certs if c.cid in ("c-root-dave",)]
    ev = Evaluator(keys, certs2, roots, NOW)
    show("B4 唯一路径依赖无法解释的范围表达式 (反向引用)",
         ev.evaluate("DAVE", uid_dave, FULL_TRUST), ev)


def scenario_c():
    print("场景 C: 环形刷信任 与 同一控制者的多把钥匙")
    keys = [
        Key("ROOT", "root-admin"),
        Key("M1", "mallory"),   # three keys, one controller
        Key("M2", "mallory"),
        Key("M3", "mallory"),
        Key("VICTIM", "victim"),
    ]
    uid_v = "Victim <victim@example.org>"
    ring = [
        Cert("r1", "M1", "M2", "M2 <m2@example.org>", trust_amount=FULL_TRUST, trust_depth=1),
        Cert("r2", "M2", "M3", "M3 <m3@example.org>", trust_amount=FULL_TRUST, trust_depth=1),
        Cert("r3", "M3", "M1", "M1 <m1@example.org>", trust_amount=FULL_TRUST, trust_depth=1),
    ]
    certs = ring + [
        Cert("m1-v", "M1", "VICTIM", uid_v),
        Cert("m2-v", "M2", "VICTIM", uid_v),
        Cert("m3-v", "M3", "VICTIM", uid_v),
    ]
    # C1: a closed ring with no root inflow at all.
    ev = Evaluator(keys, certs, [], NOW)
    show("C1 纯环互签, 无任何信任根 (阈值 120)",
         ev.evaluate("VICTIM", uid_v, FULL_TRUST), ev)
    # C2: root injects 60 into ONE ring key; the ring cannot amplify it.
    ev = Evaluator(keys, certs, [Root("M1", 60, 2)], NOW)
    show("C2 根只给环上一点注入 60, 环不能放大 (阈值 120)",
         ev.evaluate("VICTIM", uid_v, FULL_TRUST), ev)
    # C3: three cryptographically valid certifications, but all from keys of
    # the same controller -> contracted to one node -> still only 60.
    certs2 = certs + [Cert("root-m1", "ROOT", "M1", "M1 <m1@example.org>",
                           trust_amount=60, trust_depth=1)]
    ev = Evaluator(keys, certs2, [Root("ROOT", FULL_TRUST, 1)], NOW)
    show("C3 三份有效签名出自同一控制者, 不累计 (阈值 120)",
         ev.evaluate("VICTIM", uid_v, FULL_TRUST), ev)


if __name__ == "__main__":
    scenario_a()
    scenario_b()
    scenario_c()
