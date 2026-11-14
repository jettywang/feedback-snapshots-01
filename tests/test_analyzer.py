"""分析引擎判定分支测试。"""

import hashlib

from nonce_audit.analyzer import (
    REASON_CROSS_KEY,
    REASON_DENOMINATOR_NONINVERTIBLE,
    REASON_DUPLICATE_RECORD,
    REASON_SINGLE_RECORD,
    analyze,
)
from nonce_audit.curves import get_curve
from nonce_audit.ecdsa_math import Signature
from tests.helpers import fresh_key, make_record

INFO = get_curve("NIST256p")
ORDER = INFO.order
FIXED_K = 1234567890123456789012345678901234567890


def test_confirmed_reuse_with_distinct_messages():
    sk = fresh_key(INFO, 11)
    r1 = make_record("r1", INFO, sk, b"message-one", k=FIXED_K)
    r2 = make_record("r2", INFO, sk, b"message-two", k=FIXED_K)
    report = analyze([r1, r2])

    assert len(report.confirmed_groups) == 1
    group = report.confirmed_groups[0]
    assert group.evidence_record_ids == ["r1", "r2"]
    assert group.confirmed_d == sk.privkey.secret_multiplier
    assert group.confirmed_k == min(FIXED_K, ORDER - FIXED_K)
    assert group.derivation["checks"]


def test_low_s_flip_still_confirmed():
    sk = fresh_key(INFO, 12)
    r1 = make_record("r1", INFO, sk, b"alpha", k=FIXED_K)
    r2 = make_record("r2", INFO, sk, b"beta", k=FIXED_K, low_s_flip=True)
    report = analyze([r1, r2])

    assert len(report.confirmed_groups) == 1
    assert (
        report.confirmed_groups[0].confirmed_d
        == sk.privkey.secret_multiplier
    )


def test_duplicate_record_is_clue_not_confirmation():
    sk = fresh_key(INFO, 13)
    r1 = make_record("r1", INFO, sk, b"same", k=FIXED_K)
    dup = make_record("r1-copy", INFO, sk, b"same", k=FIXED_K)
    report = analyze([r1, dup])

    assert report.confirmed_groups == []
    group = report.unconfirmed_clues[0]
    assert REASON_DUPLICATE_RECORD in group.reason_codes
    assert REASON_DENOMINATOR_NONINVERTIBLE in group.reason_codes


def test_same_message_repeat_cannot_derive():
    sk = fresh_key(INFO, 14)
    # 两条都验证通过且 z 相同、r 相同时，s 只能相同或互为 n-s（low-S 翻转），
    # 因此差分推导在数学上无法进行：只能归为重复消息线索，绝不确认。
    r1 = make_record("r1", INFO, sk, b"same-msg", k=FIXED_K)
    r2 = make_record("r2", INFO, sk, b"same-msg", k=FIXED_K, low_s_flip=True)
    assert r1.z == r2.z and r1.sig.r == r2.sig.r

    report = analyze([r1, r2])
    assert report.confirmed_groups == []
    group = report.unconfirmed_clues[0]
    assert REASON_DUPLICATE_RECORD in group.reason_codes
    assert REASON_DENOMINATOR_NONINVERTIBLE in group.reason_codes
    assert all(pair.same_message for pair in group.pair_analyses)


def test_cross_key_r_collision_not_merged():
    sk_a = fresh_key(INFO, 21)
    sk_b = fresh_key(INFO, 22)
    r1 = make_record("a1", INFO, sk_a, b"aaa", k=FIXED_K)
    # n-k 产生与 k 相同的 x 坐标（相同 r），但属于另一把钥匙。
    r2 = make_record("b1", INFO, sk_b, b"bbb", k=ORDER - FIXED_K)
    assert r1.sig.r == r2.sig.r

    report = analyze([r1, r2])
    assert report.confirmed_groups == []
    cross = next(g for g in report.groups if g.cross_key)
    assert REASON_CROSS_KEY in cross.reason_codes
    assert set(cross.key_fingerprints) == {r1.fingerprint, r2.fingerprint}


def test_cross_key_bucket_keeps_same_key_confirmation():
    sk_a = fresh_key(INFO, 23)
    sk_b = fresh_key(INFO, 24)
    a1 = make_record("a1", INFO, sk_a, b"a-one", k=FIXED_K)
    a2 = make_record("a2", INFO, sk_a, b"a-two", k=FIXED_K)
    b1 = make_record("b1", INFO, sk_b, b"b-one", k=ORDER - FIXED_K)

    report = analyze([a1, a2, b1])
    confirmed = report.confirmed_groups
    assert len(confirmed) == 1
    assert confirmed[0].evidence_record_ids == ["a1", "a2"]
    assert any(g.cross_key for g in report.unconfirmed_clues)


def test_corrupt_digest_fails_verification_without_blocking_others():
    sk_a = fresh_key(INFO, 31)
    sk_b = fresh_key(INFO, 32)
    a1 = make_record("a1", INFO, sk_a, b"ok-one", k=FIXED_K)
    a2 = make_record("a2", INFO, sk_a, b"ok-two", k=FIXED_K)
    bogus_digest = hashlib.sha256(b"tampered").digest()
    real_digest = hashlib.sha256(b"original").digest()
    bad = make_record(
        "bad", INFO, sk_b, b"original", k=999,
        digest_override=bogus_digest, sign_against=real_digest,
    )
    report = analyze([a1, a2, bad])

    assert [item["id"] for item in report.invalid_records] == ["bad"]
    assert len(report.confirmed_groups) == 1


def test_forged_record_candidate_does_not_match_pubkey():
    sk = fresh_key(INFO, 41)
    r1 = make_record("r1", INFO, sk, b"one", k=FIXED_K)
    # 同 r、随机 s 与无关摘要：签名验证失败，且任何候选 d 都无法重现公钥。
    fake_digest = hashlib.sha256(b"unrelated").digest()
    fake = make_record(
        "fake",
        INFO,
        sk,
        b"two",
        k=FIXED_K,
        s_override=ORDER - 7,
        digest_override=fake_digest,
    )
    report = analyze([r1, fake])
    assert report.confirmed_groups == []
    assert any(item["id"] == "fake" for item in report.invalid_records)


def test_single_record_is_only_a_clue():
    sk = fresh_key(INFO, 51)
    r1 = make_record("solo", INFO, sk, b"lonely", k=FIXED_K)
    report = analyze([r1])
    assert report.confirmed_groups == []
    assert report.unconfirmed_clues[0].reason_codes == [REASON_SINGLE_RECORD]


def test_healthy_distinct_k_no_groups_pairs():
    sk = fresh_key(INFO, 61)
    records = [
        make_record(f"h{i}", INFO, sk, f"msg-{i}".encode(), k=FIXED_K + i)
        for i in range(1, 4)
    ]
    report = analyze(records)
    assert report.confirmed_groups == []
    assert all(REASON_SINGLE_RECORD in g.reason_codes for g in report.groups)


def test_three_records_consensus_required():
    sk = fresh_key(INFO, 71)
    r1 = make_record("r1", INFO, sk, b"m1", k=FIXED_K)
    r2 = make_record("r2", INFO, sk, b"m2", k=FIXED_K)
    r3 = make_record("r3", INFO, sk, b"m3", k=FIXED_K)
    report = analyze([r1, r2, r3])
    group = report.confirmed_groups[0]
    assert group.evidence_record_ids == ["r1", "r2", "r3"]
    assert group.derivation["pair_count_distinct_messages"] == 3
