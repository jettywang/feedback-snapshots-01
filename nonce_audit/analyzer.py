"""nonce 重用分析引擎。

判定哲学:
  相同 r 只是*线索*。只有当候选私钥 d 满足
    1. d*G 等于记录声明的公钥；
    2. 组内每一条相关签名都能用该 d 与推导的 k 解释（标准 ECDSA 验证通过）；
    3. 组内所有可推导配对给出同一个 d；
  才升级为"已确认 nonce 重用"。其余情况保留为线索并给出不能确认的原因。
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from itertools import combinations

from .curves import public_key_xy, scalar_multiply
from .ecdsa_math import (
    DerivedCandidate,
    derive_candidates,
    strict_inverse,
    verify_signature,
)
from .models import Record


# 原因码（稳定字符串，供脚本与报告引用）
REASON_DUPLICATE_RECORD = "duplicate_record"
REASON_SAME_MESSAGE = "same_message_repeat"
REASON_DENOMINATOR_NONINVERTIBLE = "denominator_noninvertible"
REASON_NO_CANDIDATE_MATCHES_PUBKEY = "no_candidate_matches_pubkey"
REASON_SINGLE_RECORD = "single_record"
REASON_CROSS_KEY = "cross_key_r_collision"
REASON_INVALID_SIGNATURE = "invalid_signature_in_group"


@dataclass
class PairAnalysis:
    record_a: str
    record_b: str
    candidates: list[DerivedCandidate]
    denominator_invertible: bool
    natural_denominator_invertible: bool
    same_message: bool
    exact_duplicate: bool


@dataclass
class GroupReport:
    curve: str
    r_hex: str
    record_ids: list[str]
    key_fingerprints: list[str]
    cross_key: bool
    confirmed: bool = False
    reason_codes: list[str] = field(default_factory=list)
    pair_analyses: list[PairAnalysis] = field(default_factory=list)
    evidence_record_ids: list[str] = field(default_factory=list)
    derivation: dict = field(default_factory=dict)
    confirmed_d: int | None = None
    confirmed_k: int | None = None
    invalid_record_ids: list[str] = field(default_factory=list)


@dataclass
class AuditReport:
    total_records: int
    curve_counts: dict
    invalid_records: list[dict]
    groups: list[GroupReport]

    @property
    def confirmed_groups(self) -> list[GroupReport]:
        return [g for g in self.groups if g.confirmed]

    @property
    def unconfirmed_clues(self) -> list[GroupReport]:
        return [g for g in self.groups if not g.confirmed]


def _verify_record(record: Record) -> bool:
    point = record.vk.pubkey.point
    return verify_signature(record.curve_info, record.z, record.sig, point)


def _public_key_matches(record: Record, candidate_d: int) -> bool:
    derived_point = scalar_multiply(record.curve_info, candidate_d)
    px, py = public_key_xy(record.vk)
    return derived_point.x() == px and derived_point.y() == py


def _analyze_same_key_group(
    group: list[Record],
    attached_invalid: set[str],
) -> GroupReport | None:
    head = group[0]
    order = head.curve_info.order
    report = GroupReport(
        curve=head.curve_info.name,
        r_hex=format(head.sig.r, "x"),
        record_ids=[r.record_id for r in group],
        key_fingerprints=sorted({r.fingerprint for r in group}),
        cross_key=False,
    )
    if attached_invalid:
        report.invalid_record_ids = sorted(attached_invalid)
        report.reason_codes.append(REASON_INVALID_SIGNATURE)

    if len(group) == 1:
        report.reason_codes.append(REASON_SINGLE_RECORD)
        return report

    # 配对分析：覆盖重复消息、low-S 方向、不可逆分母等全部情况。
    candidate_votes: list[set[int]] = []
    distinct_message_pairs = 0
    for rec_a, rec_b in combinations(group, 2):
        exact_dup = (
            rec_a.z == rec_b.z and rec_a.normalized_s == rec_b.normalized_s
        )
        same_message = rec_a.z == rec_b.z
        candidates, invertible = derive_candidates(
            head.curve_info, rec_a.z, rec_a.sig, rec_b.z, rec_b.sig
        )
        # 自然方向（两条 s 都按日志原值）下的分母，用于精确标注不可逆原因。
        natural_denom = (rec_a.sig.s - rec_b.sig.s) % order
        natural_invertible = strict_inverse(natural_denom, order) is not None
        analysis = PairAnalysis(
            record_a=rec_a.record_id,
            record_b=rec_b.record_id,
            candidates=candidates,
            denominator_invertible=invertible,
            natural_denominator_invertible=natural_invertible,
            same_message=same_message,
            exact_duplicate=exact_dup,
        )
        report.pair_analyses.append(analysis)

        if exact_dup:
            if REASON_DUPLICATE_RECORD not in report.reason_codes:
                report.reason_codes.append(REASON_DUPLICATE_RECORD)
            # 任一方向上 s1≡s2（含 low-S 规范化造成的 s 与 n-s 相等情形）
            # 都会使差分分母为零，需要明确标注这一不可推导条件。
            if not invertible or not natural_invertible:
                report.reason_codes.append(REASON_DENOMINATOR_NONINVERTIBLE)
            continue
        if same_message:
            if REASON_SAME_MESSAGE not in report.reason_codes:
                report.reason_codes.append(REASON_SAME_MESSAGE)
            continue

        distinct_message_pairs += 1
        if not natural_invertible:
            report.reason_codes.append(REASON_DENOMINATOR_NONINVERTIBLE)
        if not candidates:
            report.reason_codes.append(REASON_NO_CANDIDATE_MATCHES_PUBKEY)
            continue

        # 条件 1: 候选 d 必须能导出声明的公钥。
        matching = [c for c in candidates if _public_key_matches(rec_a, c.d)]
        if not matching:
            report.reason_codes.append(REASON_NO_CANDIDATE_MATCHES_PUBKEY)
            continue
        # k 可能以 k 或 n-k 出现（取决于 s 方向），共识只对 d 投票；
        # k 的两种方向在条件 2 的解释性检查中统一处理。
        candidate_votes.append({c.d for c in matching})

    # 条件 3: 所有可推导配对必须收敛到同一个 d。
    confirmed_d: int | None = None
    if candidate_votes:
        consensus = set.intersection(*candidate_votes)
        if len(consensus) == 1:
            confirmed_d = next(iter(consensus))

    # 条件 2: 组内每条*有效*签名都必须能被候选 d 解释（标准验证已先执行一次）。
    # 挂靠的无效记录不参与推导，只作为告警保留，不阻断对有效证据的确认。
    if confirmed_d is not None:
        all_explained = all(
            _secret_explains_record(order, rec, confirmed_d)
            for rec in group
        )
        if all_explained:
            report.confirmed = True
            report.confirmed_d = confirmed_d
            report.confirmed_k = _recover_k(order, group[0], confirmed_d)
            report.evidence_record_ids = _evidence_ids(group, report)
            orientations = _collect_orientations(report)
            report.derivation = {
                "formula": "d = (s2*z1 - s1*z2) / (r*(s1 - s2)) mod n; "
                "k = (z1 + d*r) / s1 mod n",
                "r": report.r_hex,
                "s_orientations": orientations,
                "pair_count_distinct_messages": distinct_message_pairs,
                "low_s_records": [
                    r.record_id for r in group if r.low_s
                ],
                "high_s_records": [r.record_id for r in group if not r.low_s],
                "checks": [
                    "candidate_d_times_G_equals_public_key",
                    "all_group_signatures_verify",
                    "all_distinct_message_pairs_agree_on_d",
                ],
            }
            report.reason_codes = sorted(set(report.reason_codes))
            return report

    report.reason_codes = sorted(set(report.reason_codes))
    return report


def _secret_explains_record(order: int, record: Record, d_value: int) -> bool:
    """候选 d 必须解释该记录: s*k ≡ z + d*r（mod n），k 或 n-k 均可。"""
    rhs = (record.z + d_value * record.sig.r) % order
    for sign in (record.sig.s, (-record.sig.s) % order):
        inv = strict_inverse(sign, order)
        if inv is None:
            continue
        k_try = (rhs * inv) % order
        if 1 <= k_try < order:
            return True
    return False


def _recover_k(order: int, record: Record, d_value: int) -> int:
    """恢复规范化 k（取 min(k, n-k)），仅在 --reveal-secrets 时输出。"""
    rhs = (record.z + d_value * record.sig.r) % order
    k_value = (rhs * strict_inverse(record.sig.s, order)) % order
    return min(k_value, (-k_value) % order)


def _evidence_ids(group: list[Record], report: GroupReport) -> list[str]:
    """证据记录：去掉完全重复的副本，保留参与差分推导的不同消息签名。"""
    duplicate_ids: set[str] = set()
    for pair in report.pair_analyses:
        if pair.exact_duplicate:
            duplicate_ids.add(pair.record_b)
    return [r.record_id for r in group if r.record_id not in duplicate_ids]


def _collect_orientations(report: GroupReport) -> dict:
    out = {}
    for pair in report.pair_analyses:
        dirs = [
            [cand.s1_orientation, cand.s2_orientation]
            for cand in pair.candidates
            if cand.d == report.confirmed_d
        ]
        if dirs:
            out[f"{pair.record_a}|{pair.record_b}"] = dirs
    return out


def analyze(records: list[Record]) -> AuditReport:
    invalid: list[dict] = []
    valid_records: list[Record] = []
    for record in records:
        if _verify_record(record):
            valid_records.append(record)
        else:
            invalid.append(
                {
                    "id": record.record_id,
                    "curve": record.curve_info.name,
                    "reason": (
                        "signature_does_not_verify_against_"
                        "public_key_and_digest"
                    ),
                }
            )
    invalid_ids = {item["id"] for item in invalid}

    # 按 (曲线, r) 分桶；不同曲线的 r 不可比较。
    buckets: dict[tuple[str, int], list[Record]] = defaultdict(list)
    for record in valid_records:
        buckets[(record.curve_info.name, record.sig.r)].append(record)

    # 无效记录按 (曲线, r) 挂靠到对应桶，仅作告警，不参与密码学推导。
    orphan_invalid: list[dict] = list(invalid)
    invalid_by_bucket: dict[tuple[str, int], list[Record]] = defaultdict(list)
    for record in records:
        if record.record_id in invalid_ids:
            key = (record.curve_info.name, record.sig.r)
            if key in buckets:
                invalid_by_bucket[key].append(record)
                orphan_invalid = [
                    item
                    for item in orphan_invalid
                    if item["id"] != record.record_id
                ]

    groups: list[GroupReport] = []
    for (curve_name, _r), bucket in sorted(
        buckets.items(), key=lambda item: (item[0][0], item[0][1])
    ):
        fingerprints = {r.fingerprint for r in bucket}
        attached_invalid_records = invalid_by_bucket.get((curve_name, _r), [])
        attached_invalid = {r.record_id for r in attached_invalid_records}
        if len(fingerprints) > 1:
            # 跨钥匙 r 碰撞：保留碰撞线索，同时按公钥拆成独立子组分析。
            cross_report = GroupReport(
                curve=curve_name,
                r_hex=format(_r, "x"),
                record_ids=[r.record_id for r in bucket],
                key_fingerprints=sorted(fingerprints),
                cross_key=True,
            )
            cross_report.reason_codes.append(REASON_CROSS_KEY)
            if attached_invalid:
                cross_report.invalid_record_ids = sorted(attached_invalid)
                cross_report.reason_codes.append(REASON_INVALID_SIGNATURE)
            groups.append(cross_report)

            per_key: dict[str, list[Record]] = defaultdict(list)
            for record in bucket:
                per_key[record.fingerprint].append(record)
            for sub in per_key.values():
                sub_fp = sub[0].fingerprint
                sub_invalid = {
                    rec.record_id
                    for rec in attached_invalid_records
                    if rec.fingerprint == sub_fp
                }
                sub_report = _analyze_same_key_group(sub, sub_invalid)
                if sub_report is not None:
                    groups.append(sub_report)
            continue

        report = _analyze_same_key_group(bucket, attached_invalid)
        if report is not None:
            groups.append(report)

    # 无法挂靠到任何有效 r 桶的无效记录，单独成线索组。
    for item in orphan_invalid:
        record = next(r for r in records if r.record_id == item["id"])
        solo = GroupReport(
            curve=record.curve_info.name,
            r_hex=format(record.sig.r, "x"),
            record_ids=[record.record_id],
            key_fingerprints=[record.fingerprint],
            cross_key=False,
        )
        solo.invalid_record_ids = [record.record_id]
        solo.reason_codes = [REASON_INVALID_SIGNATURE, REASON_SINGLE_RECORD]
        groups.append(solo)

    curve_counts: dict[str, int] = defaultdict(int)
    for record in records:
        curve_counts[record.curve_info.name] += 1

    return AuditReport(
        total_records=len(records),
        curve_counts=dict(sorted(curve_counts.items())),
        invalid_records=invalid,
        groups=groups,
    )
