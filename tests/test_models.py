"""样本解析与校验测试。"""

import pytest

from nonce_audit.models import SampleFormatError, parse_records
from nonce_audit.sampler import build_demo_sample
from tests.helpers import fresh_key
from nonce_audit.curves import get_curve


def test_parse_demo_payload():
    payload, _ = build_demo_sample()
    records = parse_records(payload)
    assert len(records) == len(payload["records"])
    assert {r.curve_info.name for r in records} == {"NIST256p"}


def test_duplicate_ids_rejected():
    payload, _ = build_demo_sample()
    payload["records"][1]["id"] = payload["records"][0]["id"]
    with pytest.raises(SampleFormatError, match="记录 id 重复"):
        parse_records(payload)


def test_unknown_curve_rejected():
    payload, _ = build_demo_sample()
    payload["records"][0]["curve"] = "NOPE123"
    with pytest.raises(ValueError, match="不支持的曲线"):
        parse_records(payload)


def test_scalar_out_of_range_rejected():
    payload, _ = build_demo_sample()
    payload["records"][0]["s"] = get_curve("NIST256p").order
    with pytest.raises(SampleFormatError, match="超出曲线阶范围"):
        parse_records(payload)


def test_bad_schema_rejected():
    payload, _ = build_demo_sample()
    payload["schema"] = "something-else"
    with pytest.raises(SampleFormatError, match="schema"):
        parse_records(payload)


def test_sec1_and_pem_key_forms_parse():
    from nonce_audit.curves import parse_public_key

    info = get_curve("NIST256p")
    sk = fresh_key(info, 123)
    vk = sk.get_verifying_key()
    raw = vk.to_string("raw")
    parsed_sec1 = parse_public_key({"sec1": raw.hex()}, info)
    assert parsed_sec1.to_string() == vk.to_string()
    parsed_pem = parse_public_key({"pem": vk.to_pem()}, info)
    assert parsed_pem.to_string() == vk.to_string()
