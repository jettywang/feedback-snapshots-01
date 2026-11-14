"""Structured, reproducible fuzzing of the in-tree OpenPGP parser.

No external gpg process is started. Seeds are taken from the static test
keyrings (tests/gpg_keyrings). All randomness derives from a fixed seed.

Usage:
    python3 tests/fuzz_gpg_parser.py [--report PATH] [--seed N] [--tag LABEL]

Criteria (each with an independent basis):
  C1 trailing-packet isolation
     Basis: parse_signature_packet() slices data[header_len:packet_len];
     bytes of a following packet must never become signature material.
  C2 exception taxonomy
     Basis: docstrings promise PacketParsingError / ValueError / IndexError
     (parse_pubkey_bundle: PacketParsingError only). Anything else escapes
     the publicly catchable parse-error surface.
  C3 truncation integrity
     Basis: RFC4880 MPI/subpacket fields are length-prefixed; a truncated
     packet must raise a parse error, not silently yield different material.
  C4 unknown-subpacket tolerance (legal control)
     Basis: RFC4880 5.2.3.1 - unknown subpacket types must be ignorable.
  C5 bundle walk accounting
     Basis: parse_pubkey_bundle must reject desynchronised packet lengths
     and consume the buffer packet-by-packet without overlap.
"""

import argparse
import collections
import random
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from securesystemslib._gpg import util as gpg_util
from securesystemslib._gpg.common import (
    parse_pubkey_bundle,
    parse_pubkey_payload,
    parse_signature_packet,
)
from securesystemslib._gpg.constants import (
    PACKET_TYPE_PRIMARY_KEY,
    PACKET_TYPE_SIGNATURE,
    PACKET_TYPE_SUB_KEY,
    SHA1,
    SHA256,
    SHA512,
    SIGNATURE_TYPE_CERTIFICATES,
    SIGNATURE_TYPE_SUB_KEY_BINDING,
)
from securesystemslib._gpg.exceptions import (
    KeyNotFoundError,
    PacketParsingError,
    PacketVersionNotSupportedError,
    SignatureAlgorithmNotSupportedError,
)

SEED = 1400
HERE = Path(__file__).resolve().parent
KEYRINGS = HERE / "gpg_keyrings"

ALLOWED_EXCEPTIONS = (
    PacketParsingError,
    ValueError,
    IndexError,
    PacketVersionNotSupportedError,
    SignatureAlgorithmNotSupportedError,
    KeyNotFoundError,
)

SIG_PARSE_KWARGS = {
    "supported_signature_types": {0x00, SIGNATURE_TYPE_SUB_KEY_BINDING}
    | SIGNATURE_TYPE_CERTIFICATES,
    "supported_hash_algorithms": {SHA1, SHA256, SHA512},
    "include_info": True,
}

FINDINGS = []
OUTCOMES = collections.Counter()


def exc_name(exc):
    return f"{type(exc).__module__}.{type(exc).__name__}"


def record(criterion, kind, seed_name, mutation, detail, sample):
    FINDINGS.append(
        {
            "criterion": criterion,
            "kind": kind,
            "seed": seed_name,
            "mutation": mutation,
            "detail": detail,
            "sample": bytes(sample),
        }
    )


# ---------------------------------------------------------------- seeds

def walk_packets(data):
    """Split concatenated RFC4880 packets; returns list of (type, bytes)."""
    packets = []
    pos = 0
    while pos < len(data):
        ptype, _, _, plen = gpg_util.parse_packet_header(data[pos:])
        packets.append((ptype, bytes(data[pos : pos + plen])))
        pos += plen
    return packets


def synthetic_ed25519_pubkey_payload():
    """Structurally valid Ed25519 v4 pubkey payload (parser-shaped seed)."""
    oid = bytes.fromhex("2B06010401DA470F01")
    point = b"\x40" + bytes(range(1, 33))  # 0x40 prefix + 32-byte point
    bitlen = 263  # 33 bytes, top byte 0x40
    return (
        bytes([4]) + b"\x5c\x00\x00\x00" + bytes([22])
        + bytes([len(oid)]) + oid
        + struct.pack(">H", bitlen) + point
    )


def load_seeds():
    seeds = {"sig": [], "pubkey_payload": [], "bundle": []}
    bundle_files = [
        ("rsa", "F557D0FF451DEF45372591429EA70BD13D883381.raw"),
        ("rsa-expired", "E8AC80C924116DABB51D4B987CB07D6D2C199C7C.raw"),
    ]
    for name, fname in bundle_files:
        data = (KEYRINGS / "rsa" / fname).read_bytes()
        seeds["bundle"].append((name, data))
        for ptype, packet in walk_packets(data):
            if ptype == PACKET_TYPE_SIGNATURE:
                seeds["sig"].append((f"{name}-sig", packet))
            elif ptype in (PACKET_TYPE_PRIMARY_KEY, PACKET_TYPE_SUB_KEY):
                _, hlen, _, _ = gpg_util.parse_packet_header(packet)
                seeds["pubkey_payload"].append(
                    (f"{name}-key", bytes(packet[hlen:]))
                )
    seeds["sig"].append(
        ("eddsa-short-sig", (KEYRINGS / "eddsa" / "short.sig").read_bytes())
    )
    # tests/gpg_keyrings/eddsa/pubring.gpg is empty; use a parser-shaped
    # synthetic Ed25519 payload to cover eddsa.get_pubkey_params.
    seeds["pubkey_payload"].append(
        ("eddsa-synth-key", synthetic_ed25519_pubkey_payload())
    )
    return seeds


# ------------------------------------------------- structured offset maps

def sig_layout(packet):
    """Offsets of a v4 signature packet's structural fields."""
    _, hlen, _, plen = gpg_util.parse_packet_header(packet)
    lay = {"header_len": hlen, "packet_len": plen}
    p = hlen + 4  # skip version, sig type, sig alg, hash alg
    lay["hashed_count_off"] = p
    (hc,) = struct.unpack(">H", packet[p : p + 2])
    p += 2
    lay["hashed_off"] = p
    lay["hashed_len"] = hc
    p += hc
    lay["unhashed_count_off"] = p
    (uc,) = struct.unpack(">H", packet[p : p + 2])
    p += 2
    lay["unhashed_off"] = p
    lay["unhashed_len"] = uc
    p += uc
    lay["left16_off"] = p
    lay["mpi_off"] = p + 2
    return lay


def subpacket_offsets(area, base):
    """Absolute offsets of subpacket length octets inside an area."""
    offs = []
    pos = 0
    while pos < len(area):
        try:
            _, hlen, _, slen = gpg_util.parse_subpacket_header(area[pos:])
        except Exception:
            break
        offs.append((base + pos, hlen, slen))
        pos += slen
    return offs


def mpi_len_offsets_pub(payload):
    """Bit-length field offsets of the MPI chain in an RSA/DSA pubkey payload."""
    offs = []
    p = 6  # version(1) + creation time(4) + algorithm(1)
    for _ in range(4):  # at most 4 MPIs (DSA); RSA stops earlier
        if p + 2 > len(payload):
            break
        offs.append(p)
        mlen = gpg_util.get_mpi_length(payload[p : p + 2])
        p += 2 + mlen
    return offs


def mpi_len_offsets_sig(packet, lay):
    """Bit-length field offsets of trailing signature MPIs (best effort)."""
    offs = []
    p = lay["mpi_off"]
    for _ in range(2):
        if p + 2 > len(packet):
            break
        offs.append(p)
        mlen = gpg_util.get_mpi_length(packet[p : p + 2])
        p += 2 + mlen
    return offs


# ------------------------------------------------------------ mutations

def encode_header(ptype, n):
    """New-format packet header for a claimed body length n."""
    first = 0xC0 | ptype
    if n < 192:
        return bytes([first, n])
    if n <= 8383:
        n -= 192
        return bytes([first, (n >> 8) + 192, n & 0xFF])
    return bytes([first, 255]) + struct.pack(">I", n)


def encode_new_packet(ptype, body):
    """Re-encode a packet with a new-format header and minimal length."""
    return encode_header(ptype, len(body)) + bytes(body)


def mut_packet_lengths(packet):
    """Desync and re-sync packet length mutations."""
    ptype, hlen, blen, _ = gpg_util.parse_packet_header(packet)
    body = packet[hlen : hlen + blen]
    out = []
    for delta in (-2, -1, 1, 2, 8, 64):
        nb = blen + delta
        if nb < 0:
            continue
        # (a) header lies, body unchanged
        out.append(
            (encode_header(ptype, nb) + body, f"len-field={nb} body-unchanged")
        )
        # (b) body adjusted to match the (lying) header
        adj = body[:nb] if nb <= len(body) else body + b"\x00" * (nb - len(body))
        out.append((encode_new_packet(ptype, adj), f"len-field={nb} body-adjusted"))
    return out


def mut_truncations(data, points):
    cuts = sorted({p for p in points if 1 <= p < len(data)})
    return [(data[:c], f"truncate@{c}") for c in cuts]


def mut_subpacket_areas(packet, lay):
    """Mutate hashed/unhashed count fields and individual subpacket headers."""
    out = []
    for area_name in ("hashed", "unhashed"):
        count_off = lay[f"{area_name}_count_off"]
        area_off = lay[f"{area_name}_off"]
        area_len = lay[f"{area_name}_len"]
        for new_count in (0, 1, area_len - 1, area_len + 1, 0xFFFF):
            if new_count < 0:
                continue
            m = bytearray(packet)
            m[count_off : count_off + 2] = struct.pack(">H", new_count & 0xFFFF)
            out.append((bytes(m), f"{area_name}-count={new_count}"))
        area = packet[area_off : area_off + area_len]
        for abs_off, hlen, slen in subpacket_offsets(area, area_off):
            for new_len in (0, 1, slen - 1, slen + 1, 255):
                if new_len < 0 or new_len > 191:
                    continue
                m = bytearray(packet)
                m[abs_off] = new_len
                out.append(
                    (bytes(m), f"{area_name}-subpacket-len@{abs_off}={new_len}")
                )
    return out


def mut_mpi_bitlengths(data, offsets):
    out = []
    for off in offsets:
        if off + 2 > len(data):
            continue
        (orig,) = struct.unpack(">H", data[off : off + 2])
        for bits in (0, 1, 7, 8, 9, orig - 1, orig + 1, orig + 8, 0x7FFF, 0xFFFF):
            if bits < 0:
                continue
            m = bytearray(data)
            m[off : off + 2] = struct.pack(">H", bits & 0xFFFF)
            out.append((bytes(m), f"mpi-bitlen@{off}:{orig}->{bits & 0xFFFF}"))
    return out


def insert_subpacket(packet, lay, area_name, subpacket):
    """Insert a well-formed subpacket, fixing area count AND packet header."""
    ptype = packet[0] & 0x3F if packet[0] & 0x40 else (packet[0] & 0x3C) >> 2
    hlen = lay["header_len"]
    body = bytearray(packet[hlen : lay["packet_len"]])
    count_off = lay[f"{area_name}_count_off"] - hlen
    area_off = lay[f"{area_name}_off"] - hlen
    area_len = lay[f"{area_name}_len"]
    new_area = subpacket + body[area_off : area_off + area_len]
    body[count_off : count_off + 2] = struct.pack(">H", len(new_area))
    body[area_off : area_off + area_len] = new_area
    return encode_new_packet(ptype, bytes(body))


# -------------------------------------------------------------- minimizer

def minimize(sample, pred, budget=4000):
    """Deterministic ddmin-lite: chunk deletion, then byte zeroing."""
    data = bytes(sample)
    chunk = max(1, len(data) // 2)
    while chunk >= 1 and budget > 0:
        i = 0
        while i < len(data) and budget > 0:
            cand = data[:i] + data[i + chunk :]
            budget -= 1
            if cand and cand != data and pred(cand):
                data = cand
            else:
                i += chunk
        chunk //= 2
    for i in range(len(data)):
        if data[i] != 0 and budget > 0:
            cand = data[:i] + b"\x00" + data[i + 1 :]
            budget -= 1
            if pred(cand):
                data = cand
    return data


# ---------------------------------------------------------------- oracles

def run_sig(data):
    try:
        return ("ok", parse_signature_packet(bytes(data), **SIG_PARSE_KWARGS))
    except Exception as e:  # noqa: BLE001 - taxonomy is what we measure
        return ("err", e)


def run_pub_payload(data):
    try:
        return ("ok", parse_pubkey_payload(bytearray(data)))
    except Exception as e:  # noqa: BLE001
        return ("err", e)


def run_bundle(data):
    try:
        return ("ok", parse_pubkey_bundle(bytes(data)))
    except Exception as e:  # noqa: BLE001
        return ("err", e)


def check_taxonomy(criterion, seed_name, mutation, status, exc, sample):
    if status == "err" and not isinstance(exc, ALLOWED_EXCEPTIONS):
        record(
            criterion, "EXC-TAXONOMY", seed_name, mutation,
            f"unexpected exception {exc_name(exc)}: {exc}", sample,
        )
        OUTCOMES[(criterion, "finding")]
        return False
    OUTCOMES[(criterion, "allowed" if status == "err" else "ok")]
    return True


def comparable(result):
    """Projection of a parsed signature relevant to material identity."""
    return {
        k: result.get(k)
        for k in ("keyid", "short_keyid", "other_headers", "signature")
    }


# ------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", help="write markdown report to this path")
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--tag", default="", help="label for weakened runs")
    args = ap.parse_args()
    rng = random.Random(args.seed)

    seeds = load_seeds()
    print(
        f"seeds: {len(seeds['sig'])} signature packets, "
        f"{len(seeds['pubkey_payload'])} pubkey payloads, "
        f"{len(seeds['bundle'])} bundles"
    )

    baselines = {}
    consumption = []

    # ---- baselines, consumption map
    for name, packet in seeds["sig"]:
        status, res = run_sig(packet)
        if status != "ok":
            continue
        baselines[packet] = res
        consumption.append((name, len(packet), sig_layout(packet)))

    trailers = list(baselines)[:2] + [b"\x00\x00\x00\x00"]

    # ---- C1 trailing isolation
    for packet, base in baselines.items():
        lay = sig_layout(packet)
        consumed = lay["packet_len"]
        for trailer in trailers:
            if trailer is packet:
                continue
            joined = packet + trailer
            status, res = run_sig(joined)
            if status == "ok":
                if comparable(res) != comparable(base):
                    record("C1", "TRAILING-SWALLOW", "sig-seed",
                           f"append {len(trailer)}B trailer",
                           "parsed material changed when trailer appended",
                           joined)
                if gpg_util.parse_packet_header(joined)[3] != consumed:
                    record("C1", "CONSUMED-LEN", "sig-seed", "append trailer",
                           "consumed length changed", joined)
            else:
                record("C1", "TRAILING-BREAKS-PARSE", "sig-seed",
                       "append trailer", f"parse failed: {res}", joined)
            OUTCOMES[("C1", "checked")] += 1

    # ---- C2/C3 over signature packets
    for name, packet in seeds["sig"]:
        status, base = run_sig(packet)
        base_cmp = comparable(base) if status == "ok" else None
        try:
            lay = sig_layout(packet)
            mpi_offs = mpi_len_offsets_sig(packet, lay)
        except Exception:
            lay, mpi_offs = None, []

        mutations = list(mut_packet_lengths(packet))
        if lay:
            mutations += list(mut_subpacket_areas(packet, lay))
            points = [
                lay["hashed_count_off"], lay["hashed_off"],
                lay["unhashed_count_off"], lay["unhashed_off"],
                lay["left16_off"], lay["mpi_off"], lay["packet_len"] - 1,
            ]
            for area_name in ("hashed", "unhashed"):
                area = packet[lay[f"{area_name}_off"]:
                              lay[f"{area_name}_off"] + lay[f"{area_name}_len"]]
                points += [o for o, _, _ in
                           subpacket_offsets(area, lay[f"{area_name}_off"])]
            points += [p + d for p in list(points) for d in (-1, 1)]
            points += mpi_offs
            rnd_points = rng.sample(range(1, len(packet)),
                                    min(120, len(packet) - 1))
            mutations += mut_truncations(packet, points + rnd_points)
        mutations += mut_mpi_bitlengths(packet, mpi_offs)

        for sample, desc in mutations:
            status, res = run_sig(sample)
            if not check_taxonomy("C2", name, desc, status, res, sample):
                continue
            if (status == "ok" and base_cmp is not None
                    and desc.startswith("truncate")
                    and comparable(res) != base_cmp):
                record("C3", "SILENT-TRUNC", name, desc,
                       "truncated packet parsed with different material",
                       sample)
                OUTCOMES[("C3", "finding")] += 1
            elif desc.startswith("truncate"):
                OUTCOMES[("C3", "allowed-or-equal")] += 1

    # ---- C2/C3 over pubkey payloads
    for name, payload in seeds["pubkey_payload"]:
        status, base = run_pub_payload(payload)
        base_pub = (
            base["keyval"]["public"] if status == "ok" else None
        )
        if name.startswith("eddsa"):
            # version(1)+time(4)+alg(1)+oid_len(1)+oid(9) -> MPI bitlen @ 16
            mpi_offs = [16]
        else:
            mpi_offs = mpi_len_offsets_pub(payload)
        mutations = mut_mpi_bitlengths(payload, mpi_offs)
        points = sorted(set(
            mpi_offs + [p + d for p in mpi_offs for d in (-1, 1, 2)]
            + [6, 7, len(payload) - 1]
        ))
        mutations += mut_truncations(payload, points)
        for sample, desc in mutations:
            status, res = run_pub_payload(sample)
            if not check_taxonomy("C2", name, desc, status, res, sample):
                continue
            if (status == "ok" and base_pub is not None
                    and desc.startswith("truncate")
                    and res["keyval"]["public"] != base_pub):
                record("C3", "SILENT-TRUNC-PUB", name, desc,
                       "truncated pubkey payload parsed with different params",
                       sample)
                OUTCOMES[("C3-pub", "finding")] += 1
            elif desc.startswith("truncate"):
                OUTCOMES[("C3-pub", "allowed-or-equal")] += 1

    # ---- C2/C5 over bundles
    for name, bundle in seeds["bundle"]:
        packets = walk_packets(bundle)
        boundaries = []
        pos = 0
        for _, p in packets:
            boundaries += [pos, pos + 1, pos + len(p) - 1, pos + len(p)]
            pos += len(p)
        mutations = mut_truncations(bundle, sorted(set(boundaries)))
        ptype, hlen, blen, _ = gpg_util.parse_packet_header(packets[0][1])
        rest = bundle[len(packets[0][1]):]
        body = packets[0][1][hlen:hlen + blen]
        for nb in (0, 1, 5, 6, 7, 8, blen - 1, blen + 1, blen + 8):
            if nb < 0:
                continue
            adj = body[:nb] if nb <= len(body) else body + b"\x00" * (nb - len(body))
            mutations.append((encode_new_packet(ptype, adj) + rest,
                              f"primary-len={nb}+rest"))
            # header lies about primary key length, stream bytes unchanged
            mutations.append((encode_header(ptype, nb) + body + rest,
                              f"primary-len-field={nb} desync"))
        for sample, desc in mutations:
            status, res = run_bundle(sample)
            check_taxonomy("C2", name, desc, status, res, sample)
            if status == "ok" and desc.startswith("primary-len="):
                record("C5", "PUBKEY-TRAILING-GARBAGE", name, desc,
                       "pubkey payload parser ignores trailing body bytes; "
                       "non-canonical packet accepted, keyid silently differs",
                       sample)
                OUTCOMES[("C5", "finding")] += 1
            elif desc.startswith("primary-len"):
                OUTCOMES[("C5", "rejected")] += 1
            if status == "ok" and "desync" in desc:
                record("C5", "DESYNC-ACCEPTED", name, desc,
                       "bundle accepted although primary key length field "
                       "desynchronises the packet walk", sample)
                OUTCOMES[("C5", "finding")] += 1

    # ---- C4 legal control: unknown subpackets must be ignorable
    unknown_sub = bytes([3, 100, 0xDE, 0xAD])  # len=3, type=100, 2B payload
    zero_len_sub = bytes([0])  # length 0: invalid per RFC (len includes type)
    for packet, base in list(baselines.items()):
        lay = sig_layout(packet)
        base_mat = {k: base.get(k) for k in ("keyid", "short_keyid", "signature")}
        base_subs = set(base.get("info", {}).get("subpackets", {}))
        for area in ("hashed", "unhashed"):
            ctrl = insert_subpacket(packet, lay, area, unknown_sub)
            status, res = run_sig(ctrl)
            OUTCOMES[("C4", "checked")] += 1
            if status != "ok":
                record("C4", "UNKNOWN-SUBPACKET-REJECTED", "sig-seed",
                       f"insert unknown subpacket type 100 in {area}",
                       f"legal control failed: {res}", ctrl)
            elif {k: res.get(k) for k in base_mat} != base_mat:
                record("C4", "UNKNOWN-SUBPACKET-SHIFTS-MATERIAL", "sig-seed",
                       f"insert unknown subpacket in {area}",
                       "keyid/signature changed by ignorable subpacket", ctrl)
            mutated = insert_subpacket(packet, lay, area, zero_len_sub)
            status, res = run_sig(mutated)
            if status == "ok":
                got = set(res.get("info", {}).get("subpackets", {}))
                if got != base_subs:
                    record("C4", "ZERO-LEN-SUBPACKET-MISPARSE", "sig-seed",
                           f"insert zero-length subpacket in {area}",
                           f"invalid 0-length subpacket silently accepted; "
                           f"subpacket types {sorted(got)} != {sorted(base_subs)}",
                           mutated)

    # ---- minimize one reproducer per finding class
    def predicate_for(f):
        base = baselines.get(f["sample"])
        def pred(sample):
            if f["kind"] == "EXC-TAXONOMY":
                want = f["detail"].split(":")[0].replace("unexpected exception ", "")
                for runner in (run_sig, run_pub_payload, run_bundle):
                    s, r = runner(sample)
                    if s == "err" and exc_name(r) == want:
                        return True
                return False
            if f["kind"] == "SILENT-TRUNC":
                s, r = run_sig(sample)
                return s == "ok"
            if f["kind"] == "SILENT-TRUNC-PUB":
                s, _ = run_pub_payload(sample)
                return s == "ok"
            if f["kind"] == "ZERO-LEN-SUBPACKET-MISPARSE":
                s, _ = run_sig(sample)
                return s == "ok"
            if f["kind"] in ("TRAILING-SWALLOW", "DESYNC-ACCEPTED",
                             "PUBKEY-TRAILING-GARBAGE"):
                s, _ = run_sig(sample)
                t, _ = run_bundle(sample)
                return s == "ok" or t == "ok"
            return False
        return pred

    minimized = []
    seen = set()
    for f in FINDINGS:
        if f["kind"] == "EXC-TAXONOMY":
            dedup = f["detail"]
        else:
            dedup = f["mutation"].split("@")[0].split("=")[0]
        key = (f["criterion"], f["kind"], dedup, f["seed"].split("-")[0])
        if key in seen:
            continue
        seen.add(key)
        pred = predicate_for(f)
        short = minimize(f["sample"], pred) if pred(f["sample"]) else f["sample"]
        minimized.append((f, short))

    # ---- report
    try:
        rev = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, cwd=HERE.parent,
        ).stdout.strip()
    except Exception:
        rev = "unknown"

    lines = []
    w = lines.append
    w(f"# OpenPGP parser structured fuzz report {args.tag}\n")
    w(f"- seed: `{args.seed}`, harness: `tests/fuzz_gpg_parser.py`, rev: `{rev}`")
    w(f"- seeds: {len(seeds['sig'])} sig packets, "
      f"{len(seeds['pubkey_payload'])} pubkey payloads, "
      f"{len(seeds['bundle'])} bundles (from tests/gpg_keyrings, no gpg invoked)\n")
    w("## Consumption map (bytes the parser consumes per seed packet)\n")
    for name, plen, lay in consumption:
        w(f"- `{name}` packet_len={plen} header=[0,{lay['header_len']}) "
          f"hashed=[{lay['hashed_off']},{lay['hashed_off'] + lay['hashed_len']}) "
          f"unhashed=[{lay['unhashed_off']},{lay['unhashed_off'] + lay['unhashed_len']}) "
          f"left16=[{lay['left16_off']},{lay['left16_off'] + 2}) "
          f"mpi=[{lay['mpi_off']},{plen})")
    w("\n## Mutation outcomes\n")
    for (crit, outcome), n in sorted(OUTCOMES.items()):
        w(f"- {crit} {outcome}: {n}")
    w("\n## Findings\n")
    if not minimized:
        w("no findings\n")
    for f, short in minimized:
        w(f"### {f['criterion']} {f['kind']}\n")
        w(f"- seed: `{f['seed']}`, mutation: `{f['mutation']}`")
        w(f"- detail: {f['detail']}")
        w(f"- minimized sample ({len(short)}B, was {len(f['sample'])}B):")
        w(f"  `{short.hex()}`\n")
    report = "\n".join(lines)
    print(report)
    if args.report:
        Path(args.report).write_text(report)
        print(f"report written to {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
