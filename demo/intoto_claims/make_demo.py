#!/usr/bin/env python3
"""Reproduce in-toto claim boundaries with local test keys.

No verification rule is changed. This script only:

  1. loads the repository's PEM test keys (tests/pems/*),
  2. builds signed Layout and Link metadata with the repo's own models,
  3. calls the repo's own ``verifylib.in_toto_verify``, and
  4. writes the resulting evidence under ``out/``.

Run from the repository root:

    .venv/bin/python demo/intoto_claims/make_demo.py
"""

import copy
import hashlib
import json
import logging
import os
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from in_toto.models._signer import (  # noqa: E402
    load_crypto_signer_from_pkcs8_file as load_signer,
    load_public_key_from_file as load_pubkey,
)
from in_toto.models.layout import (  # noqa: E402
    SUBLAYOUT_LINK_DIR_FORMAT,
    Inspection,
    Layout,
    Step,
)
from in_toto.models.link import FILENAME_FORMAT, Link  # noqa: E402
from in_toto.models.metadata import Metablock, Metadata  # noqa: E402
from in_toto.runlib import (  # noqa: E402
    in_toto_record_start,
    in_toto_record_stop,
)
from in_toto.verifylib import in_toto_verify  # noqa: E402

DEMO = Path(__file__).resolve().parent
OUT = DEMO / "out"
PEMS = REPO / "tests" / "pems"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def artifact(data):
    return {"sha256": sha256(data)}


def load_keys():
    """Load four distinct local test keys from tests/pems."""
    keys = {}
    for name, priv, pub in [
        ("owner", "ecdsa_private_unencrypted.pem", "ecdsa_public.pem"),
        ("functionary", "ed25519_private_unencrypted.pem", "ed25519_public.pem"),
        ("peer", "rsa_private_unencrypted.pem", "rsa_public.pem"),
    ]:
        signer = load_signer(PEMS / priv)
        pubkey = load_pubkey(PEMS / pub)
        keys[name] = {"signer": signer, "pub": pubkey, "keyid": pubkey["keyid"]}
    return keys


def signed_layout(layout, signer):
    metadata = Metablock(signed=layout)
    metadata.create_signature(signer)
    return metadata


def signed_link(link, signer):
    metadata = Metablock(signed=link)
    metadata.create_signature(signer)
    return metadata


def write_link(path, metadata, step_name, keyid):
    path.mkdir(parents=True, exist_ok=True)
    metadata.dump(str(path / FILENAME_FORMAT.format(step_name=step_name, keyid=keyid)))


def attempt(layout_metadata, owner_pub, link_dir, cwd=None):
    """Run verification exactly as in_toto-verify does, capturing the result."""
    result = {"passed": False, "exception": None, "summary": None}
    original_cwd = os.getcwd()
    try:
        if cwd is not None:
            os.chdir(cwd)
        summary = in_toto_verify(
            layout_metadata,
            {owner_pub["keyid"]: owner_pub},
            link_dir_path=str(link_dir),
            persist_inspection_links=False,
        )
        result["passed"] = True
        result["summary"] = summary
    except Exception as exc:  # noqa: BLE001 - we report the exception class
        result["exception"] = f"{type(exc).__name__}: {exc}"
    finally:
        os.chdir(original_cwd)
    return result


def dump(name, obj):
    path = OUT / name
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")
    return path


def main():
    logging.getLogger("in_toto").setLevel(logging.CRITICAL)
    OUT.mkdir(exist_ok=True)
    keys = load_keys()
    owner, functionary, peer = keys["owner"], keys["functionary"], keys["peer"]

    scenario = {}

    # ------------------------------------------------------------------
    # S1/S2: same artifacts, different command -- a passing verification
    # whose summary reports the Link's command, not the layout's command.
    # ------------------------------------------------------------------
    src = b'int main(void) { return 0; }\n'
    binary = b'BUILT-BINARY-BYTES\n'

    s1_links = OUT / "s1_links"
    s1 = OUT / "s1_links"
    shutil.rmtree(s1, ignore_errors=True)
    s1.mkdir(parents=True)
    (s1 / "src.c").write_bytes(src)
    (s1 / "app").write_bytes(binary)

    layout = Layout(
        keys={functionary["keyid"]: functionary["pub"]},
        steps=[
            Step(
                name="compile",
                pubkeys=[functionary["keyid"]],
                expected_command=["make", "release"],
                expected_materials=[["ALLOW", "*"]],
                expected_products=[["ALLOW", "*"]],
                threshold=1,
            )
        ],
    )
    layout_metadata = signed_layout(layout, owner["signer"])

    # Link claims: this is the evidence the functionary signed.
    link = Link(
        name="compile",
        command=["make", "ship"],
        materials={"src.c": artifact(src)},
        products={"app": artifact(binary)},
        byproducts={"stdout": "shipped\n", "stderr": "", "return-value": 0},
        environment={},
    )
    link_metadata = signed_link(link, functionary["signer"])

    write_link(s1, link_metadata, "compile", functionary["keyid"])
    layout_metadata.dump(str(s1 / "root.layout"))
    s1_layout_result = attempt(layout_metadata, owner["pub"], s1)
    scenario["s1_different_command_same_artifacts"] = {
        "layout_expected_command": layout.steps[0].expected_command,
        "link_reported_command": link.command,
        "passed": s1_layout_result["passed"],
        "exception": s1_layout_result["exception"],
        "summary_command": (
            s1_layout_result["summary"].command
            if s1_layout_result["summary"]
            else None
        ),
    }

    # ------------------------------------------------------------------
    # S2: the same signed artifacts, but one byte changed in the Link after
    # signing. This is the control for S1: the signature check rejects it.
    # ------------------------------------------------------------------
    s2 = OUT / "s2_tampered"
    shutil.rmtree(s2, ignore_errors=True)
    s2.mkdir(parents=True)
    tampered = copy.deepcopy(link_metadata.to_dict())
    tampered["signed"]["materials"]["src.c"]["sha256"] = sha256(b"other source\n")
    tampered_metadata = Metablock.from_dict(tampered)
    tampered_metadata.dump(
        str(s2 / FILENAME_FORMAT.format(step_name="compile", keyid=functionary["keyid"]))
    )
    layout_metadata.dump(str(s2 / "root.layout"))
    s2_result = attempt(layout_metadata, owner["pub"], s2)
    scenario["s2_tampered_after_signing"] = {
        "passed": s2_result["passed"],
        "exception": s2_result["exception"],
    }

    # ------------------------------------------------------------------
    # S3: signed Link with artifacts but no execution evidence at all.
    # Produced with the official two-phase recording API, whose Link has an
    # empty command and empty byproducts unless the caller supplies them.
    # ------------------------------------------------------------------
    s3 = OUT / "s3_links"
    shutil.rmtree(s3, ignore_errors=True)
    s3.mkdir(parents=True)
    work = s3 / "work"
    work.mkdir()
    (work / "src.c").write_bytes(src)
    (work / "app").write_bytes(binary)

    layout3 = Layout(
        keys={functionary["keyid"]: functionary["pub"]},
        steps=[
            Step(
                name="compile",
                pubkeys=[functionary["keyid"]],
                expected_command=["make", "release"],
                expected_materials=[["ALLOW", "*"]],
                expected_products=[["ALLOW", "*"]],
                threshold=1,
            )
        ],
    )
    layout3_metadata = signed_layout(layout3, owner["signer"])

    cwd = os.getcwd()
    os.chdir(work)
    try:
        in_toto_record_start("compile", ["src.c"], signer=functionary["signer"])
        in_toto_record_stop("compile", ["app"], signer=functionary["signer"])
    finally:
        os.chdir(cwd)
    recorded = Metadata.load(
        str(work / FILENAME_FORMAT.format(step_name="compile", keyid=functionary["keyid"]))
    )
    recorded_payload = recorded.get_payload()
    shutil.move(
        str(work / FILENAME_FORMAT.format(step_name="compile", keyid=functionary["keyid"])),
        str(s3),
    )
    layout3_metadata.dump(str(s3 / "root.layout"))
    s3_result = attempt(layout3_metadata, owner["pub"], s3)
    scenario["s3_no_execution_evidence"] = {
        "created_by": "in_toto_record_start + in_toto_record_stop",
        "layout_expected_command": layout3.steps[0].expected_command,
        "link_reported_command": recorded_payload.command,
        "link_reported_byproducts": recorded_payload.byproducts,
        "passed": s3_result["passed"],
        "exception": s3_result["exception"],
        "summary_command": (
            s3_result["summary"].command if s3_result["summary"] else None
        ),
    }

    # ------------------------------------------------------------------
    # S4: threshold=2 with two distinct authorized signers whose commands
    # and byproducts differ but whose materials/products agree.
    # ------------------------------------------------------------------
    s4 = OUT / "s4_links"
    shutil.rmtree(s4, ignore_errors=True)
    s4.mkdir(parents=True)

    layout4 = Layout(
        keys={
            functionary["keyid"]: functionary["pub"],
            peer["keyid"]: peer["pub"],
        },
        steps=[
            Step(
                name="compile",
                pubkeys=[functionary["keyid"], peer["keyid"]],
                expected_command=["make", "release"],
                expected_materials=[["ALLOW", "*"]],
                expected_products=[["ALLOW", "*"]],
                threshold=2,
            )
        ],
    )
    layout4_metadata = signed_layout(layout4, owner["signer"])

    for description, signer, keyid in [
        ("functionary", functionary["signer"], functionary["keyid"]),
        ("peer", peer["signer"], peer["keyid"]),
    ]:
        link = Link(
            name="compile",
            command=["make", description],
            materials={"src.c": artifact(src)},
            products={"app": artifact(binary)},
            byproducts={"return-value": 0 if description == "functionary" else 7},
            environment={},
        )
        write_link(s4, signed_link(link, signer), "compile", keyid)
    layout4_metadata.dump(str(s4 / "root.layout"))
    s4_result = attempt(layout4_metadata, owner["pub"], s4)
    scenario["s4_threshold_command_disagreement"] = {
        "layout_expected_command": layout4.steps[0].expected_command,
        "link_commands": ["make functionary", "make peer"],
        "return_values": [0, 7],
        "passed": s4_result["passed"],
        "exception": s4_result["exception"],
    }

    # ------------------------------------------------------------------
    # S5: threshold=2 with differing products -> threshold fails.
    # Proves artifacts, not commands, are the threshold-checked fields.
    # ------------------------------------------------------------------
    s5 = OUT / "s5_links"
    shutil.rmtree(s5, ignore_errors=True)
    s5.mkdir(parents=True)
    layout5_metadata = signed_layout(layout4, owner["signer"])
    for description, signer, keyid in [
        ("a", functionary["signer"], functionary["keyid"]),
        ("b", peer["signer"], peer["keyid"]),
    ]:
        link = Link(
            name="compile",
            command=["make", "release"],
            materials={"src.c": artifact(src)},
            products={"app": artifact(binary + description.encode())},
            byproducts={"return-value": 0},
            environment={},
        )
        write_link(s5, signed_link(link, signer), "compile", keyid)
    layout5_metadata.dump(str(s5 / "root.layout"))
    s5_result = attempt(layout5_metadata, owner["pub"], s5)
    scenario["s5_threshold_artifact_disagreement"] = {
        "passed": s5_result["passed"],
        "exception": s5_result["exception"],
    }

    # ------------------------------------------------------------------
    # S6: sublayout. The outer layout delegates to an inner layout. The
    # summary Link is synthesized from the inner steps' endpoints.
    # ------------------------------------------------------------------
    s6 = OUT / "s6_links"
    shutil.rmtree(s6, ignore_errors=True)
    subdir = s6 / SUBLAYOUT_LINK_DIR_FORMAT.format(
        name="delegate", keyid=functionary["keyid"]
    )
    subdir.mkdir(parents=True)

    inner_layout = Layout(
        keys={peer["keyid"]: peer["pub"]},
        steps=[
            Step(
                name="inner-compile",
                pubkeys=[peer["keyid"]],
                expected_command=["compile", "src.c"],
                expected_materials=[["ALLOW", "*"]],
                expected_products=[["ALLOW", "*"]],
                threshold=1,
            )
        ],
    )
    inner_metadata = signed_layout(inner_layout, functionary["signer"])
    inner_metadata.dump(
        str(s6 / FILENAME_FORMAT.format(step_name="delegate", keyid=functionary["keyid"]))
    )

    inner_link = Link(
        name="inner-compile",
        command=["compile", "src.c"],
        materials={"src.c": artifact(src)},
        products={"app": artifact(binary)},
        byproducts={"return-value": 0},
        environment={},
    )
    write_link(subdir, signed_link(inner_link, peer["signer"]), "inner-compile", peer["keyid"])

    outer_layout = Layout(
        keys={functionary["keyid"]: functionary["pub"]},
        steps=[
            Step(
                name="delegate",
                pubkeys=[functionary["keyid"]],
                expected_command=["make", "release"],
                expected_materials=[["ALLOW", "*"]],
                expected_products=[["ALLOW", "*"]],
                threshold=1,
            )
        ],
    )
    outer_metadata = signed_layout(outer_layout, owner["signer"])
    outer_metadata.dump(str(s6 / "root.layout"))
    s6_result = attempt(outer_metadata, owner["pub"], s6)
    summary = s6_result["summary"]
    scenario["s6_sublayout_summary"] = {
        "outer_expected_command": outer_layout.steps[0].expected_command,
        "inner_link_command": inner_link.command,
        "passed": s6_result["passed"],
        "exception": s6_result["exception"],
        "summary": None
        if summary is None
        else {
            "name": summary.name,
            "command": summary.command,
            "byproducts": summary.byproducts,
            "materials": summary.materials,
            "products": summary.products,
        },
    }

    # ------------------------------------------------------------------
    # S7: an Inspection re-hashes the file on disk and MATCHes it against
    # the Link's products. This is the only check in the chain that ties a
    # claimed product hash to bytes actually present at verification time.
    #
    # S7a: the bytes on disk differ from the claimed product hash.
    #      MATCH silently consumes nothing; no error is raised unless a
    #      catch-all rule is present. S7b adds DISALLOW * to make it fail.
    # ------------------------------------------------------------------
    s7 = OUT / "s7_inspection"
    shutil.rmtree(s7, ignore_errors=True)
    s7.mkdir(parents=True)

    for suffix, product_rules in [
        ("match_only", [["MATCH", "app", "WITH", "PRODUCTS", "FROM", "compile"]]),
        (
            "match_and_disallow",
            [
                ["MATCH", "app", "WITH", "PRODUCTS", "FROM", "compile"],
                ["DISALLOW", "app"],
            ],
        ),
    ]:
        d = s7 / suffix
        d.mkdir()
        (d / "src.c").write_bytes(src)
        (d / "app").write_bytes(b"DIFFERENT-FROM-CLAIM\n")
        layout7 = Layout(
            keys={functionary["keyid"]: functionary["pub"]},
            steps=[
                Step(
                    name="compile",
                    pubkeys=[functionary["keyid"]],
                    expected_command=["make", "release"],
                    expected_materials=[],
                    expected_products=[],
                    threshold=1,
                )
            ],
            inspect=[
                Inspection(
                    name="rehash",
                    run=[sys.executable, "-c", "pass"],
                    expected_materials=[],
                    expected_products=product_rules,
                )
            ],
        )
        layout7_metadata = signed_layout(layout7, owner["signer"])
        layout7_metadata.dump(str(d / "root.layout"))
        claimed_link = Link(
            name="compile",
            command=["make", "release"],
            materials={"src.c": artifact(src)},
            products={"app": artifact(binary)},
            byproducts={"return-value": 0},
            environment={},
        )
        write_link(
            d,
            signed_link(claimed_link, functionary["signer"]),
            "compile",
            functionary["keyid"],
        )
        result = attempt(layout7_metadata, owner["pub"], d, cwd=d)
        scenario[f"s7_artifact_rule_{suffix}"] = {
            "disk_app_hash": sha256(b"DIFFERENT-FROM-CLAIM\n"),
            "claimed_app_hash": sha256(binary),
            "passed": result["passed"],
            "exception": result["exception"],
        }

    # ------------------------------------------------------------------
    # S8: a Step Link may itself carry a signed non-zero return value. Step
    # return values are never inspected; only Inspection return values are.
    # ------------------------------------------------------------------
    s8 = OUT / "s8_retval"
    shutil.rmtree(s8, ignore_errors=True)
    s8.mkdir(parents=True)
    layout8_metadata = signed_layout(layout, owner["signer"])
    layout8_metadata.dump(str(s8 / "root.layout"))
    failed_link = Link(
        name="compile",
        command=["make", "release"],
        materials={"src.c": artifact(src)},
        products={"app": artifact(binary)},
        byproducts={"return-value": 7, "stderr": "signed failure\n"},
        environment={},
    )
    write_link(
        s8,
        signed_link(failed_link, functionary["signer"]),
        "compile",
        functionary["keyid"],
    )
    s8_result = attempt(layout8_metadata, owner["pub"], s8)
    scenario["s8_step_signed_nonzero_retval"] = {
        "link_return_value": 7,
        "passed": s8_result["passed"],
        "exception": s8_result["exception"],
    }

    # ------------------------------------------------------------------
    # S9: the Link's name and environment fields are signed but never
    # compared with the layout. Only the *filename* determines which step
    # a Link is loaded for.
    # ------------------------------------------------------------------
    s9 = OUT / "s9_unchecked_fields"
    shutil.rmtree(s9, ignore_errors=True)
    s9.mkdir(parents=True)
    layout9_metadata = signed_layout(layout, owner["signer"])
    layout9_metadata.dump(str(s9 / "root.layout"))
    mismatched_fields = Link(
        name="some-other-step",
        command=["make", "release"],
        materials={"src.c": artifact(src)},
        products={"app": artifact(binary)},
        byproducts={"return-value": 0},
        environment={"workdir": "somewhere-else"},
    )
    write_link(
        s9,
        signed_link(mismatched_fields, functionary["signer"]),
        "compile",
        functionary["keyid"],
    )
    s9_result = attempt(layout9_metadata, owner["pub"], s9)
    scenario["s9_signed_unchecked_fields"] = {
        "link_name": mismatched_fields.name,
        "step_name": "compile",
        "link_environment": mismatched_fields.environment,
        "passed": s9_result["passed"],
        "exception": s9_result["exception"],
    }

    # ------------------------------------------------------------------
    # S10: a Layout signed by the owner but by an unauthorized functionary
    # is rejected at the layout-signature boundary.
    # ------------------------------------------------------------------
    s10 = OUT / "s10_bad_layout_sig"
    shutil.rmtree(s10, ignore_errors=True)
    s10.mkdir(parents=True)
    wrong_owner = signed_layout(layout, peer["signer"])
    wrong_owner.dump(str(s10 / "root.layout"))
    write_link(
        s10,
        signed_link(
            Link(
                name="compile",
                command=["make", "release"],
                materials={"src.c": artifact(src)},
                products={"app": artifact(binary)},
                byproducts={"return-value": 0},
                environment={},
            ),
            functionary["signer"],
        ),
        "compile",
        functionary["keyid"],
    )
    s10_result = attempt(wrong_owner, owner["pub"], s10)
    scenario["s10_layout_signed_by_wrong_key"] = {
        "passed": s10_result["passed"],
        "exception": s10_result["exception"],
    }

    scenario["_keys"] = {
        name: {"keyid": k["keyid"], "keytype": k["pub"]["keytype"]}
        for name, k in keys.items()
    }
    dump("scenario.json", scenario)

    print(json.dumps(scenario, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
