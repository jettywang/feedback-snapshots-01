#!/usr/bin/env python3
"""Offline diagnosis for 'unable to confirm' IAM-policy findings.

This drives the validator's real reference-resolution call chain without any
AWS network or Access Analyzer call:

    cfn_loader.load
      -> NodeEvaluator.eval / CfnObject.eval(roles_schema)
         -> RefEvaluator / GetAttEvaluator / SubEvaluator
            -> cycle_detection.validate_no_cycle   (reference ring)
            -> parameter / resource lookup branch  (insufficient data)

Every outcome is one of:
    CONFIRMED            the role's policies resolved to concrete JSON (evidence)
    UNCONFIRMED_CYCLE    validate_no_cycle raised "Cycle detected ..."
    UNCONFIRMED_NO_DATA a lookup could not be satisfied (missing param/resource, ...)
    UNCONFIRMED_OTHER    any other ApplicationError (kept distinct, never a pass)

Neither unconfirmed state is ever reported as a safe pass. CONFIRMED roles are
emitted as recoverable evidence regardless of failures elsewhere in the template.
"""
import argparse
import io
import json
import os

# Keep boto3 from reaching the EC2 IMDS / STS when the package is imported.
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "offline-diag")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "offline-diag")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-2")

from cfn_policy_validator.cfn_tools import cfn_loader
from cfn_policy_validator.parsers.account_config import AccountConfig
from cfn_policy_validator.parsers.identity_schemas import roles_schema
from cfn_policy_validator.application_error import ApplicationError

# Import the cycle module first and patch it before any evaluator module loads,
# because RefEvaluator / GetAttEvaluator bind validate_no_cycle at import time
# (`from ...cycle_detection import validate_no_cycle`).
from cfn_policy_validator.parsers.utils import cycle_detection
from cfn_policy_validator.parsers.utils.intrinsic_functions import ref_evaluator, fn_get_att_evaluator

ACCOUNT_CONFIG = AccountConfig("aws", "us-east-2", "111222333444")

# Error-message signatures taken verbatim from the validator source so the
# classification tracks the real call chain rather than a heuristic guess.
CYCLE_PREFIX = "Cycle detected for "
NO_DATA_SIGNATURES = (
    "No value passed for referenced parameter:",
    "Unable to find a referenced resource or parameter in template:",
    "Unable to find referenced resource for GetAtt reference to",
    "Fn::FindInMap lookup failed.",
)


def install_cycle_recorder():
    """Wrap validate_no_cycle to capture the exact (resource, property) ring.

    The recorded path is the ordered VisitedNode list at the moment the node is
    re-entered, so the ring can be re-walked during review. The wrapper is
    installed at every binding site because the evaluators import the function
    by name at module load time.
    """
    original = cycle_detection.validate_no_cycle
    seen = []

    def recorder(resource_name, resource_property, visited_nodes):
        chain = [(n.resource_name, n.property_name) for n in visited_nodes]
        chain.append((resource_name, resource_property))
        seen.append(chain)
        return original(resource_name, resource_property, visited_nodes)

    cycle_detection.validate_no_cycle = recorder
    ref_evaluator.validate_no_cycle = recorder
    fn_get_att_evaluator.validate_no_cycle = recorder
    return seen, original


def restore_cycle_recorder(original):
    cycle_detection.validate_no_cycle = original
    ref_evaluator.validate_no_cycle = original
    fn_get_att_evaluator.validate_no_cycle = original


def classify(message):
    if message.startswith(CYCLE_PREFIX):
        return "UNCONFIRMED_CYCLE"
    if any(sig in message for sig in NO_DATA_SIGNATURES):
        return "UNCONFIRMED_NO_DATA"
    return "UNCONFIRMED_OTHER"


def diagnose(template_path, parameters):
    with open(template_path, "r") as stream:
        template = cfn_loader.load(stream, ACCOUNT_CONFIG, parameters, False)

    ring_log, original = install_cycle_recorder()
    results = []
    try:
        for logical_name, resource in template.get("Resources", {}).items():
            if resource.get("Type") != "AWS::IAM::Role":
                continue
            try:
                evaluated = resource.eval(roles_schema)
                results.append({
                    "role": logical_name,
                    "status": "CONFIRMED",
                    "evidence": evaluated["Properties"].get("Policies", []),
                })
            except ApplicationError as exc:
                message = str(exc)
                entry = {
                    "role": logical_name,
                    "status": classify(message),
                    "error": message,
                }
                if entry["status"] == "UNCONFIRMED_CYCLE" and ring_log:
                    entry["cycle_path"] = ring_log[-1]
                results.append(entry)
    finally:
        restore_cycle_recorder(original)

    summary = {
        "template": os.path.basename(template_path),
        "parameters_supplied": sorted(parameters.keys()),
        "roles_confirmed": [r["role"] for r in results if r["status"] == "CONFIRMED"],
        "roles_unconfirmed_cycle": [r["role"] for r in results if r["status"] == "UNCONFIRMED_CYCLE"],
        "roles_unconfirmed_no_data": [r["role"] for r in results if r["status"] == "UNCONFIRMED_NO_DATA"],
        "roles_unconfirmed_other": [r["role"] for r in results if r["status"] == "UNCONFIRMED_OTHER"],
        "safe_passes": 0,
        "roles": results,
    }
    return summary


def main():
    parser = argparse.ArgumentParser(description="Offline reference-resolution diagnosis.")
    parser.add_argument("--template-path", required=True)
    parser.add_argument("--parameters", nargs="*", default=[], metavar="KEY=VALUE",
                        help="CloudFormation parameter values, e.g. BucketScope=audit-logs")
    args = parser.parse_args()

    parameters = {}
    for pair in args.parameters:
        key, _, value = pair.partition("=")
        parameters[key] = value

    print(json.dumps(diagnose(args.template_path, parameters), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
