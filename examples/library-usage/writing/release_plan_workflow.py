#!/usr/bin/env python
"""
Plan a safe, multi-batch rollout for an oversized approved IAM policy.

The script demonstrates the three questions an operator has to answer:

1. Which document gets installed first?  (the one carrying every explicit Deny)
2. If a batch fails, which documents are detached?  (the failed one, then reverse order)
3. What are the effective permissions at every prefix, and after full installation?

Everything is replayed in memory; no AWS calls are made.
"""

import json

from policy_sentry.writing.batching import BatchLimits, build_release_plan, explain_rollback
from policy_sentry.writing.rule_engine import AccessRequest, effective_permissions

APPROVED_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenySecretExportOutsideRegion",
            "Effect": "Deny",
            "Action": ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"],
            "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/*",
            "Condition": {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}},
        },
        {
            "Sid": "S3ReadWrite",
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
            "Resource": [
                "arn:aws:s3:::example-org-audit-logs",
                "arn:aws:s3:::example-org-audit-logs/*",
                "arn:aws:s3:::example-org-data",
                "arn:aws:s3:::example-org-data/*",
            ],
        },
        {
            "Sid": "KmsDecrypt",
            "Effect": "Allow",
            "Action": ["kms:Decrypt", "kms:DescribeKey"],
            "Resource": "arn:aws:kms:us-east-1:123456789012:key/abcd1234",
        },
    ],
}

PROBES = [
    AccessRequest("s3:GetObject", "arn:aws:s3:::example-org-data/report.csv"),
    AccessRequest("s3:PutObject", "arn:aws:s3:::example-org-data/report.csv"),
    AccessRequest("s3:DeleteObject", "arn:aws:s3:::example-org-audit-logs/old.log"),
    AccessRequest("kms:Decrypt", "arn:aws:kms:us-east-1:123456789012:key/abcd1234"),
    AccessRequest(
        "secretsmanager:GetSecretValue",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/app",
        {"aws:RequestedRegion": "eu-west-1"},
    ),
    AccessRequest(
        "secretsmanager:GetSecretValue",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/app",
        {"aws:RequestedRegion": "us-east-1"},
    ),
    AccessRequest("iam:CreateUser", "*"),
]


def main() -> None:
    plan = build_release_plan(APPROVED_POLICY, BatchLimits(max_bytes=450))

    print("=== Install order ===")
    for entry in plan.to_manifest()["batches"]:
        effects = sorted({fragment["effect"] for fragment in entry["fragments"]})
        print(f"install {entry['install']} ({entry['bytes']} bytes; effects={effects})")

    print("\n=== Effective permissions after each prefix ===")
    installed = []
    source_decisions = effective_permissions([APPROVED_POLICY], PROBES)
    for sequence, document in enumerate(plan.documents(), start=1):
        installed.append(document)
        decisions = effective_permissions(installed, PROBES)
        print(f"after batch {sequence:02d}:")
        for probe in PROBES:
            marker = (probe.action, probe.resource)
            print(f"  {decisions[marker]:5} {marker[0]:32} {marker[1]}")
        widened = [
            (probe.action, probe.resource)
            for probe in PROBES
            if decisions[(probe.action, probe.resource)] == "Allow"
            and source_decisions[(probe.action, probe.resource)] != "Allow"
        ]
        assert not widened, f"prefix {sequence} widened the envelope: {widened}"

    print("\n=== Final equivalence check ===")
    final_decisions = effective_permissions(plan.documents(), PROBES)
    print("fully installed policy equals the approved policy:", final_decisions == source_decisions)

    print("\n=== Rollback if batch 02 fails to install ===")
    print(json.dumps(explain_rollback(plan, failed_batch=2), indent=2))


if __name__ == "__main__":
    main()
