import unittest
from policy_sentry.writing.validate import check_actions_schema, check_crud_schema, check_handover_schema

valid_cfg_for_crud = {
    "mode": "crud",
    "name": "RoleNameWithCRUD",
    "read": [
        "arn:aws:s3:::example-org-sbx-vmimport",
    ],
    "write": [
        "arn:aws:s3:::example-org-s3-access-logs",
    ],
    "list": [
        "arn:aws:s3:::example-org-flow-logs",
        "arn:aws:s3:::example-org-sbx-vmimport/stuff",
    ],
    "tagging": ["arn:aws:ssm:us-east-1:123456789012:parameter/test"],
    "permissions-management": ["arn:aws:s3:::example-org-s3-access-logs"],
    "wildcard-only": {"service-read": ["s3"]},
}

valid_cfg_for_actions = {
    "mode": "actions",
    "name": "RoleNameWithActions",
    "actions": [
        "kms:CreateGrant",
        "kms:CreateCustomKeyStore",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:AuthorizeSecurityGroupIngress",
    ],
}

valid_crud_with_one_item_only = {
    "mode": "crud",
    "name": "RoleNameWithCRUD",
    "read": [
        "arn:aws:s3:::example-org-sbx-vmimport",
    ],
}

invalid_crud_with_mispelled_category = {
    "mode": "crud",
    "name": "RoleNameWithCRUD",
    "reed": [
        "arn:aws:s3:::example-org-sbx-vmimport",
    ],
    "right": [
        "arn:aws:s3:::example-org-sbx-vmimport",
    ],
    "wrist": [
        "arn:aws:s3:::example-org-sbx-vmimport",
    ],
}

valid_crud_with_sts_actions = {
    "mode": "crud",
    "name": "RoleNameWithCRUD",
    "sts": {
        "assume-role": [
            "arn:aws:iam::123456789012:role/demo",
        ]
    },
}

invalid_crud_with_invalid_sts_action = {
    "mode": "crud",
    "name": "RoleNameWithCRUD",
    "sts": {
        "assume-role-fake-something": [
            "arn:aws:iam::123456789012:role/demo",
        ]
    },
}


class YMLSchemaTestCase(unittest.TestCase):
    def test_actions_schema(self):
        """test_actions_schema: Validates that the user-supplied YAML is working for CRUD mode"""
        result = check_actions_schema(valid_cfg_for_actions)
        self.assertTrue(result)

    def test_crud_schema(self):
        """test_actions_schema: Validates that the user-supplied YAML is working for CRUD mode"""
        result = check_crud_schema(valid_cfg_for_crud)
        self.assertTrue(result)
        self.assertTrue(check_crud_schema(valid_crud_with_one_item_only))
        self.assertTrue(check_crud_schema(valid_crud_with_sts_actions))
        with self.assertRaises(Exception):
            check_crud_schema(invalid_crud_with_mispelled_category)
        with self.assertRaises(Exception):
            check_crud_schema(invalid_crud_with_invalid_sts_action)


valid_cfg_for_handover = {
    "mode": "crud",
    "name": "RoleWithHandover",
    "read": ["arn:aws:s3:::shared-policies/team/*"],
    "handover": {
        "approval": {
            "project": "project-alpha",
            "start": "2026-12-01T00:00:00Z",
            "end": "2026-12-02T00:00:00Z",
        },
        "projects": [
            {
                "name": "project-alpha",
                "description": "Temporary operator",
                "access": {"read": ["arn:aws:s3:::project-alpha/artifacts/*"]},
            }
        ],
    },
}

invalid_cfg_for_handover_without_project_name = {
    "mode": "crud",
    "handover": {
        "approval": {"project": "project-alpha", "start": "2026-12-01T00:00:00Z", "end": "2026-12-02T00:00:00Z"},
        "projects": [{"access": {"read": ["arn:aws:s3:::project-alpha/artifacts/*"]}}],
    },
}

invalid_cfg_for_handover_without_projects = {
    "mode": "crud",
    "handover": {
        "approval": {"project": "project-alpha", "start": "2026-12-01T00:00:00Z", "end": "2026-12-02T00:00:00Z"},
    },
}


class HandoverSchemaTestCase(unittest.TestCase):
    def test_handover_schema(self):
        self.assertTrue(check_handover_schema(valid_cfg_for_handover))
        self.assertTrue(check_crud_schema(valid_cfg_for_handover))
        with self.assertRaises(Exception):
            check_handover_schema(invalid_cfg_for_handover_without_project_name)
        with self.assertRaises(Exception):
            check_handover_schema(invalid_cfg_for_handover_without_projects)

    def test_plain_crud_template_has_no_handover(self):
        from policy_sentry.writing.template import create_crud_template

        self.assertNotIn("handover:", create_crud_template())

    def test_handover_template_includes_crud_and_handover(self):
        from policy_sentry.writing.template import create_crud_template

        template = create_crud_template(with_handover=True)
        self.assertIn("mode: crud", template)
        self.assertIn("handover:", template)
        self.assertIn("approval:", template)
