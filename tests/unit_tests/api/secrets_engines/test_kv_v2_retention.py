import pytest

from hvac import exceptions
from hvac.api.secrets_engines.kv_v2 import KvV2
from hvac.api.secrets_engines.kv_v2_retention import (
    KvV2RetentionAuditor,
    MetadataAccessStatus,
    RetentionPolicy,
    UnverifiableReason,
    VersionStatus,
    audit_kv_v2_retention,
)


def version_metadata(destroyed=False, deletion_time="", **extra):
    metadata = {
        "created_time": "2026-11-01T00:00:00.000000Z",
        "deletion_time": deletion_time,
        "destroyed": destroyed,
    }
    metadata.update(extra)
    return metadata


class FakeKvV2:
    def __init__(self, responses=None, list_responses=None):
        self.responses = responses or {}
        self.list_responses = list_responses or {}
        self.calls = []
        self.read_secret = self._forbidden_data_method
        self.read_secret_version = self._forbidden_data_method

    def read_secret_metadata(self, path, mount_point):
        self.calls.append(("read_secret_metadata", path, mount_point))
        response = self.responses[path]
        if isinstance(response, Exception):
            raise response
        return response

    def list_secrets(self, path, mount_point):
        self.calls.append(("list_secrets", path, mount_point))
        response = self.list_responses[path]
        if isinstance(response, Exception):
            raise response
        return response

    def _forbidden_data_method(self, *args, **kwargs):
        raise AssertionError("secret data methods must never be called")


class FakeClient:
    def __init__(self, kv_v2):
        class Kv:
            v2 = kv_v2

        class Secrets:
            kv = Kv()

        self.secrets = Secrets()


def metadata_response(versions, **data):
    response_data = {
        "versions": versions,
        "max_versions": data.pop("max_versions", 10),
    }
    response_data.update(data)
    return {"data": response_data}


def test_inventory_distinguishes_access_soft_deleted_and_destroyed():
    kv = FakeKvV2(
        responses={
            "app/config": metadata_response(
                {
                    "1": version_metadata(destroyed=True),
                    "2": version_metadata(deletion_time="2026-11-02T00:00:00Z"),
                    "3": version_metadata(),
                }
            )
        }
    )

    report = KvV2RetentionAuditor(FakeClient(kv)).audit(["app/config"])

    assert report.inventory == {"app/config": (2, 3)}
    assert report.accessible == {"app/config": (3,)}
    statuses = {record.version: record.status for record in report.paths[0].versions}
    assert statuses == {
        1: VersionStatus.DESTROYED,
        2: VersionStatus.SOFT_DELETED,
        3: VersionStatus.ACCESSIBLE,
    }


def test_explicit_retention_policy_limits_to_latest_versions():
    kv = FakeKvV2(
        responses={
            "app/config": metadata_response(
                {
                    "1": version_metadata(),
                    "2": version_metadata(),
                    "3": version_metadata(destroyed=True),
                    "4": version_metadata(),
                    "5": version_metadata(),
                },
                max_versions=10,
            )
        }
    )

    report = KvV2RetentionAuditor(
        FakeClient(kv), policy=RetentionPolicy(max_versions=3)
    ).audit(["app/config"])

    assert report.paths[0].effective_max_versions == 3
    assert report.inventory == {"app/config": (4, 5)}
    assert report.unverifiable == ()


def test_metadata_max_versions_is_used_when_no_explicit_policy():
    kv = FakeKvV2(
        responses={
            "app/config": metadata_response(
                {
                    "1": version_metadata(),
                    "2": version_metadata(),
                    "3": version_metadata(),
                },
                max_versions=2,
            )
        }
    )

    report = KvV2RetentionAuditor(FakeClient(kv)).audit(["app/config"])

    assert report.paths[0].effective_max_versions == 2
    assert report.inventory == {"app/config": (2, 3)}


def test_soft_deleted_versions_can_be_excluded_from_inventory():
    kv = FakeKvV2(
        responses={
            "app/config": metadata_response(
                {
                    "1": version_metadata(),
                    "2": version_metadata(deletion_time="2026-11-02T00:00:00Z"),
                }
            )
        }
    )

    report = KvV2RetentionAuditor(
        FakeClient(kv), policy=RetentionPolicy(include_soft_deleted=False)
    ).audit(["app/config"])

    assert report.inventory == {"app/config": (1,)}
    assert report.paths[0].versions[1].status is VersionStatus.SOFT_DELETED


@pytest.mark.parametrize(
    ("exception", "status"),
    [
        (exceptions.Forbidden("denied"), MetadataAccessStatus.FORBIDDEN),
        (exceptions.Unauthorized("bad token"), MetadataAccessStatus.UNAUTHORIZED),
        (exceptions.InvalidPath("gone"), MetadataAccessStatus.NOT_FOUND),
        (exceptions.InvalidRequest("bad"), MetadataAccessStatus.INVALID_REQUEST),
        (exceptions.InternalServerError("boom"), MetadataAccessStatus.VAULT_ERROR),
        (RuntimeError("boom"), MetadataAccessStatus.UNEXPECTED_ERROR),
    ],
)
def test_path_access_failures_have_distinct_statuses(exception, status):
    kv = FakeKvV2(responses={"app/config": exception})

    report = KvV2RetentionAuditor(FakeClient(kv)).audit(["app/config"])

    result = report.paths[0]
    assert result.access_status is status
    assert result.retained_versions == ()
    assert result.accessible_versions == ()
    assert report.inventory == {}
    assert report.unverifiable == (
        {
            "path": "app/config",
            "status": status.value,
            "error_type": type(exception).__name__,
        },
    )


def test_permission_failure_does_not_stop_other_paths():
    kv = FakeKvV2(
        responses={
            "app/denied": exceptions.Forbidden("denied", method="GET", url="/metadata"),
            "app/open": metadata_response({"1": version_metadata()}),
        }
    )

    report = KvV2RetentionAuditor(FakeClient(kv)).audit(["app/denied", "app/open"])

    assert report.inventory == {"app/open": (1,)}
    assert report.unverifiable[0]["status"] == "forbidden"


@pytest.mark.parametrize(
    ("versions", "reason"),
    [
        ({"1": "not-a-mapping"}, UnverifiableReason.INVALID_VERSION_METADATA),
        ({"1": {"deletion_time": ""}}, UnverifiableReason.MISSING_DESTROYED),
        (
            {"1": {"destroyed": "false", "deletion_time": ""}},
            UnverifiableReason.INVALID_DESTROYED,
        ),
        ({"1": {"destroyed": False}}, UnverifiableReason.MISSING_DELETION_TIME),
        (
            {"1": {"destroyed": False, "deletion_time": 123}},
            UnverifiableReason.INVALID_DELETION_TIME,
        ),
    ],
)
def test_unverifiable_version_entries_have_distinct_reasons(versions, reason):
    kv = FakeKvV2(responses={"app/config": metadata_response(versions)})

    report = KvV2RetentionAuditor(FakeClient(kv)).audit(["app/config"])

    result = report.paths[0]
    assert result.access_status is MetadataAccessStatus.OK
    assert result.versions[0].status is VersionStatus.UNVERIFIABLE
    assert result.versions[0].reason is reason
    assert result.retained_versions == ()
    assert report.unverifiable == (
        {
            "path": "app/config",
            "version": 1,
            "status": "unverifiable",
            "reason": reason.value,
        },
    )


@pytest.mark.parametrize(
    "response",
    [
        None,
        {},
        {"data": None},
        {"data": {}},
        {"data": {"versions": []}},
        {"data": {"versions": {"one": version_metadata()}}},
    ],
)
def test_malformed_metadata_is_reported_separately(response):
    kv = FakeKvV2(responses={"app/config": response})

    report = KvV2RetentionAuditor(FakeClient(kv)).audit(["app/config"])

    assert report.paths[0].access_status is MetadataAccessStatus.MALFORMED_METADATA
    assert report.inventory == {}
    assert report.unverifiable[0]["status"] == "malformed_metadata"


def test_call_log_contains_only_metadata_operations_and_preserves_mount_point():
    kv = FakeKvV2(
        responses={"app/config": metadata_response({"1": version_metadata()})}
    )

    KvV2RetentionAuditor(FakeClient(kv), mount_point="team-kv").audit(["app/config"])

    assert kv.calls == [("read_secret_metadata", "app/config", "team-kv")]


def test_default_mount_point_matches_kv_v2_default():
    kv = FakeKvV2(
        responses={"app/config": metadata_response({"1": version_metadata()})}
    )

    KvV2RetentionAuditor(FakeClient(kv)).audit(["app/config"])

    assert kv.calls == [("read_secret_metadata", "app/config", "secret")]


def test_real_kv_v2_uses_metadata_endpoint_and_mount_point():
    class RecordingAdapter:
        def __init__(self):
            self.requests = []

        def get(self, url, params=None):
            self.requests.append((url, params))
            return metadata_response({"1": version_metadata()})

    adapter = RecordingAdapter()

    class Client:
        secrets = type(
            "Secrets",
            (),
            {"kv": type("Kv", (), {"v2": KvV2(adapter=adapter)})()},
        )()

    KvV2RetentionAuditor(Client(), mount_point="team-kv").audit(["app/config"])

    assert adapter.requests == [("/v1/team-kv/metadata/app/config", None)]


def test_unapproved_custom_metadata_is_not_serialized():
    kv = FakeKvV2(
        responses={
            "app/config": metadata_response(
                {"1": version_metadata()},
                custom_metadata={"owner": "payments", "ssn": "do-not-report"},
            )
        }
    )

    report = KvV2RetentionAuditor(FakeClient(kv)).audit(["app/config"])

    assert report.paths[0].labels == {}
    assert report.to_dict()["paths"][0]["labels"] == {}
    assert "custom_metadata" not in report.to_dict()
    assert "do-not-report" not in repr(report.to_dict())


def test_only_approved_custom_metadata_labels_are_reported():
    kv = FakeKvV2(
        responses={
            "app/config": metadata_response(
                {"1": version_metadata()},
                custom_metadata={"owner": "payments", "ssn": "do-not-report"},
            )
        }
    )

    report = KvV2RetentionAuditor(
        FakeClient(kv), approved_custom_metadata_keys=["owner"]
    ).audit(["app/config"])

    assert report.paths[0].labels == {"owner": "payments"}
    assert report.to_dict()["paths"][0]["labels"] == {"owner": "payments"}
    assert "ssn" not in repr(report.to_dict())


def test_audit_mount_discovers_with_metadata_list_only():
    kv = FakeKvV2(
        responses={
            "apps/one": metadata_response({"1": version_metadata()}),
            "apps/two": metadata_response(
                {"2": version_metadata(), "3": version_metadata(destroyed=True)}
            ),
        },
        list_responses={
            "": {"data": {"keys": ["apps/"]}},
            "apps": {"data": {"keys": ["one", "two"]}},
        },
    )

    report = KvV2RetentionAuditor(FakeClient(kv), mount_point="kv").audit_mount()

    assert report.inventory == {"apps/one": (1,), "apps/two": (2,)}
    assert kv.calls == [
        ("list_secrets", "", "kv"),
        ("list_secrets", "apps", "kv"),
        ("read_secret_metadata", "apps/one", "kv"),
        ("read_secret_metadata", "apps/two", "kv"),
    ]
    assert all(call[0] in {"read_secret_metadata", "list_secrets"} for call in kv.calls)


@pytest.mark.parametrize(
    ("exception", "status"),
    [
        (exceptions.Forbidden("denied"), MetadataAccessStatus.LIST_FORBIDDEN),
        (exceptions.Unauthorized("bad token"), MetadataAccessStatus.LIST_UNAUTHORIZED),
        (exceptions.InvalidPath("gone"), MetadataAccessStatus.LIST_NOT_FOUND),
        (exceptions.InvalidRequest("bad"), MetadataAccessStatus.LIST_INVALID_REQUEST),
        (exceptions.InternalServerError("boom"), MetadataAccessStatus.LIST_VAULT_ERROR),
        (RuntimeError("boom"), MetadataAccessStatus.LIST_UNEXPECTED_ERROR),
    ],
)
def test_list_failures_have_distinct_discovery_statuses(exception, status):
    kv = FakeKvV2(list_responses={"": exception})

    report = KvV2RetentionAuditor(FakeClient(kv)).audit_mount()

    assert report.paths[0].access_status is status
    assert report.inventory == {}
    assert report.unverifiable[0]["status"] == status.value


def test_list_response_without_keys_is_reported_as_malformed():
    kv = FakeKvV2(list_responses={"": {"data": {}}})

    report = KvV2RetentionAuditor(FakeClient(kv)).audit_mount()

    assert report.paths[0].access_status is MetadataAccessStatus.LIST_MALFORMED_METADATA
    assert report.unverifiable[0]["status"] == "list_malformed_metadata"


def test_wrapper_uses_same_metadata_only_path():
    kv = FakeKvV2(
        responses={"app/config": metadata_response({"1": version_metadata()})}
    )

    report = audit_kv_v2_retention(
        FakeClient(kv), paths=["app/config"], mount_point="team-kv"
    )

    assert report.inventory == {"app/config": (1,)}
    assert kv.calls == [("read_secret_metadata", "app/config", "team-kv")]


def test_invalid_arguments_are_rejected_before_requests():
    kv = FakeKvV2()
    auditor = KvV2RetentionAuditor(FakeClient(kv))

    with pytest.raises(ValueError):
        auditor.audit([""])
    with pytest.raises(ValueError):
        RetentionPolicy(max_versions=0)
    with pytest.raises(ValueError):
        KvV2RetentionAuditor(FakeClient(kv), mount_point="")
    with pytest.raises(ValueError):
        KvV2RetentionAuditor(FakeClient(kv), approved_custom_metadata_keys=[""])
    assert kv.calls == []
