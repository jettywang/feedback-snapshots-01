import random
from unittest.mock import MagicMock, call

import pytest

from hvac import exceptions
from hvac.api.secrets_engines.transit import DEFAULT_MOUNT_POINT, Transit

KEY_NAME = "retiring-key"
MOUNT_POINT = "payments-transit"


@pytest.fixture
def version_plan():
    """Generate a coherent set of key versions for a retirement rehearsal.

    Nothing here is hardcoded per-test: every assertion about request
    parameters is checked against these generated numbers.
    """
    rng = random.Random()
    retired_below = rng.randint(2, 100)
    grace_readable = retired_below - 1
    latest_version = retired_below + rng.randint(1, 50)
    return {
        "latest_version": latest_version,
        "new_min_encryption_version": retired_below,
        "grace_readable_version": grace_readable,
        "trim_min_version": retired_below,
    }


@pytest.fixture
def transit():
    adapter = MagicMock()
    return Transit(adapter=adapter), adapter


class TestTransitKeyVersionRetirement:
    def test_read_current_key_configuration(self, transit, version_plan):
        transit_client, adapter = transit
        adapter.get.return_value = {
            "data": {
                "latest_version": version_plan["latest_version"],
                "min_encryption_version": 0,
                "min_decryption_version": 1,
            }
        }

        response = transit_client.read_key(name=KEY_NAME, mount_point=MOUNT_POINT)

        adapter.get.assert_called_once_with(
            url=f"/v1/{MOUNT_POINT}/keys/{KEY_NAME}",
        )
        assert response["data"]["latest_version"] == version_plan["latest_version"]

    def test_raise_min_encryption_version_sends_exact_params(
        self, transit, version_plan
    ):
        transit_client, adapter = transit
        target = version_plan["new_min_encryption_version"]

        transit_client.update_key_configuration(
            name=KEY_NAME,
            min_encryption_version=target,
            mount_point=MOUNT_POINT,
        )

        adapter.post.assert_called_once_with(
            url=f"/v1/{MOUNT_POINT}/keys/{KEY_NAME}/config",
            json={"min_encryption_version": target},
        )

    def test_legacy_ciphertext_still_decryptable_during_grace_period(
        self, transit, version_plan
    ):
        """A raised min_encryption_version is a server-side write bound.

        The client must keep passing old-version ciphertext through to the
        decrypt endpoint untouched while min_decryption_version still allows
        it, instead of enforcing the new bound locally.
        """
        transit_client, adapter = transit
        old_version = version_plan["grace_readable_version"]
        assert old_version < version_plan["new_min_encryption_version"]
        legacy_ciphertext = f"vault:v{old_version}:generated-ciphertext"
        adapter.post.return_value = {"data": {"plaintext": "c3RpbGwtcmVhZGFibGU="}}

        response = transit_client.decrypt_data(
            name=KEY_NAME,
            ciphertext=legacy_ciphertext,
            mount_point=MOUNT_POINT,
        )

        adapter.post.assert_called_once_with(
            url=f"/v1/{MOUNT_POINT}/decrypt/{KEY_NAME}",
            json={"ciphertext": legacy_ciphertext},
        )
        assert response["data"]["plaintext"] == "c3RpbGwtcmVhZGFibGU="

    def test_server_rejection_of_retired_version_propagates(
        self, transit, version_plan
    ):
        transit_client, adapter = transit
        retired_ciphertext = "vault:v1:generated-ciphertext"
        adapter.post.side_effect = exceptions.InvalidRequest(
            "ciphertext version is disallowed by key config"
        )

        with pytest.raises(exceptions.InvalidRequest):
            transit_client.decrypt_data(
                name=KEY_NAME,
                ciphertext=retired_ciphertext,
                mount_point=MOUNT_POINT,
            )

    def test_server_rejection_of_config_update_propagates(
        self, transit, version_plan
    ):
        transit_client, adapter = transit
        adapter.post.side_effect = exceptions.InvalidRequest(
            "min_encryption_version cannot be greater than latest_version"
        )

        with pytest.raises(exceptions.InvalidRequest):
            transit_client.update_key_configuration(
                name=KEY_NAME,
                min_encryption_version=version_plan["latest_version"] + 1,
                mount_point=MOUNT_POINT,
            )

    def test_readback_inconsistency_is_not_masked(self, transit, version_plan):
        """If the server reports min_decryption_version lagging behind
        min_encryption_version (the new bound is not yet fully effective),
        the client must surface both values verbatim so callers can see the
        bound is not yet enforced, rather than reconciling them locally.
        """
        transit_client, adapter = transit
        lagging = version_plan["new_min_encryption_version"] - 1
        adapter.get.return_value = {
            "data": {
                "latest_version": version_plan["latest_version"],
                "min_encryption_version": version_plan["new_min_encryption_version"],
                "min_decryption_version": lagging,
            }
        }

        response = transit_client.read_key(name=KEY_NAME, mount_point=MOUNT_POINT)

        assert (
            response["data"]["min_encryption_version"]
            == version_plan["new_min_encryption_version"]
        )
        assert response["data"]["min_decryption_version"] == lagging
        assert (
            response["data"]["min_decryption_version"]
            < response["data"]["min_encryption_version"]
        )

    def test_trim_key_retires_old_versions(self, transit, version_plan):
        transit_client, adapter = transit
        trim_at = version_plan["trim_min_version"]

        transit_client.trim_key(
            name=KEY_NAME,
            min_version=trim_at,
            mount_point=MOUNT_POINT,
        )

        adapter.post.assert_called_once_with(
            url=f"/v1/{MOUNT_POINT}/keys/{KEY_NAME}/trim",
            json={"min_available_version": trim_at},
        )

    @pytest.mark.parametrize("use_zero_min_encryption", [False, True])
    def test_update_key_configuration_param_validation(
        self, transit, version_plan, use_zero_min_encryption
    ):
        transit_client, adapter = transit
        min_decryption = version_plan["new_min_encryption_version"]
        min_encryption = 0 if use_zero_min_encryption else min_decryption

        if use_zero_min_encryption:
            transit_client.update_key_configuration(
                name=KEY_NAME,
                min_decryption_version=min_decryption,
                min_encryption_version=min_encryption,
                mount_point=MOUNT_POINT,
            )
            adapter.post.assert_called_once_with(
                url=f"/v1/{MOUNT_POINT}/keys/{KEY_NAME}/config",
                json={
                    "min_decryption_version": min_decryption,
                    "min_encryption_version": 0,
                },
            )
        else:
            with pytest.raises(
                exceptions.ParamValidationError,
                match="min_encryption_version must be 0 or > min_decryption_version",
            ):
                transit_client.update_key_configuration(
                    name=KEY_NAME,
                    min_decryption_version=min_decryption,
                    min_encryption_version=min_encryption,
                    mount_point=MOUNT_POINT,
                )
            adapter.post.assert_not_called()

    def test_version_retirement_lifecycle(self, transit, version_plan):
        """Chain the full rehearsal: read config, raise the encryption floor,
        keep reading old ciphertext during the grace period, observe the
        not-yet-effective bound on read-back, then trim and verify.

        Every step asserts the exact request the client issued, proving the
        client layer never treats a not-yet-effective version bound as if it
        were already enforced.
        """
        transit_client, adapter = transit
        target = version_plan["new_min_encryption_version"]
        old_version = version_plan["grace_readable_version"]
        legacy_ciphertext = f"vault:v{old_version}:generated-ciphertext"

        adapter.get.side_effect = [
            # 1. current config: nothing enforced yet
            {
                "data": {
                    "latest_version": version_plan["latest_version"],
                    "min_encryption_version": 0,
                    "min_decryption_version": 1,
                }
            },
            # 4. read-back after the update: decryption floor still lagging
            {
                "data": {
                    "latest_version": version_plan["latest_version"],
                    "min_encryption_version": target,
                    "min_decryption_version": 1,
                }
            },
            # 6. final state after trim: bound effective, versions retired
            {
                "data": {
                    "latest_version": version_plan["latest_version"],
                    "min_encryption_version": target,
                    "min_decryption_version": target,
                    "min_available_version": target,
                }
            },
        ]
        adapter.post.side_effect = [
            MagicMock(status_code=204),  # 2. config update accepted
            {"data": {"plaintext": "Z3JhY2UtcGVyaW9k"}},  # 3. legacy decrypt ok
            {"data": {"min_available_version": target}},  # 5. trim accepted
        ]

        # 1. read current configuration
        before = transit_client.read_key(name=KEY_NAME, mount_point=MOUNT_POINT)
        assert before["data"]["min_encryption_version"] == 0

        # 2. raise the minimum encryption version
        transit_client.update_key_configuration(
            name=KEY_NAME,
            min_encryption_version=target,
            mount_point=MOUNT_POINT,
        )

        # 3. grace period: old-version ciphertext still decrypts
        grace = transit_client.decrypt_data(
            name=KEY_NAME,
            ciphertext=legacy_ciphertext,
            mount_point=MOUNT_POINT,
        )
        assert grace["data"]["plaintext"] == "Z3JhY2UtcGVyaW9k"

        # 4. read-back: bound visible but not yet effective for decryption
        during = transit_client.read_key(name=KEY_NAME, mount_point=MOUNT_POINT)
        assert during["data"]["min_encryption_version"] == target
        assert during["data"]["min_decryption_version"] < target

        # 5. retire the old versions for good
        trimmed = transit_client.trim_key(
            name=KEY_NAME,
            min_version=version_plan["trim_min_version"],
            mount_point=MOUNT_POINT,
        )
        assert trimmed["data"]["min_available_version"] == target

        # 6. final verification: the bound is now actually enforced
        after = transit_client.read_key(name=KEY_NAME, mount_point=MOUNT_POINT)
        assert after["data"]["min_decryption_version"] == target
        assert after["data"]["min_available_version"] == target

        assert adapter.get.call_args_list == [
            call(url=f"/v1/{MOUNT_POINT}/keys/{KEY_NAME}"),
            call(url=f"/v1/{MOUNT_POINT}/keys/{KEY_NAME}"),
            call(url=f"/v1/{MOUNT_POINT}/keys/{KEY_NAME}"),
        ]
        assert adapter.post.call_args_list == [
            call(
                url=f"/v1/{MOUNT_POINT}/keys/{KEY_NAME}/config",
                json={"min_encryption_version": target},
            ),
            call(
                url=f"/v1/{MOUNT_POINT}/decrypt/{KEY_NAME}",
                json={"ciphertext": legacy_ciphertext},
            ),
            call(
                url=f"/v1/{MOUNT_POINT}/keys/{KEY_NAME}/trim",
                json={"min_available_version": version_plan["trim_min_version"]},
            ),
        ]

    def test_default_mount_point_used_when_not_overridden(self, transit):
        transit_client, adapter = transit

        transit_client.read_key(name=KEY_NAME)

        adapter.get.assert_called_once_with(
            url=f"/v1/{DEFAULT_MOUNT_POINT}/keys/{KEY_NAME}",
        )
