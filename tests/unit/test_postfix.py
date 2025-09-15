# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Postfix service unit tests."""

from unittest.mock import patch
from typing import TYPE_CHECKING

import pytest


from reactive import utils, postfix, state

if TYPE_CHECKING:
    from pathlib import Path


@patch("subprocess.call")
@patch("reactive.postfix.os.utime")
@patch("reactive.postfix.utils.write_file")
class TestCreateUpdateMap:

    def test_pmfname_file_not_exists(self, write_file, os_utime, _call, tmp_path: "Path") -> None:
        """
        arrange: path to non-existing pmfname file.
        act: call _create_update_map.
        assert:
            - file created
            - write_file called
            - return change
        """
        # Arrange
        write_file.return_value = True
        non_existing_file_path = tmp_path / "pmfname"
        postmap = f"hash:{non_existing_file_path}"

        # Act
        result = postfix._create_update_map("contents", postmap)

        # Assert
        os_utime.assert_called_once_with(str(non_existing_file_path), None)
        write_file.assert_called_once_with(
            utils.JUJU_HEADER + "contents\n",
            str(non_existing_file_path),
        )
        assert result is True

    def test_pmfname_file_exists_no_change(
        self, write_file, os_utime, _call, tmp_path: "Path"
    ) -> None:
        """
        arrange: path to existing pmfname file having same content to be written.
        act: call _create_update_map.
        assert:
            - no file creation
            - write_file called
            - return no change
        """
        # Arrange
        write_file.return_value = False
        exising_file_path = tmp_path / "pmfname"
        exising_file_path.write_text("stuff")
        postmap = f"hash:{exising_file_path}"

        # Act
        result = postfix._create_update_map("contents", postmap)

        # Assert
        os_utime.assert_not_called()
        write_file.assert_called_once_with(
            utils.JUJU_HEADER + "contents\n",
            str(exising_file_path),
        )
        assert result is False

    def test_pmfname_file_exists_change_hash_type(
        self, write_file, os_utime, call, tmp_path: "Path"
    ) -> None:
        """
        arrange: path to existing pmfname and pmap_name is hash.
        act: call _create_update_map.
        assert:
            - no file creation
            - write_file called
            - postmap command called
            - return change.
        """
        # Arrange
        write_file.return_value = True
        exising_file_path = tmp_path / "pmfname"
        exising_file_path.write_text("stuff")
        postmap = f"hash:{exising_file_path}"

        # Act
        result = postfix._create_update_map("contents", postmap)

        # Assert
        os_utime.assert_not_called()
        write_file.assert_called_once_with(
            utils.JUJU_HEADER + "contents\n",
            str(exising_file_path),
        )
        call.asset_called_once_with(["postmap", postmap])
        assert result is True

    def test_pmfname_file_exists_change_not_hash_type(
        self, write_file, os_utime, call, tmp_path: "Path"
    ) -> None:
        """
        arrange: path to existing pmfname and pmap_name is not shash.
        act: call _create_update_map.
        assert:
            - no file creation
            - call write_file
            - postmap command not called
            - return change.
        """
        # Arrange
        write_file.return_value = True
        exising_file_path = tmp_path / "pmfname"
        exising_file_path.write_text("stuff")
        postmap = f"cidr:{exising_file_path}"

        # Act
        result = postfix._create_update_map("contents", postmap)

        # Assert
        os_utime.assert_not_called()
        write_file.assert_called_once_with(
            utils.JUJU_HEADER + "contents\n",
            str(exising_file_path),
        )
        call.assert_not_called()
        assert result is True


class TestWithState:

    @pytest.fixture(autouse=True)
    def setup_method(self) -> None:
        charm_config = {
            "append_x_envelope_to": False,
            "connection_limit": 100,
            "domain": "",
            "enable_rate_limits": False,
            "enable_reject_unknown_sender_domain": True,
            "enable_spf": False,
            "enable_smtp_auth": True,
            "tls_ciphers": "HIGH",
            "tls_exclude_ciphers": """
                - aNULL
                - eNULL
                - DES
                - 3DES
                - MD5
                - RC4
                - CAMELLIA
            """,
            "tls_protocols": """
                - '!SSLv2'
                - '!SSLv3'
            """,
            "tls_security_level": "may",
            "virtual_alias_maps_type": "hash",
        }
        self.charm_state = state.State.from_charm(config=charm_config)


class TestSMTPDRelayRestrictions(TestWithState):

    @pytest.mark.parametrize(
        (
            "relay_access_sources",
            "enable_smtp_auth",
            "sender_login_maps",
            "restrict_senders",
            "expected",
        ),
        [
            pytest.param(
                [],
                False,
                {},
                {},
                ["permit_mynetworks", "defer_unauth_destination"],
                id="no_access_sources_no_auth",
            ),
            pytest.param(
                ["source1, source2"],
                False,
                {},
                {},
                [
                    "permit_mynetworks",
                    "check_client_access cidr:/etc/postfix/relay_access",
                    "defer_unauth_destination",
                ],
                id="has_access_sources_no_auth",
            ),
            pytest.param(
                ["source1, source2"],
                True,
                {},
                {},
                [
                    "permit_mynetworks",
                    "check_client_access cidr:/etc/postfix/relay_access",
                    "permit_sasl_authenticated",
                    "defer_unauth_destination",
                ],
                id="has_auth",
            ),
            pytest.param(
                [],
                True,
                {"group@example.com": "group"},
                {},
                [
                    "permit_mynetworks",
                    "reject_known_sender_login_mismatch",
                    "permit_sasl_authenticated",
                    "defer_unauth_destination",
                ],
                id="has_auth_and_sender_login_maps",
            ),
            pytest.param(
                [],
                True,
                {},
                {"sender": state.AccessMapValue.OK},
                [
                    "permit_mynetworks",
                    "reject_sender_login_mismatch",
                    "permit_sasl_authenticated",
                    "defer_unauth_destination",
                ],
                id="has_auth_and_restrict_senders",
            ),
            pytest.param(
                [],
                True,
                {"group@example.com": "group"},
                {"sender": state.AccessMapValue.OK},
                [
                    "permit_mynetworks",
                    "reject_known_sender_login_mismatch",
                    "reject_sender_login_mismatch",
                    "permit_sasl_authenticated",
                    "defer_unauth_destination",
                ],
                id="has_auth_and_sender_login_maps_and_restrict_senders",
            ),
        ],
    )
    def test_items_and_order(
        self,
        relay_access_sources: list[str],
        enable_smtp_auth: bool,
        sender_login_maps: dict[str, str],
        restrict_senders: dict[str, state.AccessMapValue],
        expected: list[str],
    ) -> None:
        """
        arrange: create charm_state with enable_smpt_auth and sender_login_maps.
        act: call _smtpd_relay_restrictions with the charm_state.
        assert: has expected restrictions in correct order.
        """
        # Arrange
        self.charm_state.relay_access_sources = relay_access_sources
        self.charm_state.enable_smtp_auth = enable_smtp_auth
        self.charm_state.sender_login_maps = sender_login_maps
        self.charm_state.restrict_senders = restrict_senders

        # Act
        result = postfix._smtpd_relay_restrictions(self.charm_state)

        # Assert
        assert result == expected
