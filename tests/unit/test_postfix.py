# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Postfix service unit tests."""

import ipaddress
from typing import TYPE_CHECKING
from unittest.mock import Mock, call, patch

import pytest

from reactive import postfix, state, utils

if TYPE_CHECKING:
    from pathlib import Path

    from pydantic import IPvAnyNetwork


@patch("reactive.postfix.subprocess.call")
@patch("reactive.postfix.os.utime")
@patch("reactive.postfix.utils.write_file")
class TestCreateUpdateMap:

    def test_pmfname_file_not_exists(
        self,
        mock_write_file: Mock,
        mock_os_utime: Mock,
        _mock_call: Mock,
        tmp_path: "Path",
    ) -> None:
        """
        arrange: path to non-existing pmfname file.
        act: call _create_update_map.
        assert:
            - file created
            - write_file called
            - return change
        """
        # Arrange
        mock_write_file.return_value = True
        non_existing_file_path = tmp_path / "pmfname"
        postmap = f"hash:{non_existing_file_path}"

        # Act
        result = postfix._create_update_map("contents", postmap)

        # Assert
        mock_os_utime.assert_called_once_with(str(non_existing_file_path), None)
        mock_write_file.assert_called_once_with(
            utils.JUJU_HEADER + "contents\n",
            str(non_existing_file_path),
        )
        assert result is True

    def test_pmfname_file_exists_no_change(
        self,
        mock_write_file: Mock,
        mock_os_utime: Mock,
        _mock_call: Mock,
        tmp_path: "Path",
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
        mock_write_file.return_value = False
        exising_file_path = tmp_path / "pmfname"
        exising_file_path.write_text("stuff")
        postmap = f"hash:{exising_file_path}"

        # Act
        result = postfix._create_update_map("contents", postmap)

        # Assert
        mock_os_utime.assert_not_called()
        mock_write_file.assert_called_once_with(
            utils.JUJU_HEADER + "contents\n",
            str(exising_file_path),
        )
        assert result is False

    def test_pmfname_file_exists_change_hash_type(
        self,
        mock_write_file: Mock,
        mock_os_utime: Mock,
        mock_call: Mock,
        tmp_path: "Path",
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
        mock_write_file.return_value = True
        exising_file_path = tmp_path / "pmfname"
        exising_file_path.write_text("stuff")
        postmap = f"hash:{exising_file_path}"

        # Act
        result = postfix._create_update_map("contents", postmap)

        # Assert
        mock_os_utime.assert_not_called()
        mock_write_file.assert_called_once_with(
            utils.JUJU_HEADER + "contents\n",
            str(exising_file_path),
        )
        mock_call.asset_called_once_with(["postmap", postmap])
        assert result is True

    def test_pmfname_file_exists_change_not_hash_type(
        self,
        mock_write_file: Mock,
        mock_os_utime: Mock,
        mock_call: Mock,
        tmp_path: "Path",
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
        mock_write_file.return_value = True
        exising_file_path = tmp_path / "pmfname"
        exising_file_path.write_text("stuff")
        postmap = f"cidr:{exising_file_path}"

        # Act
        result = postfix._create_update_map("contents", postmap)

        # Assert
        mock_os_utime.assert_not_called()
        mock_write_file.assert_called_once_with(
            utils.JUJU_HEADER + "contents\n",
            str(exising_file_path),
        )
        mock_call.assert_not_called()
        assert result is True


class TestSMTPDRelayRestrictions:

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
    def test_restrictions(
        self,
        relay_access_sources: list[str],
        enable_smtp_auth: bool,
        sender_login_maps: dict[str, str],
        restrict_senders: dict[str, state.AccessMapValue],
        expected: list[str],
    ) -> None:
        """
        arrange: Create charm_state with different relay restriction settings.
        act: Call _smtpd_restrictions with the charm_state.
        assert: The returned list of restrictions is correct and in order..
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


class TestSmtpdSenderRestrictions:

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

    @pytest.mark.parametrize(
        ("enable_reject_unknown_sender", "restrict_sender_access", "expected"),
        [
            pytest.param(
                False,
                [],
                ["check_sender_access hash:/etc/postfix/access"],
                id="neither_enabled",
            ),
            pytest.param(
                True,
                [],
                [
                    "reject_unknown_sender_domain",
                    "check_sender_access hash:/etc/postfix/access",
                ],
                id="reject_unknown_enabled",
            ),
            pytest.param(
                False,
                ["example.com"],
                ["check_sender_access hash:/etc/postfix/access", "reject"],
                id="restrict_access_enabled",
            ),
            pytest.param(
                True,
                ["example.com"],
                [
                    "reject_unknown_sender_domain",
                    "check_sender_access hash:/etc/postfix/access",
                    "reject",
                ],
                id="both_enabled",
            ),
        ],
    )
    def test_restrictions(
        self,
        enable_reject_unknown_sender: bool,
        restrict_sender_access: list[str],
        expected: list[str],
    ) -> None:
        """
        arrange: Create charm_state with different sender restriction settings.
        act: Call _smtpd_sender_restrictions with the charm_state.
        assert: The returned list of restrictions is correct and in order.
        """
        # Arrange
        self.charm_state.enable_reject_unknown_sender_domain = enable_reject_unknown_sender
        self.charm_state.restrict_sender_access = restrict_sender_access

        # Act
        result = postfix._smtpd_sender_restrictions(self.charm_state)

        # Assert
        assert result == expected


class TestSmtpdRecipientRestrictions:

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

    @pytest.mark.parametrize(
        (
            "append_x_envelope_to",
            "restrict_senders",
            "additional_restrictions",
            "enable_spf",
            "expected",
        ),
        [
            pytest.param(False, {}, [], False, [], id="all_disabled"),
            pytest.param(
                True,
                {},
                [],
                False,
                ["check_recipient_access regexp:/etc/postfix/append_envelope_to_header"],
                id="append_x_envelope_enabled",
            ),
            pytest.param(
                False,
                {"sender": "value"},
                [],
                False,
                ["check_sender_access hash:/etc/postfix/restricted_senders"],
                id="restrict_senders_enabled",
            ),
            pytest.param(
                False,
                {},
                ["custom_restriction_1"],
                False,
                ["custom_restriction_1"],
                id="additional_restrictions_enabled",
            ),
            pytest.param(
                False,
                {},
                [],
                True,
                ["check_policy_service unix:private/policyd-spf"],
                id="spf_enabled",
            ),
            pytest.param(
                True,
                {"sender": "value"},
                ["custom_restriction_1", "custom_restriction_2"],
                True,
                [
                    "check_recipient_access regexp:/etc/postfix/append_envelope_to_header",
                    "check_sender_access hash:/etc/postfix/restricted_senders",
                    "custom_restriction_1",
                    "custom_restriction_2",
                    "check_policy_service unix:private/policyd-spf",
                ],
                id="all_enabled",
            ),
        ],
    )
    def test_restrictions(
        self,
        append_x_envelope_to: bool,
        restrict_senders: dict,
        additional_restrictions: list[str],
        enable_spf: bool,
        expected: list[str],
    ) -> None:
        """
        arrange: Create charm_state with different recipient restriction settings.
        act: Call _smtpd_recipient_restrictions with the charm_state.
        assert: The returned list of restrictions is correct and in order.
        """
        # Arrange
        self.charm_state.append_x_envelope_to = append_x_envelope_to
        self.charm_state.restrict_senders = restrict_senders
        self.charm_state.additional_smtpd_recipient_restrictions = additional_restrictions
        self.charm_state.enable_spf = enable_spf

        # Act
        result = postfix._smtpd_recipient_restrictions(self.charm_state)

        # Assert
        assert result == expected


class TestConstructPolicydSpfConfigFileContent:
    @pytest.mark.parametrize(
        ("spf_skip_addresses", "expected_skip_string"),
        [
            pytest.param([], "", id="empty_list"),
            pytest.param(
                [ipaddress.ip_network("127.0.0.1")],
                "127.0.0.1/32",
                id="single_ipv4_address",
            ),
            pytest.param(
                [
                    ipaddress.ip_network("192.168.1.0/24"),
                    ipaddress.ip_network("::1"),
                    ipaddress.ip_network("10.0.0.5"),
                ],
                "192.168.1.0/24,::1/128,10.0.0.5/32",
                id="multiple_mixed_addresses",
            ),
        ],
    )
    @patch("reactive.postfix.utils.render_jinja2_template")
    def test_content_construction(
        self,
        mock_render_template: Mock,
        spf_skip_addresses: list["IPvAnyNetwork"],
        expected_skip_string: str,
    ) -> None:
        """
        arrange: Given a list of IP addresses to skip for SPF checks.
        act: Call construct_policyd_spf_config_file_content.
        assert: The Jinja2 renderer is called with the correctly formatted context.
        """
        # Arrange
        expected_context = {
            "JUJU_HEADER": utils.JUJU_HEADER,
            "skip_addresses": expected_skip_string,
        }

        # Act
        postfix.construct_policyd_spf_config_file_content(spf_skip_addresses)

        # Assert
        mock_render_template.assert_called_once_with(
            expected_context, "templates/policyd_spf_conf.tmpl"
        )


@patch("reactive.postfix._create_update_map")
class TestEnsurePostmapFiles:

    def setup_method(self) -> None:
        charm_config = {
            # Values directly used by the function under test
            "header_checks": "- '/^Subject:/ WARN'",
            "relay_access_sources": "- 192.168.1.0/24",
            "relay_recipient_maps": "user@example.com: OK",
            "restrict_recipients": "bad@example.com: REJECT",
            "restrict_senders": "spammer@example.com: REJECT",
            "restrict_sender_access": "- unwanted.com",
            "sender_login_maps": "sender@example.com: user@example.com",
            "smtp_header_checks": "- '/^Received:/ IGNORE'",
            "tls_policy_maps": "example.com: secure",
            "transport_maps": "domain.com: smtp:relay.example.com",
            "virtual_alias_maps": "alias@example.com: real@example.com",
            "virtual_alias_maps_type": "hash",
            # Values required for State object instantiation
            "domain": "example.com",
            "append_x_envelope_to": False,
            "enable_rate_limits": False,
            "enable_reject_unknown_sender_domain": False,
            "enable_smtp_auth": False,
            "enable_spf": False,
            "connection_limit": 0,
        }

        self.charm_state = state.State.from_charm(config=charm_config)

    def test_all_maps_are_processed(self, mock_create_update_map: Mock) -> None:
        """
        arrange: Create a charm_state with data for all possible maps.
        act: Call ensure_postmap_files.
        assert: The _create_update_map helper is called for each map with the
                correctly formatted content and path.
        """
        # Arrange
        postfix_conf_dir = "/etc/postfix"

        expected_calls = [
            call(
                "/^(.*)$/ PREPEND X-Envelope-To: $1",
                "regexp:/etc/postfix/append_envelope_to_header",
            ),
            call("/^Subject:/ WARN", "regexp:/etc/postfix/header_checks"),
            call("192.168.1.0/24", "cidr:/etc/postfix/relay_access"),
            call("user@example.com OK", "hash:/etc/postfix/relay_recipient"),
            call("bad@example.com REJECT", "hash:/etc/postfix/restricted_recipients"),
            call("spammer@example.com REJECT", "hash:/etc/postfix/restricted_senders"),
            call(f"{'unwanted.com':35} OK\n", "hash:/etc/postfix/access"),
            call("sender@example.com user@example.com", "hash:/etc/postfix/sender_login"),
            call("/^Received:/ IGNORE", "regexp:/etc/postfix/smtp_header_checks"),
            call("example.com secure", "hash:/etc/postfix/tls_policy"),
            call("domain.com smtp:relay.example.com", "hash:/etc/postfix/transport"),
            call("alias@example.com real@example.com", "hash:/etc/postfix/virtual_alias"),
        ]

        # Act
        postfix.ensure_postmap_files(postfix_conf_dir, self.charm_state)

        # Assert
        assert mock_create_update_map.call_count == len(expected_calls)
        mock_create_update_map.assert_has_calls(expected_calls, any_order=True)

    @pytest.mark.parametrize(
        ("side_effects", "expected_return"),
        [
            pytest.param([False] * 12, False, id="no_changes_returns_false"),
            pytest.param([False] * 5 + [True] + [False] * 6, True, id="one_change_returns_true"),
        ],
    )
    def test_return_value(
        self,
        mock_create_update_map: Mock,
        side_effects: list[bool],
        expected_return: bool,
    ) -> None:
        """
        arrange: Mock the _create_update_map helper to return various boolean values.
        act: Call ensure_postmap_files.
        assert: The function correctly aggregates the boolean results.
        """
        # Arrange
        mock_create_update_map.side_effect = side_effects

        # Act
        result = postfix.ensure_postmap_files("/etc/postfix", self.charm_state)

        # Assert
        assert result is expected_return
