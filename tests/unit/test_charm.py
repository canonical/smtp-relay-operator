# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the SMTP Relay charm."""

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import ops.testing
import pytest
from ops.testing import Context, State
from scenario import TCPPort

from src.charm import DEFAULT_ALIASES_FILEPATH, DEFAULT_DOVECOT_USERS_FILEPATH, SMTPRelayCharm
from state import ConfigurationError
import tls

if TYPE_CHECKING:
    from charms.operator_libs_linux.v1 import systemd


DEFAULT_TLS_CONFIG_PATHS = tls.TLSConfigPaths(
    "/etc/ssl/private/dhparams.pem",
    "/etc/ssl/certs/ssl-cert-snakeoil.pem",
    "/etc/ssl/private/ssl-cert-snakeoil.key",
    "",
)


@patch("charm.utils.write_file")
@patch("charm.utils.copy_file")
@patch("charm.apt.add_package")
def test_install(
    mock_add_package: Mock,
    _mock_copy_file: Mock,
    _mock_write_file: Mock,
    context: Context[SMTPRelayCharm],
) -> None:
    """Test that the install handler is called."""
    charm_state = State(config={}, leader=True)

    out = context.run(context.on.install(), charm_state)
    assert out.unit_status == ops.testing.MaintenanceStatus("Installing packages")
    mock_add_package.assert_called_once_with(
        ["dovecot-core", "postfix-policyd-spf-python", "postfix"],
        update_cache=True,
    )


class TestReconcile:

    @patch("charm.State.from_charm", side_effect=ConfigurationError("Invalid configuration"))
    def test_invalid_config(
        self,
        _state_from_config: Mock,
        context: Context[SMTPRelayCharm],
    ) -> None:
        """Test that invalid config blocks the charm."""
        charm_state = State(config={}, leader=True)

        out = context.run(context.on.config_changed(), charm_state)

        assert out.unit_status == ops.testing.BlockedStatus("Invalid config")

    @pytest.mark.parametrize(
        ("smtp_auth_users"),
        [pytest.param("", id="no auth users"), pytest.param("- user", id="with auth users")],
    )
    @patch("charm.construct_dovecot_user_file_content")
    @patch("charm.construct_dovecot_config_file_content")
    @patch("charm.systemd")
    @patch("charm.SMTPRelayCharm._configure_policyd_spf")
    @patch("charm.SMTPRelayCharm._configure_smtp_relay")
    @patch("charm.utils.write_file")
    def test_configure_smtp_auth_no_auth(
        self,
        _mock_write_file: Mock,
        mock_configure_smtp_relay: Mock,
        mock_configure_policyd_spf: Mock,
        mock_systemd: "systemd",
        mock_construct_dovecot_config_file_content: Mock,
        mock_construct_dovecot_user_file_content: Mock,
        smtp_auth_users: str,
        context: Context[SMTPRelayCharm],
    ) -> None:

        charm_state = State(
            config={
                "enable_smtp_auth": False,
                "smtp_auth_users": smtp_auth_users,
            },
            leader=True,
        )

        out = context.run(context.on.config_changed(), charm_state)

        mock_construct_dovecot_config_file_content.assert_called_once_with(
            DEFAULT_DOVECOT_USERS_FILEPATH, False
        )

        assert {TCPPort(465), TCPPort(587)}.isdisjoint(out.opened_ports)

        mock_systemd.service_pause.assert_called_once_with("dovecot")
        mock_systemd.service_enable.assert_not_called()
        mock_systemd.service_reload.assert_not_called()

        if smtp_auth_users:
            mock_construct_dovecot_user_file_content.assert_called_once_with(["user"])
        else:
            mock_construct_dovecot_user_file_content.assert_not_called()

        assert out.unit_status == ops.testing.ActiveStatus()

    @patch("charm.construct_dovecot_user_file_content")
    @patch("charm.construct_dovecot_config_file_content")
    @patch("charm.systemd")
    @patch("charm.SMTPRelayCharm._configure_policyd_spf")
    @patch("charm.SMTPRelayCharm._configure_smtp_relay")
    @patch("charm.utils.write_file")
    def test_configure_smtp_auth_with_auth_dovecot_not_running(
        self,
        _mock_write_file: Mock,
        mock_configure_smtp_relay: Mock,
        mock_configure_policyd_spf: Mock,
        mock_systemd: "systemd",
        mock_construct_dovecot_config_file_content: Mock,
        mock_construct_dovecot_user_file_content: Mock,
        context: Context[SMTPRelayCharm],
    ) -> None:
        charm_state = State(config={"enable_smtp_auth": True}, leader=True)
        mock_systemd.service_running.return_value = False

        out = context.run(context.on.config_changed(), charm_state)

        mock_construct_dovecot_config_file_content.assert_called_once_with(
            DEFAULT_DOVECOT_USERS_FILEPATH, True
        )
        assert {TCPPort(465), TCPPort(587)}.issubset(out.opened_ports)

        mock_systemd.service_resume.assert_called_once_with("dovecot")
        mock_systemd.service_reload.assert_not_called()
        mock_systemd.service_pause.assert_not_called()

        mock_construct_dovecot_user_file_content.assert_not_called()

        assert out.unit_status == ops.testing.ActiveStatus()

    @pytest.mark.parametrize(
        ("changed"),
        [pytest.param(True, id="config change"), pytest.param(False, id="no config change")],
    )
    @patch("charm.construct_dovecot_user_file_content")
    @patch("charm.construct_dovecot_config_file_content")
    @patch("charm.systemd")
    @patch("charm.SMTPRelayCharm._configure_policyd_spf")
    @patch("charm.SMTPRelayCharm._configure_smtp_relay")
    @patch("charm.utils.write_file")
    def test_configure_smtp_auth_with_auth_dovecot_running(
        self,
        mock_write_file: Mock,
        mock_configure_smtp_relay: Mock,
        mock_configure_policyd_spf: Mock,
        mock_systemd: "systemd",
        mock_construct_dovecot_config_file_content: Mock,
        mock_construct_dovecot_user_file_content: Mock,
        changed: bool,
        context: Context[SMTPRelayCharm],
    ) -> None:
        mock_write_file.return_value = changed

        charm_state = State(config={"enable_smtp_auth": True}, leader=True)
        mock_systemd.service_running.return_value = True

        out = context.run(context.on.config_changed(), charm_state)

        mock_construct_dovecot_config_file_content.assert_called_once_with(
            DEFAULT_DOVECOT_USERS_FILEPATH, True
        )
        assert {TCPPort(465), TCPPort(587)} <= out.opened_ports

        if changed:
            mock_systemd.service_reload.assert_called_with("dovecot")
        else:
            mock_systemd.service_reload.assert_not_called()
        mock_systemd.service_resume.assert_not_called()
        mock_systemd.service_pause.assert_not_called()

        mock_construct_dovecot_user_file_content.assert_not_called()

        assert out.unit_status == ops.testing.ActiveStatus()

    @patch("charm.subprocess.check_call", Mock())
    @patch("charm.Path.is_file", lambda x: {DEFAULT_ALIASES_FILEPATH: False}.get(x, True))
    @patch("charm.socket.gethostname", Mock(return_value="hostname"))
    @patch("charm.get_tls_config_paths", Mock(return_value=DEFAULT_TLS_CONFIG_PATHS))
    @patch("charm.construct_postfix_config_params", return_value={})
    @patch("charm.systemd", Mock(return_value=Mock(return_value=True)))
    @patch("charm.SMTPRelayCharm._configure_policyd_spf", Mock())
    @patch("charm.SMTPRelayCharm._configure_smtp_auth", Mock())
    @patch("charm.utils.write_file", Mock(return_value=False))
    def test_configure_smtp_relay_generate_fqdn(
        self,
        mock_construct_postfix_config_params: Mock,
        context: Context[SMTPRelayCharm],
    ) -> None:
        charm_state = State(config={"domain": "example-domain.com"}, leader=True)

        out = context.run(context.on.config_changed(), charm_state)

        _, kwargs = mock_construct_postfix_config_params.call_args
        assert kwargs["fqdn"] == "smtp-relay-0.example-domain.com"

        assert out.unit_status == ops.testing.ActiveStatus()
        assert TCPPort(25) in out.opened_ports

    @patch("charm.subprocess.check_call", Mock())
    @patch("charm.Path.is_file", lambda x: {DEFAULT_ALIASES_FILEPATH: False}.get(x, True))
    @patch("charm.socket.gethostname", Mock(return_value="hostname"))
    @patch("charm.socket.getfqdn", Mock(return_value="fqdn"))
    @patch("charm.get_tls_config_paths", Mock(return_value=DEFAULT_TLS_CONFIG_PATHS))
    @patch("charm.construct_postfix_config_params", return_value={})
    @patch("charm.systemd", Mock(return_value=Mock(return_value=True)))
    @patch("charm.SMTPRelayCharm._configure_policyd_spf", Mock())
    @patch("charm.SMTPRelayCharm._configure_smtp_auth", Mock())
    @patch("charm.utils.write_file", Mock(return_value=False))
    def test_configure_smtp_relay_get_milters(
        self,
        mock_construct_postfix_config_params: Mock,
        context: Context[SMTPRelayCharm],
    ) -> None:
        charm_state = State(
            relations=[
                ops.testing.Relation(
                    "milter",
                    remote_units_data={
                        0: {"ingress-address": "10.0.0.10"},
                        1: {"ingress-address": "10.0.0.11", "port": "9999"},
                        2: {"ingress-address": "10.0.0.12"},
                    },
                ),
                ops.testing.Relation(
                    "milter",
                    remote_units_data={
                        0: {"ingress-address": "10.0.1.10"},
                        1: {"ingress-address": "10.0.1.11", "port": "9999"},
                    },
                ),
                ops.testing.PeerRelation(
                    "peer",
                    peers_data={
                        1: {},
                        2: {},
                    },
                ),
            ],
        )

        out = context.run(context.on.config_changed(), charm_state)

        _, kwargs = mock_construct_postfix_config_params.call_args
        assert kwargs["milters"] == "inet:10.0.0.10:8892 inet:10.0.1.11:9999"

        assert out.unit_status == ops.testing.ActiveStatus()
        assert TCPPort(25) in out.opened_ports

    @patch("charm.subprocess.check_call")
    @patch("charm.Path.touch", Mock(return_value=None))
    @patch("charm.Path.is_file", Mock(return_value=False))
    @patch("charm.socket.gethostname", Mock(return_value="hostname"))
    @patch("charm.socket.getfqdn", Mock(return_value="fqdn"))
    @patch("charm.get_tls_config_paths", Mock(return_value=DEFAULT_TLS_CONFIG_PATHS))
    @patch("charm.construct_postfix_config_params", Mock(return_value={}))
    @patch("charm.systemd", Mock(return_value=Mock(return_value=True)))
    @patch("charm.SMTPRelayCharm._configure_policyd_spf", Mock())
    @patch("charm.SMTPRelayCharm._configure_smtp_auth", Mock())
    @patch("charm.utils.write_file", Mock(return_value=False))
    def test_configure_smtp_relay_apply_postfix_maps(
        self, mock_check_call: Mock, context: Context[SMTPRelayCharm]
    ) -> None:
        charm_state = State(config={}, leader=True)

        out = context.run(context.on.config_changed(), charm_state)

        assert mock_check_call.call_count == 8

        assert out.unit_status == ops.testing.ActiveStatus()
        assert TCPPort(25) in out.opened_ports

    @pytest.mark.parametrize(
        "service_running",
        [
            pytest.param(True, id="service-running"),
            pytest.param(False, id="service-not-running"),
        ],
    )
    @pytest.mark.parametrize(
        "changed",
        [
            pytest.param(True, id="change"),
            pytest.param(False, id="no-change"),
        ],
    )
    @patch("charm.socket.gethostname", Mock(return_value="hostname"))
    @patch("charm.socket.getfqdn", Mock(return_value="fqdn"))
    @patch("charm.get_tls_config_paths", Mock(return_value=DEFAULT_TLS_CONFIG_PATHS))
    @patch("charm.SMTPRelayCharm._update_aliases", new=Mock())
    @patch("charm.SMTPRelayCharm._apply_postfix_maps")
    @patch("charm.construct_postfix_config_params", Mock(return_value={}))
    @patch("charm.systemd")
    @patch("charm.SMTPRelayCharm._configure_policyd_spf", Mock())
    @patch("charm.SMTPRelayCharm._configure_smtp_auth", Mock())
    @patch("charm.utils.write_file", Mock(return_value=False))
    def test_configure_smtp_relay_service_control(
        self,
        mock_systemd: "systemd",
        mock_apply_postfix_maps: Mock,
        changed,
        service_running: bool,
        context: Context[SMTPRelayCharm],
    ) -> None:
        charm_state = State(config={}, leader=True)
        mock_apply_postfix_maps.return_value = changed
        mock_systemd.service_running.return_value = service_running

        out = context.run(context.on.config_changed(), charm_state)

        if not service_running:
            mock_systemd.service_resume.assert_called_once_with("postfix")
            mock_systemd.service_reload.assert_not_called()
        elif changed:
            mock_systemd.service_reload.assert_called_once_with("postfix")
            mock_systemd.service_resume.assert_not_called()
        else:
            mock_systemd.service_resume.assert_not_called()
            mock_systemd.service_reload.assert_not_called()

        assert out.unit_status == ops.testing.ActiveStatus()
        assert TCPPort(25) in out.opened_ports


class TestUpdateAliases:
    @pytest.mark.parametrize(
        ("changed"),
        [
            pytest.param(True, id="change"),
            pytest.param(False, id="no-change"),
        ],
    )
    @patch("charm.utils.write_file")
    @patch("charm.subprocess.check_call")
    def test_update_aliases_calls_newaliases(
        self,
        mock_check_call: Mock,
        mock_write_file: Mock,
        changed: bool,
    ) -> None:

        mock_write_file.return_value = changed

        SMTPRelayCharm._update_aliases("admin@email.com")
        if changed:
            mock_check_call.assert_called_once_with(["newaliases"])
        else:
            mock_check_call.assert_not_called()

    @pytest.mark.parametrize(
        "initial_content, expected_content",
        [
            pytest.param(
                "",
                "devnull:       /dev/null\nroot:          admin@email.com\n",
                id="empty_file",
            ),
            pytest.param(
                "devnull:       /dev/null\n",
                "devnull:       /dev/null\nroot:          admin@email.com\n",
                id="missing_root",
            ),
            pytest.param(
                "root:          old@example.com\n",
                "devnull:       /dev/null\nroot:          admin@email.com\n",
                id="update_root",
            ),
            pytest.param(
                "postmaster:    root\n",
                "postmaster:    root\ndevnull:       /dev/null\nroot:          admin@email.com\n",
                id="preserve_existing_aliases",
            ),
            pytest.param(
                "devnull:       /dev/null\nroot:          admin@email.com\n",
                "devnull:       /dev/null\nroot:          admin@email.com\n",
                id="no_change",
            ),
        ],
    )
    @pytest.mark.parametrize(
        "admin_email_address",
        [
            pytest.param("admin@email.com", id="admin-email"),
            pytest.param(None, id="no-admin-email"),
        ],
    )
    @patch("charm.subprocess.check_call", new=Mock())
    def test_update_aliases_content(
        self,
        admin_email_address: str | None,
        initial_content: str,
        expected_content: str,
        tmp_path: Path,
    ) -> None:
        aliases_path = tmp_path / "aliases"
        aliases_path.write_text(initial_content)

        SMTPRelayCharm._update_aliases(admin_email_address, aliases_path)

        if not admin_email_address:
            expected_content = "\n".join(
                [alias for alias in expected_content.split("\n") if not alias.startswith("root")]
            )

        assert aliases_path.read_text() == expected_content

    @patch("charm.subprocess.check_call", new=Mock())
    def test_update_aliases_no_file(self, tmp_path: Path) -> None:
        non_existing_path = tmp_path / "aliases"

        SMTPRelayCharm._update_aliases(None, non_existing_path)

        assert non_existing_path.is_file()
        assert non_existing_path.read_text() == "devnull:       /dev/null\n"
