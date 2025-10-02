# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the SMTP Relay charm."""

from typing import TYPE_CHECKING
from unittest.mock import Mock, call, patch

import ops.testing
import pytest
from ops.testing import Context, State
from scenario import TCPPort

from src.charm import DEFAULT_DOVECOT_USERS_FILEPATH, SMTPRelayCharm
from state import ConfigurationError

if TYPE_CHECKING:
    from charms.operator_libs_linux.v1 import systemd


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
    def test_no_auth(
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
    def test_with_auth_dovecot_not_running(
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
    def test_with_auth_dovecot_running(
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
