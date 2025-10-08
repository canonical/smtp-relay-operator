# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the Postfix Relay charm."""

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import ANY, Mock, call, patch

import ops.testing
import pytest
from ops.testing import Context, State
from scenario import TCPPort

import charm
import tls
from state import ConfigurationError

if TYPE_CHECKING:
    from charms.operator_libs_linux.v1 import systemd


FILES_PATH = Path(__file__).parent / "files"

DEFAULT_TLS_CONFIG_PATHS = tls.TLSConfigPaths(
    "/etc/ssl/private/dhparams.pem",
    "/etc/ssl/certs/ssl-cert-snakeoil.pem",
    "/etc/ssl/private/ssl-cert-snakeoil.key",
    "",
)


@patch("charm.utils.copy_file", Mock())
@patch("charm.apt.add_package")
def test_install(
    mock_add_package: Mock,
    context: Context[charm.PostfixRelayCharm],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    arrange: Set up a charm state.
    act: Run the install event hook on the charm.
    assert: The unit status is set to maintenance and the correct packages are installed.
    """
    log_rotate_syslog = tmp_path / "rsyslog"
    log_rotate_syslog.write_text((FILES_PATH / "logrotate").read_text())
    monkeypatch.setattr(charm, "LOG_ROTATE_SYSLOG", log_rotate_syslog)
    expected_path = FILES_PATH / "logrotate_frequency"

    charm_state = State(config={}, leader=True)

    out = context.run(context.on.install(), charm_state)

    assert out.unit_status == ops.testing.WaitingStatus()
    mock_add_package.assert_called_once_with(
        ["dovecot-core", "postfix", "postfix-policyd-spf-python"],
        update_cache=True,
    )
    assert log_rotate_syslog.read_text() == expected_path.read_text()


@patch("charm.State.from_charm", Mock(side_effect=ConfigurationError("Invalid configuration")))
def test_invalid_config(context: Context[charm.PostfixRelayCharm]) -> None:
    """
    arrange: Invalid charm config.
    act: Run the config-changed event hook on the charm.
    assert: The unit status is set to blocked with the correct error message.
    """
    charm_state = State(config={}, leader=True)

    out = context.run(context.on.config_changed(), charm_state)

    assert out.unit_status == ops.testing.BlockedStatus("Invalid config")


@patch("charm.subprocess.check_call", Mock())
class TestConfigureAuth:
    """Unit tests for _configure_auth."""

    @pytest.mark.parametrize(
        "smtp_auth_users",
        [pytest.param("", id="no auth users"), pytest.param("- user", id="with auth users")],
    )
    @patch("charm.systemd")
    @patch("charm.utils.write_file")
    def test_no_auth(
        self,
        mock_write_file: Mock,
        mock_systemd: "systemd",
        smtp_auth_users: str,
        context: Context[charm.PostfixRelayCharm],
    ) -> None:
        """
        arrange: Charm with SMTP auth disabled.
        act: Run the config-changed event hook on the charm.
        assert: The charm correctly configures dovecot for a disabled state,
            pauses the dovecot service, and does not open SMTP auth ports.
        """
        charm_state = State(
            config={
                "enable_smtp_auth": False,
                "smtp_auth_users": smtp_auth_users,
            },
            leader=True,
        )

        out = context.run(context.on.config_changed(), charm_state)

        assert {TCPPort(465), TCPPort(587)}.isdisjoint(out.opened_ports)

        expected_systemd_call = call("dovecot")
        assert expected_systemd_call in mock_systemd.service_pause.mock_calls
        assert expected_systemd_call not in mock_systemd.service_enable.mock_calls
        assert expected_systemd_call not in mock_systemd.service_reload.mock_calls

        expected_write_calls = [call(ANY, charm.DOVECOT_CONFIG_FILEPATH)]
        if smtp_auth_users:
            expected_write_calls.append(
                call(ANY, charm.DOVECOT_USERS_FILEPATH, perms=0o640, group=charm.DOVECOT_NAME)
            )

        mock_write_file.assert_has_calls(expected_write_calls)

        assert out.unit_status == ops.testing.ActiveStatus()

    @pytest.mark.parametrize(
        "dovecot_running",
        [pytest.param(True, id="dovecot_running"), pytest.param(False, id="dovecot_not_running")],
    )
    @patch("charm.systemd")
    @patch("charm.utils.write_file")
    def test_with_auth_dovecot(
        self,
        mock_write_file: Mock,
        mock_systemd: "systemd",
        dovecot_running: bool,
        context: Context[charm.PostfixRelayCharm],
    ) -> None:
        """
        arrange: Charm with SMTP auth enabled and dovecot not running.
        act: Run the config-changed event hook on the charm.
        assert: Opensthe required ports, generates the dovecot config,
            and resumes the dovecot service.
        """
        charm_state = State(config={"enable_smtp_auth": True}, leader=True)
        mock_systemd.service_running.return_value = dovecot_running

        out = context.run(context.on.config_changed(), charm_state)

        assert {TCPPort(465), TCPPort(587)}.issubset(out.opened_ports)

        expected_systemd_call = call("dovecot")
        if dovecot_running:
            assert expected_systemd_call in mock_systemd.service_reload.mock_calls
            assert expected_systemd_call not in mock_systemd.service_resume.mock_calls
            assert expected_systemd_call not in mock_systemd.service_pause.mock_calls
        else:
            assert expected_systemd_call in mock_systemd.service_resume.mock_calls
            assert expected_systemd_call not in mock_systemd.service_reload.mock_calls
            assert expected_systemd_call not in mock_systemd.service_pause.mock_calls

        mock_write_file.assert_has_calls([call(ANY, charm.DOVECOT_CONFIG_FILEPATH)])

        assert out.unit_status == ops.testing.ActiveStatus()


@pytest.mark.parametrize(
    "postfix_running",
    [pytest.param(True, id="postfix_running"), pytest.param(False, id="postfix_not_running")],
)
@patch.object(
    charm, "construct_postfix_config_params", wraps=charm.construct_postfix_config_params
)
@patch.object(charm, "get_tls_config_paths", Mock(return_value=DEFAULT_TLS_CONFIG_PATHS))
@patch("charm.systemd")
@patch("charm.utils.write_file", Mock())
@patch("charm.subprocess.check_call")
def test_configure_relay(
    mock_subprocess_check_call: Mock,
    mock_systemd: "systemd",
    mock_construct_postfix_config_params: Mock,
    postfix_running: bool,
    context: Context[charm.PostfixRelayCharm],
) -> None:
    """
    arrange: Configure the charm with a specific domain.
    act: Run the config-changed event hook.
    assert: The charm constructs the correct FQDN.
    """
    charm_state = State(
        config={
            "domain": "example-domain.com",
        },
        relations=[
            ops.testing.Relation(
                "milter",
                remote_units_data={
                    0: {"ingress-address": "10.0.0.10"},
                    1: {"ingress-address": "10.0.0.11", "port": "9999"},
                    2: {},
                },
            ),
            ops.testing.Relation(
                "milter",
                remote_units_data={
                    0: {"ingress-address": "10.0.1.10"},
                    1: {"ingress-address": "10.0.1.11", "port": "9999"},
                },
            ),
            ops.testing.Relation(
                "milter",
                remote_units_data={},
            ),
            ops.testing.Relation(
                "milter",
                remote_units_data={
                    0: {},
                    1: {"ingress-address": "10.0.1.10"},
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
        leader=True,
    )
    mock_systemd.service_running.return_value = postfix_running

    out = context.run(context.on.config_changed(), charm_state)

    mock_construct_postfix_config_params.assert_called_once_with(
        charm_state=ANY,
        tls_dh_params_path=DEFAULT_TLS_CONFIG_PATHS.tls_dh_params,
        tls_cert_path=DEFAULT_TLS_CONFIG_PATHS.tls_cert,
        tls_key_path=DEFAULT_TLS_CONFIG_PATHS.tls_key,
        tls_cert_key_path=DEFAULT_TLS_CONFIG_PATHS.tls_cert_key,
        fqdn="postfix-relay-0.example-domain.com",
        hostname=ANY,
        milters="inet:10.0.0.11:9999 inet:10.0.1.10:8892",
    )

    mock_subprocess_check_call.assert_has_calls(
        [
            call(["postmap", "hash:/etc/postfix/relay_recipient"]),
            call(["postmap", "hash:/etc/postfix/restricted_recipients"]),
            call(["postmap", "hash:/etc/postfix/restricted_senders"]),
            call(["postmap", "hash:/etc/postfix/access"]),
            call(["postmap", "hash:/etc/postfix/sender_login"]),
            call(["postmap", "hash:/etc/postfix/tls_policy"]),
            call(["postmap", "hash:/etc/postfix/transport"]),
            call(["postmap", "hash:/etc/postfix/virtual_alias"]),
        ],
    )
    expected_systemd_call = call("postfix")
    if postfix_running:
        assert expected_systemd_call in mock_systemd.service_reload.mock_calls
        assert expected_systemd_call not in mock_systemd.service_resume.mock_calls
    else:
        assert expected_systemd_call in mock_systemd.service_resume.mock_calls
        assert expected_systemd_call not in mock_systemd.service_reload.mock_calls

    assert out.unit_status == ops.testing.ActiveStatus()
    assert TCPPort(25) in out.opened_ports


class TestUpdateAliases:
    @pytest.mark.parametrize(
        ("changed"),
        [pytest.param(True, id="change"), pytest.param(False, id="no_change")],
    )
    @patch("charm.utils.write_file")
    @patch("charm.subprocess.check_call")
    def test_update_aliases_calls_newaliases(
        self,
        mock_check_call: Mock,
        mock_write_file: Mock,
        changed: bool,
    ) -> None:
        """
        arrange: Parameterize whether the aliases file content has changed.
        act: Call the internal _update_aliases method.
        assert: The 'newaliases' command is executed only if the file content changed.
        """
        mock_write_file.return_value = changed

        charm.PostfixRelayCharm._update_aliases("admin@email.com")
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
    @patch("charm.subprocess.check_call", Mock())
    def test_update_aliases_content(
        self,
        admin_email_address: str | None,
        initial_content: str,
        expected_content: str,
        tmp_path: "Path",
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """
        arrange: Parametrize different initial contents.
        act: Call the internal _update_aliases method.
        assert: The content of the aliases file is updated to the expected state.
        """
        aliases_path = tmp_path / "aliases"
        aliases_path.write_text(initial_content)

        monkeypatch.setattr(charm, "ALIASES_FILEPATH", aliases_path)

        charm.PostfixRelayCharm._update_aliases(admin_email_address)

        if not admin_email_address:
            expected_content = "\n".join(
                [alias for alias in expected_content.split("\n") if not alias.startswith("root")]
            )

        assert aliases_path.read_text() == expected_content

    @patch("charm.subprocess.check_call", Mock())
    def test_update_aliases_no_file(
        self,
        tmp_path: "Path",
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """
        arrange: Define a path for an aliases file that does not exist.
        act: Call the internal _update_aliases method.
        assert: The method creates the aliases file with the correct default content.
        """
        non_existing_path = tmp_path / "aliases"
        monkeypatch.setattr(charm, "ALIASES_FILEPATH", non_existing_path)

        charm.PostfixRelayCharm._update_aliases(None)

        assert non_existing_path.is_file()
        assert non_existing_path.read_text() == "devnull:       /dev/null\n"


@pytest.mark.parametrize(
    "enable_spf",
    [pytest.param(True, id="enable_spf"), pytest.param(False, id="disable_spf")],
)
@patch("charm.systemd", Mock())
@patch("charm.subprocess.check_call", Mock())
@patch("charm.utils.write_file")
def test_configure_policyd_spf(
    mock_write_file: Mock,
    enable_spf: bool,
    context: Context[charm.PostfixRelayCharm],
) -> None:
    """
    arrange: Configure the charm state with SPF enabled or disabled.
    act: Run the config-changed event hook.
    assert: Configured only when SPF is enabled.
    """
    charm_state = State(
        config={
            "enable_spf": enable_spf,
            "spf_skip_addresses": "- 10.0.114.0/24",
        }
    )

    out = context.run(context.on.config_changed(), charm_state)

    investigated_call = call(ANY, charm.POLICYD_SPF_FILEPATH)

    if enable_spf:
        mock_write_file.assert_has_calls([investigated_call])
    else:
        assert investigated_call not in mock_write_file.mock_calls

    assert out.unit_status == ops.testing.ActiveStatus()
