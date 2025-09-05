# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""SMTP Relay charm unit tests."""
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

# We also need to mock up charms.layer so we can run unit tests without having
# to build the charm and pull in layers such as layer-status.
sys.modules["charms.layer"] = mock.MagicMock()

from charmhelpers.core import unitdata  # NOQA: E402
from charms.layer import status  # NOQA: E402

# Add path to where our reactive layer lives and import.
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
from reactive import charm  # NOQA: E402


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.tmpdir = tempfile.mkdtemp(prefix="charm-unittests-")
        self.addCleanup(shutil.rmtree, self.tmpdir)

        os.environ["UNIT_STATE_DB"] = os.path.join(self.tmpdir, ".unit-state.db")
        unitdata.kv().set("test", {})

        self.charm_dir = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        )

        patcher = mock.patch("charmhelpers.core.hookenv.log")
        self.mock_log = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_log.return_value = ""
        # Also needed for host.write_file()
        patcher = mock.patch("charmhelpers.core.host.log")
        self.mock_log = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_log.return_value = ""

        patcher = mock.patch("charmhelpers.core.hookenv.charm_dir")
        self.mock_charm_dir = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_charm_dir.return_value = self.charm_dir

        patcher = mock.patch("charmhelpers.core.hookenv.application_name")
        self.mock_application_name = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_application_name.return_value = "smtp-relay"

        patcher = mock.patch("charmhelpers.core.hookenv.local_unit")
        self.mock_local_unit = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_local_unit.return_value = "smtp-relay/0"

        patcher = mock.patch("charmhelpers.core.hookenv.config")
        self.mock_config = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_config.return_value = {
            "append_x_envelope_to": False,
            "connection_limit": 100,
            "domain": "",
            "enable_rate_limits": False,
            "enable_reject_unknown_sender_domain": True,
            "enable_smtp_auth": True,
            "enable_spf": False,
            "message_size_limit": 61440000,
            "tls_ciphers": "HIGH",
            "tls_exclude_ciphers": "aNULL,eNULL,DES,3DES,MD5,RC4,CAMELLIA",
            "tls_protocols": "!SSLv2,!SSLv3",
            "tls_security_level": "may",
            "virtual_alias_maps_type": "hash",
        }

        patcher = mock.patch("charmhelpers.core.hookenv.close_port")
        self.mock_close_port = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch("charmhelpers.core.hookenv.open_port")
        self.mock_open_port = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch("charmhelpers.core.host.service_reload")
        self.mock_service_reload = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch("charmhelpers.core.host.service_restart")
        self.mock_service_restart = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch("charmhelpers.core.host.service_start")
        self.mock_service_start = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch("charmhelpers.core.host.service_stop")
        self.mock_service_stop = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch("socket.getfqdn")
        self.mock_getfqdn = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_getfqdn.return_value = "juju-87625f-hloeung-94.openstacklocal"

        patcher = mock.patch("socket.gethostname")
        self.mock_getfqdn = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_getfqdn.return_value = "juju-87625f-hloeung-94"

        status.active.reset_mock()
        status.blocked.reset_mock()
        status.maintenance.reset_mock()

    @mock.patch("charms.reactive.clear_flag")
    def test_hook_upgrade_charm(self, clear_flag):
        charm.upgrade_charm()
        status.maintenance.assert_called()

        want = [
            mock.call("smtp-relay.active"),
            mock.call("smtp-relay.auth.configured"),
            mock.call("smtp-relay.configured"),
            mock.call("smtp-relay.installed"),
        ]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch("charms.reactive.clear_flag")
    def test_hook_relation_peers_flags(self, clear_flag):
        charm.peer_relation_changed()
        want = [mock.call("smtp-relay.configured")]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch("charms.reactive.clear_flag")
    def test_config_changed(self, clear_flag):
        charm.config_changed()
        want = [mock.call("smtp-relay.configured")]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch("charms.reactive.clear_flag")
    def test_config_changed_smtp_auth(self, clear_flag):
        charm.config_changed_smtp_auth()
        want = [mock.call("smtp-relay.auth.configured")]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch("charms.reactive.clear_flag")
    def test_config_changed_policyd_spf(self, clear_flag):
        charm.config_changed_policyd_spf()
        want = [mock.call("smtp-relay.policyd-spf.configured")]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch("subprocess.call")
    def test__create_update_map(self, call):
        postfix_relay_access = "hash:{}".format(os.path.join(self.tmpdir, "relay_access"))
        self.assertTrue(charm._create_update_map("mydomain.local OK", postfix_relay_access))
        want = ["postmap", postfix_relay_access]
        call.assert_called_with(want)
        want = charm.JUJU_HEADER + "mydomain.local OK" + "\n"
        with open(os.path.join(self.tmpdir, "relay_access"), "r") as f:
            got = f.read()
        self.assertEqual(want, got)

        call.reset_mock()
        self.assertFalse(charm._create_update_map("mydomain.local OK", postfix_relay_access))
        call.assert_not_called()

    @mock.patch("subprocess.call")
    def test__create_update_map_eno_content(self, call):
        postfix_relay_access = "hash:{}".format(os.path.join(self.tmpdir, "relay_access"))
        self.assertTrue(charm._create_update_map("", postfix_relay_access))
        want = ["postmap", postfix_relay_access]
        call.assert_called_with(want)

        call.reset_mock()
        charm._create_update_map("", postfix_relay_access)
        call.assert_not_called()

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("subprocess.call")
    def test_configure_smtp_auth_relay(self, call, set_flag, clear_flag):
        dovecot_config = os.path.join(self.tmpdir, "dovecot.conf")

        self.mock_config.return_value["enable_smtp_auth"] = True
        charm.configure_smtp_auth(dovecot_config)
        self.mock_service_reload.assert_called_with("dovecot")
        # Try again, no change so no need for dovecot to be reloaded.
        self.mock_service_reload.reset_mock()
        call.reset_mock()
        charm.configure_smtp_auth(dovecot_config)
        self.mock_service_reload.assert_not_called()
        self.mock_service_start.assert_called()
        call.assert_not_called()

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("subprocess.call")
    def test_configure_smtp_auth_relay_config(self, call, set_flag, clear_flag):
        dovecot_config = os.path.join(self.tmpdir, "dovecot.conf")

        self.mock_config.return_value["enable_smtp_auth"] = True
        charm.configure_smtp_auth(dovecot_config)
        with open("tests/unit/files/dovecot_config", "r", encoding="utf-8") as f:
            want = f.read()
        with open(dovecot_config, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("subprocess.call")
    def test_configure_smtp_auth_relay_config_auth_disabled(self, call, set_flag, clear_flag):
        dovecot_config = os.path.join(self.tmpdir, "dovecot.conf")

        self.mock_config.return_value["enable_smtp_auth"] = True
        charm.configure_smtp_auth(dovecot_config)
        self.mock_config.return_value["enable_smtp_auth"] = False
        charm.configure_smtp_auth(dovecot_config)
        with open("tests/unit/files/dovecot_config_auth_disabled", "r", encoding="utf-8") as f:
            want = f.read()
        with open(dovecot_config, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        self.mock_service_stop.assert_called()

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("grp.getgrnam")
    @mock.patch("os.fchown")
    @mock.patch("subprocess.call")
    def test_configure_smtp_auth_relay_config_auth_users(
        self, call, fchown, getgrnam, set_flag, clear_flag
    ):
        dovecot_config = os.path.join(self.tmpdir, "dovecot.conf")
        dovecot_users = os.path.join(self.tmpdir, "dovecot_users")
        self.mock_config.return_value["smtp_auth_users"] = (
            "myuser1:$1$bPb0IPiM$kmrSMZkZvICKKHXu66daQ.,"
            "myuser2:$6$3rGBbaMbEiGhnGKz$KLGFv8kDTjqa3xeUgA6A1Rie1zGSf3sLT85vF1s59Yj"
            "//F36qLB/J8rUfIIndaDtkxeb5iR3gs1uBn9fNyJDD1"
        )
        charm.configure_smtp_auth(dovecot_config, dovecot_users)
        with open("tests/unit/files/dovecot_users", "r", encoding="utf-8") as f:
            want = f.read()
        with open(dovecot_users, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("utils.write_file")
    def test_configure_smtp_auth_relay_flags(self, write_file, set_flag, clear_flag):
        self.mock_config.return_value["enable_smtp_auth"] = True
        charm.configure_smtp_auth()

        want = [mock.call("smtp-relay.auth.configured")]
        set_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(set_flag.mock_calls))

        want = [mock.call("smtp-relay.active"), mock.call("smtp-relay.configured")]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    def test_configure_smtp_auth_relay_flags_auth_disabled(self, set_flag, clear_flag):
        dovecot_config = os.path.join(self.tmpdir, "dovecot.conf")

        self.mock_config.return_value["enable_smtp_auth"] = False
        charm.configure_smtp_auth(dovecot_config)

        want = [mock.call("smtp-relay.auth.configured")]
        set_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(set_flag.mock_calls))

        want = [mock.call("smtp-relay.active"), mock.call("smtp-relay.configured")]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("utils.write_file")
    def test_configure_smtp_auth_relay_ports(self, write_file, set_flag, clear_flag):
        self.mock_config.return_value["enable_smtp_auth"] = True
        charm.configure_smtp_auth()

        want = [mock.call(465, "TCP"), mock.call(587, "TCP")]
        self.mock_open_port.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(self.mock_open_port.mock_calls))

        self.mock_close_port.assert_not_called()

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    def test_configure_smtp_auth_relay_ports_auth_disabled(self, set_flag, clear_flag):
        dovecot_config = os.path.join(self.tmpdir, "dovecot.conf")

        self.mock_config.return_value["enable_smtp_auth"] = False
        charm.configure_smtp_auth(dovecot_config)

        want = [mock.call(465, "TCP"), mock.call(587, "TCP")]
        self.mock_close_port.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(self.mock_close_port.mock_calls))

        self.mock_open_port.assert_not_called()

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    def test_hook_relation_milter_flags(self, set_flag, clear_flag):
        charm.milter_relation_changed()

        want = [mock.call("smtp-relay.configured")]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

        set_flag.assert_not_called()

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        get_cn.return_value = ""
        get_milters.return_value = ""
        charm.configure_smtp_relay(self.tmpdir)
        self.mock_service_reload.assert_called_with("postfix")
        want = [mock.call(25, "TCP")]
        self.mock_open_port.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(self.mock_open_port.mock_calls))
        # Try again, no change so no need for postfix to be reloaded.
        self.mock_service_reload.reset_mock()
        self.mock_open_port.reset_mock()
        charm.configure_smtp_relay(self.tmpdir)
        self.mock_service_reload.assert_not_called()
        self.mock_service_start.assert_called()

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        postfix_master_cf = os.path.join(self.tmpdir, "master.cf")
        get_cn.return_value = ""
        get_milters.return_value = ""
        charm.configure_smtp_relay(self.tmpdir)
        with open("tests/unit/files/postfix_main.cf", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        with open("tests/unit/files/postfix_master.cf", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_master_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_auth_disabled(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        postfix_master_cf = os.path.join(self.tmpdir, "master.cf")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["enable_smtp_auth"] = False
        charm.configure_smtp_relay(self.tmpdir)
        with open("tests/unit/files/postfix_main_auth_disabled.cf", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        with open("tests/unit/files/postfix_master_auth_disabled.cf", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_master_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_auth_sender_login_maps(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["enable_smtp_auth"] = True
        charm.configure_smtp_relay(self.tmpdir)
        with open(
            "tests/unit/files/postfix_main_auth_sender_login_maps.cf", "r", encoding="utf-8"
        ) as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_domain(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["domain"] = "mydomain.local"
        self.mock_config.return_value["enable_smtp_auth"] = False
        charm.configure_smtp_relay(self.tmpdir)
        with open("tests/unit/files/postfix_main_domain.cf", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_with_milter(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        get_cn.return_value = ""
        get_milters.return_value = "inet:10.48.129.221:8892"
        charm.configure_smtp_relay(self.tmpdir)
        with open("tests/unit/files/postfix_main_with_milter.cf", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_with_milter_auth_disabled(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        get_cn.return_value = ""
        get_milters.return_value = "inet:10.48.129.221:8892"
        self.mock_config.return_value["enable_smtp_auth"] = False
        charm.configure_smtp_relay(self.tmpdir)
        with open(
            "tests/unit/files/postfix_main_with_milter_auth_disabled.cf", "r", encoding="utf-8"
        ) as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_tls_cert_key(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        get_cn.return_value = "smtp.mydomain.local"
        get_milters.return_value = ""
        charm.configure_smtp_relay(self.tmpdir)
        with open("tests/unit/files/postfix_main_tls_cert_key.cf", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_tls_no_ciphers_and_protocols(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["tls_ciphers"] = None
        self.mock_config.return_value["tls_exclude_ciphers"] = None
        self.mock_config.return_value["tls_mandatory_ciphers"] = None
        self.mock_config.return_value["tls_mandatory_protocols"] = None
        self.mock_config.return_value["tls_protocols"] = None
        self.mock_config.return_value["tls_security_level"] = None
        charm.configure_smtp_relay(self.tmpdir)
        with open(
            "tests/unit/files/postfix_main_tls_no_ciphers_and_protocols.cf", "r", encoding="utf-8"
        ) as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._create_update_map")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("utils.write_file")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_tls_dhparam_non_exists(
        self,
        call,
        write_file,
        update_aliases,
        get_milters,
        get_cn,
        create_update_map,
        set_flag,
        clear_flag,
    ):
        dhparams = os.path.join(self.tmpdir, "dhparams.pem")
        get_cn.return_value = ""
        get_milters.return_value = ""
        charm.configure_smtp_relay(self.tmpdir, dhparams)
        want = [mock.call(["openssl", "dhparam", "-out", dhparams, "2048"])]
        call.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(call.mock_calls))

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._create_update_map")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("utils.write_file")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_tls_dhparam_exists(
        self,
        call,
        write_file,
        update_aliases,
        get_milters,
        get_cn,
        create_update_map,
        set_flag,
        clear_flag,
    ):
        dhparams = os.path.join(self.tmpdir, "dhparams.pem")
        with open(dhparams, "a"):
            os.utime(dhparams, None)
        get_cn.return_value = ""
        get_milters.return_value = ""
        charm.configure_smtp_relay(self.tmpdir, dhparams)
        create_update_map.assert_called()

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_rate_limits(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["enable_rate_limits"] = True
        charm.configure_smtp_relay(self.tmpdir)
        with open("tests/unit/files/postfix_main_rate_limits.cf", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_rate_limits_auth_disabled(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["enable_rate_limits"] = True
        self.mock_config.return_value["enable_smtp_auth"] = False
        charm.configure_smtp_relay(self.tmpdir)
        with open(
            "tests/unit/files/postfix_main_rate_limits_auth_disabled.cf", "r", encoding="utf-8"
        ) as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_header_checks(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        postfix_header_checks = os.path.join(self.tmpdir, "header_checks")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["header_checks"] = "/^Received:/ HOLD"
        charm.configure_smtp_relay(self.tmpdir)
        with open("tests/unit/files/postfix_main_header_checks.cf", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        want = charm.JUJU_HEADER + "/^Received:/ HOLD" + "\n"
        with open(postfix_header_checks, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_smtp_header_checks(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        postfix_smtp_header_checks = os.path.join(self.tmpdir, "smtp_header_checks")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["smtp_header_checks"] = "/^Received:/ HOLD"
        charm.configure_smtp_relay(self.tmpdir)
        with open(
            "tests/unit/files/postfix_main_smtp_header_checks.cf", "r", encoding="utf-8"
        ) as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        want = charm.JUJU_HEADER + "/^Received:/ HOLD" + "\n"
        with open(postfix_smtp_header_checks, "r", encoding="utf-8") as f:
            got = f.read()

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_reject_unknown_sender_domain(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["enable_reject_unknown_sender_domain"] = False
        charm.configure_smtp_relay(self.tmpdir)
        with open(
            "tests/unit/files/postfix_main_reject_unknown_sender_domain.cf", "r", encoding="utf-8"
        ) as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_relay_access_sources(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        postfix_relay_access = os.path.join(self.tmpdir, "relay_access")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["relay_access_sources"] = (
            "# Reject some made user.,10.10.10.5    REJECT,10.10.10.0/24 OK"
        )
        charm.configure_smtp_relay(self.tmpdir)
        with open(
            "tests/unit/files/postfix_main_relay_access_sources.cf", "r", encoding="utf-8"
        ) as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        with open(
            "tests/unit/files/relay_access_relay_access_sources", "r", encoding="utf-8"
        ) as f:
            want = f.read()
        with open(postfix_relay_access, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_relay_access_sources_auth_disabled(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        postfix_relay_access = os.path.join(self.tmpdir, "relay_access")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["relay_access_sources"] = (
            "# Reject some made user.,10.10.10.5    REJECT,10.10.10.0/24 OK"
        )
        self.mock_config.return_value["enable_smtp_auth"] = False
        charm.configure_smtp_relay(self.tmpdir)
        with open(
            "tests/unit/files/postfix_main_relay_access_sources_auth_disabled.cf",
            "r",
            encoding="utf-8",
        ) as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        with open(
            "tests/unit/files/relay_access_relay_access_sources", "r", encoding="utf-8"
        ) as f:
            want = f.read()
        with open(postfix_relay_access, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_restrict_both_senders_and_recpients(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["restrict_recipients"] = "mydomain.local  OK"
        self.mock_config.return_value["restrict_senders"] = "noreply@mydomain.local  OK"
        charm.configure_smtp_relay(self.tmpdir)
        with open(
            "tests/unit/files/postfix_main_restrict_both_senders_and_recipients.cf",
            "r",
            encoding="utf-8",
        ) as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_restrict_recpients(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        postfix_restricted_recipients = os.path.join(self.tmpdir, "restricted_recipients")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["restrict_recipients"] = "mydomain.local  OK"
        charm.configure_smtp_relay(self.tmpdir)
        with open(
            "tests/unit/files/postfix_main_restrict_recipients.cf", "r", encoding="utf-8"
        ) as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        with open("tests/unit/files/restricted_recipients", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_restricted_recipients, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_restrict_senders(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        postfix_restricted_senders = os.path.join(self.tmpdir, "restricted_senders")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["restrict_senders"] = "noreply@mydomain.local  OK"
        charm.configure_smtp_relay(self.tmpdir)
        with open("tests/unit/files/postfix_main_restrict_senders.cf", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        with open("tests/unit/files/restricted_senders", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_restricted_senders, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_restrict_sender_access(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        postfix_access = os.path.join(self.tmpdir, "access")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["restrict_sender_access"] = (
            "canonical.com,ubuntu.com,mydomain.local,mydomain2.local"
        )
        charm.configure_smtp_relay(self.tmpdir)
        with open(
            "tests/unit/files/postfix_main_restrict_sender_access.cf", "r", encoding="utf-8"
        ) as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        with open("tests/unit/files/access_restrict_sender_access", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_access, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_restrict_sender_access_reset(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_access = os.path.join(self.tmpdir, "access")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["restrict_sender_access"] = (
            "canonical.com,ubuntu.com,mydomain.local,mydomain2.local"
        )
        charm.configure_smtp_relay(self.tmpdir)
        with open("tests/unit/files/access_restrict_sender_access", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_access, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

        self.mock_config.return_value["restrict_sender_access"] = None
        charm.configure_smtp_relay(self.tmpdir)
        want = charm.JUJU_HEADER + "\n"
        with open(postfix_access, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_tls_policy_map(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        postfix_tls_policy_map = os.path.join(self.tmpdir, "tls_policy")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["tls_policy_maps"] = (
            "# Google hosted,gapps.mydomain.local secure match=mx.google.com,"
            "# Some place enforce encryption,someplace.local encrypt,.someplace.local encrypt"
        )
        charm.configure_smtp_relay(self.tmpdir)
        with open("tests/unit/files/postfix_main_tls_policy.cf", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        with open("tests/unit/files/tls_policy", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_tls_policy_map, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_relay_domains(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["relay_domains"] = "mydomain.local,mydomain2.local"
        charm.configure_smtp_relay(self.tmpdir)
        with open("tests/unit/files/postfix_main_relay_domains.cf", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_relay_domains_with_relay_recipient_maps(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        postfix_relay_recipient_maps = os.path.join(self.tmpdir, "relay_recipient")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["relay_domains"] = "mydomain.local,mydomain2.local"
        self.mock_config.return_value["relay_recipient_maps"] = (
            "noreply@mydomain.local noreply@mydomain.local"
        )
        charm.configure_smtp_relay(self.tmpdir)
        with open(
            "tests/unit/files/postfix_main_relay_domains_with_relay_recipient_maps.cf",
            "r",
            encoding="utf-8",
        ) as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        want = charm.JUJU_HEADER + "noreply@mydomain.local noreply@mydomain.local" + "\n"
        with open(postfix_relay_recipient_maps, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_transport_maps(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        postfix_transport_maps = os.path.join(self.tmpdir, "transport")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["transport_maps"] = (
            ".mydomain.local  smtp:[smtp.mydomain.local]"
        )
        charm.configure_smtp_relay(self.tmpdir)
        with open("tests/unit/files/postfix_main_transport_maps.cf", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        want = charm.JUJU_HEADER + ".mydomain.local  smtp:[smtp.mydomain.local]" + "\n"
        with open(postfix_transport_maps, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_transport_maps_with_header_checks(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        postfix_transport_maps = os.path.join(self.tmpdir, "transport")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["header_checks"] = "/^Received:/ HOLD"
        self.mock_config.return_value["transport_maps"] = (
            ".mydomain.local  smtp:[smtp.mydomain.local]"
        )
        charm.configure_smtp_relay(self.tmpdir)
        with open(
            "tests/unit/files/postfix_main_transport_maps_with_header_checks.cf",
            "r",
            encoding="utf-8",
        ) as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        want = charm.JUJU_HEADER + ".mydomain.local  smtp:[smtp.mydomain.local]" + "\n"
        with open(postfix_transport_maps, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_transport_maps_with_virtual_alias_maps(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        postfix_virtual_alias_maps = os.path.join(self.tmpdir, "virtual_alias")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["relay_domains"] = "mydomain.local,mydomain2.local"
        self.mock_config.return_value["transport_maps"] = (
            ".mydomain.local  smtp:[smtp.mydomain.local]"
        )
        self.mock_config.return_value["virtual_alias_domains"] = "mydomain.local,mydomain2.local"
        self.mock_config.return_value["virtual_alias_maps"] = (
            "abuse@mydomain.local sysadmin@mydomain.local"
        )
        charm.configure_smtp_relay(self.tmpdir)
        with open(
            "tests/unit/files/postfix_main_transport_maps_with_virtual_alias_maps.cf",
            "r",
            encoding="utf-8",
        ) as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        want = charm.JUJU_HEADER + "abuse@mydomain.local sysadmin@mydomain.local" + "\n"
        with open(postfix_virtual_alias_maps, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_virtual_alias_maps_type(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["virtual_alias_maps"] = (
            "abuse@mydomain.local sysadmin@mydomain.local"
        )
        self.mock_config.return_value["virtual_alias_maps_type"] = "regexp"
        charm.configure_smtp_relay(self.tmpdir)
        with open(
            "tests/unit/files/postfix_main_transport_maps_with_virtual_alias_maps_type.cf",
            "r",
            encoding="utf-8",
        ) as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_append_x_envelope_to(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["append_x_envelope_to"] = True
        charm.configure_smtp_relay(self.tmpdir)
        with open(
            "tests/unit/files/postfix_main_append_x_envelope_to.cf", "r", encoding="utf-8"
        ) as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_spf(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        postfix_master_cf = os.path.join(self.tmpdir, "master.cf")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["enable_spf"] = True
        charm.configure_smtp_relay(self.tmpdir)
        with open("tests/unit/files/postfix_main_spf.cf", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        with open("tests/unit/files/postfix_master_spf.cf", "r", encoding="utf-8") as f:
            want = f.read()
        with open(postfix_master_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_policyd_spf(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        policyd_spf_config = os.path.join(self.tmpdir, "policyd-spf.conf")
        self.mock_config.return_value["enable_spf"] = True
        charm.configure_policyd_spf(policyd_spf_config)
        with open("tests/unit/files/policyd_spf_config", "r", encoding="utf-8") as f:
            want = f.read()
        with open(policyd_spf_config, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

        want = [mock.call("smtp-relay.policyd-spf.configured")]
        set_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

        want = [mock.call("smtp-relay.active")]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_policyd_spf_disabled(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        policyd_spf_config = os.path.join(self.tmpdir, "policyd-spf.conf")
        self.mock_config.return_value["enable_spf"] = False
        charm.configure_policyd_spf(policyd_spf_config)
        self.assertFalse(os.path.exists(policyd_spf_config))

        want = [mock.call("smtp-relay.policyd-spf.configured")]
        set_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

        want = [mock.call("smtp-relay.active")]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_policyd_spf_skip_addresses(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        policyd_spf_config = os.path.join(self.tmpdir, "policyd-spf.conf")
        self.mock_config.return_value["enable_spf"] = True
        self.mock_config.return_value["spf_skip_addresses"] = "10.0.114.0/24,10.1.1.0/24"
        charm.configure_policyd_spf(policyd_spf_config)
        with open(
            "tests/unit/files/policyd_spf_config_skip_addresses", "r", encoding="utf-8"
        ) as f:
            want = f.read()
        with open(policyd_spf_config, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_config_spf_with_restrict_senders(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, "main.cf")
        get_cn.return_value = ""
        get_milters.return_value = ""
        self.mock_config.return_value["enable_spf"] = True
        self.mock_config.return_value["restrict_senders"] = "noreply@mydomain.local  OK"
        charm.configure_smtp_relay(self.tmpdir)
        with open(
            "tests/unit/files/postfix_main_spf_with_restrict_senders.cf", "r", encoding="utf-8"
        ) as f:
            want = f.read()
        with open(postfix_main_cf, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch("charms.reactive.clear_flag")
    @mock.patch("charms.reactive.set_flag")
    @mock.patch("reactive.charm._get_autocert_cn")
    @mock.patch("reactive.charm._get_milters")
    @mock.patch("reactive.charm._update_aliases")
    @mock.patch("utils.write_file")
    @mock.patch("subprocess.call")
    def test_configure_smtp_relay_flags(
        self, call, write_file, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        get_milters.return_value = ""
        charm.configure_smtp_relay(self.tmpdir)

        want = [mock.call("smtp-relay.configured")]
        set_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(set_flag.mock_calls))

        want = [mock.call("smtp-relay.active")]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    def test__calculate_offset(self):
        self.assertEqual(33, charm._calculate_offset("smtp-relay"))

        self.assertEqual(153, charm._calculate_offset("smtp-relay-canonical"))
        self.assertEqual(146, charm._calculate_offset("smtp-relay-internal"))

        self.assertEqual(8607, charm._calculate_offset("smtp-relay", 4))

    def test__get_autocert_cn(self):
        autocert_conf_dir = os.path.join(self.tmpdir, "autocert")
        want = ""
        self.assertEqual(want, charm._get_autocert_cn(autocert_conf_dir))

        autocert_conf_dir = os.path.join(self.tmpdir, "autocert")
        autocert_conf = os.path.join(autocert_conf_dir, "smtp.mydomain.local.ini")
        os.mkdir(autocert_conf_dir)
        with open(autocert_conf, "a"):
            os.utime(autocert_conf, None)
        want = "smtp.mydomain.local"
        self.assertEqual(want, charm._get_autocert_cn(autocert_conf_dir))

    def test__get_autocert_cn_multiple_files(self):
        autocert_conf_dir = os.path.join(self.tmpdir, "autocert")
        os.mkdir(autocert_conf_dir)
        files = ["abc", "smtp.mydomain.local.ini", "zzz.mydomain.local.ini"]
        for fn in files:
            fff = os.path.join(autocert_conf_dir, fn)
            with open(fff, "a"):
                os.utime(fff, None)
        want = "smtp.mydomain.local"
        self.assertEqual(want, charm._get_autocert_cn(autocert_conf_dir))

    def test__get_autocert_cn_non_exists(self):
        autocert_conf_dir = os.path.join(self.tmpdir, "autocert")
        os.mkdir(autocert_conf_dir)
        want = ""
        self.assertEqual(want, charm._get_autocert_cn(autocert_conf_dir))

    def test__generate_fqdn(self):
        want = "smtp-relay-0.mydomain.local"
        self.assertEqual(want, charm._generate_fqdn("mydomain.local"))

    @mock.patch("charmhelpers.core.hookenv.related_units")
    @mock.patch("charmhelpers.core.hookenv.relation_ids")
    def test__get_peers(self, relation_ids, related_units):
        relation_ids.return_value = ["peer:53"]
        related_units.return_value = ["smtp-relay/3", "smtp-relay/4"]
        want = ["smtp-relay/0", "smtp-relay/3", "smtp-relay/4"]
        self.assertEqual(want, charm._get_peers())
        relation_ids.assert_called_with("peer")
        related_units.assert_called_with("peer:53")

    @mock.patch("charmhelpers.core.hookenv.related_units")
    @mock.patch("charmhelpers.core.hookenv.relation_ids")
    def test__get_peers_no_peer_relation(self, relation_ids, related_units):
        relation_ids.return_value = []
        want = ["smtp-relay/0"]
        self.assertEqual(want, charm._get_peers())
        relation_ids.assert_called_with("peer")
        related_units.assert_not_called()

    @mock.patch("charmhelpers.core.hookenv.related_units")
    @mock.patch("charmhelpers.core.hookenv.relation_ids")
    def test__get_peers_no_peers(self, relation_ids, related_units):
        relation_ids.return_value = ["peer:53"]
        related_units.return_value = []
        want = ["smtp-relay/0"]
        self.assertEqual(want, charm._get_peers())
        relation_ids.assert_called_with("peer")
        related_units.assert_called_with("peer:53")

    @mock.patch("charmhelpers.core.hookenv.related_units")
    @mock.patch("charmhelpers.core.hookenv.relation_ids")
    def test__get_peers_single_peer(self, relation_ids, related_units):
        relation_ids.return_value = ["peer:53"]
        related_units.return_value = ["smtp-relay/1"]
        want = ["smtp-relay/0", "smtp-relay/1"]
        self.assertEqual(want, charm._get_peers())
        relation_ids.assert_called_with("peer")
        related_units.assert_called_with("peer:53")

    @mock.patch("charmhelpers.core.hookenv.related_units")
    @mock.patch("charmhelpers.core.hookenv.relation_ids")
    def test__get_peers_single_sorted(self, relation_ids, related_units):
        relation_ids.return_value = ["peer:53"]
        related_units.return_value = ["smtp-relay/4", "smtp-relay/3", "smtp-relay/2"]
        want = ["smtp-relay/0", "smtp-relay/2", "smtp-relay/3", "smtp-relay/4"]
        self.assertEqual(want, charm._get_peers())
        relation_ids.assert_called_with("peer")
        related_units.assert_called_with("peer:53")

    @mock.patch("charmhelpers.core.hookenv.related_units")
    @mock.patch("charmhelpers.core.hookenv.relation_ids")
    def test__get_peers_duplicates(self, relation_ids, related_units):
        # Duplicate, shouldn't happen but just in case.
        relation_ids.return_value = ["peer:53"]
        related_units.return_value = ["smtp-relay/0", "smtp-relay/4"]
        want = ["smtp-relay/0", "smtp-relay/4"]
        self.assertEqual(want, charm._get_peers())

    @mock.patch("charmhelpers.core.hookenv.related_units")
    @mock.patch("charmhelpers.core.hookenv.relation_get")
    @mock.patch("charmhelpers.core.hookenv.relation_ids")
    @mock.patch("reactive.charm._get_peers")
    def test__get_milters(self, get_peers, relation_ids, relation_get, related_units):
        get_peers.return_value = ["smtp-relay/0", "smtp-relay/1"]
        relation_ids.return_value = ["milter:54"]
        related_units.return_value = ["smtp-dkim-signing-charm/1", "smtp-dkim-signing-charm/4"]
        relation_get.return_value = {
            "ingress-address": "10.48.129.221",
            "port": 8892,
        }
        want = "inet:10.48.129.221:8892"
        self.assertEqual(want, charm._get_milters())
        relation_ids.assert_called_with("milter")
        related_units.assert_called_with("milter:54")
        relation_get.assert_called_with(rid="milter:54", unit="smtp-dkim-signing-charm/4")

    @mock.patch("charmhelpers.core.hookenv.related_units")
    @mock.patch("charmhelpers.core.hookenv.relation_get")
    @mock.patch("charmhelpers.core.hookenv.relation_ids")
    @mock.patch("reactive.charm._get_peers")
    def test__get_milters_multiple(self, get_peers, relation_ids, relation_get, related_units):
        get_peers.return_value = ["smtp-relay/0", "smtp-relay/1"]
        relation_ids.return_value = ["milter:54", "milter:55"]
        related_units.return_value = ["smtp-dkim-signing-charm/1", "smtp-dkim-signing-charm/4"]
        relation_get.return_value = {
            "ingress-address": "10.48.129.221",
            "port": 8892,
        }
        want = "inet:10.48.129.221:8892 inet:10.48.129.221:8892"
        self.assertEqual(want, charm._get_milters())
        relation_ids.assert_called_with("milter")
        want = [mock.call("milter:54"), mock.call("milter:55")]
        related_units.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(related_units.mock_calls))
        want = [
            mock.call(rid="milter:54", unit="smtp-dkim-signing-charm/4"),
            mock.call(rid="milter:55", unit="smtp-dkim-signing-charm/4"),
        ]
        relation_get.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(relation_get.mock_calls))

    @mock.patch("charmhelpers.core.hookenv.related_units")
    @mock.patch("charmhelpers.core.hookenv.relation_get")
    @mock.patch("charmhelpers.core.hookenv.relation_ids")
    @mock.patch("reactive.charm._calculate_offset")
    @mock.patch("reactive.charm._get_peers")
    def test__get_milters_map_offset(
        self, get_peers, calculate_offset, relation_ids, relation_get, related_units
    ):
        calculate_offset.return_value = 1
        get_peers.return_value = ["smtp-relay/0", "smtp-relay/1"]
        relation_ids.return_value = ["milter:54"]
        related_units.return_value = [
            "smtp-dkim-signing-charm/1",
            "smtp-dkim-signing-charm/2",
            "smtp-dkim-signing-charm/3",
        ]
        charm._get_milters()
        relation_get.assert_called_with(rid="milter:54", unit="smtp-dkim-signing-charm/2")

    @mock.patch("charmhelpers.core.hookenv.related_units")
    @mock.patch("charmhelpers.core.hookenv.relation_get")
    @mock.patch("charmhelpers.core.hookenv.relation_ids")
    @mock.patch("reactive.charm._get_peers")
    def test__get_milters_map_second(self, get_peers, relation_ids, relation_get, related_units):
        self.mock_local_unit.return_value = "smtp-relay/1"
        get_peers.return_value = ["smtp-relay/0", "smtp-relay/1"]
        relation_ids.return_value = ["milter:54"]
        related_units.return_value = ["smtp-dkim-signing-charm/1", "smtp-dkim-signing-charm/4"]
        charm._get_milters()
        relation_get.assert_called_with(rid="milter:54", unit="smtp-dkim-signing-charm/1")

    @mock.patch("charmhelpers.core.hookenv.related_units")
    @mock.patch("charmhelpers.core.hookenv.relation_get")
    @mock.patch("charmhelpers.core.hookenv.relation_ids")
    @mock.patch("reactive.charm._get_peers")
    def test__get_milters_map_wrap_around(
        self, get_peers, relation_ids, relation_get, related_units
    ):
        self.mock_local_unit.return_value = "smtp-relay/2"
        get_peers.return_value = ["smtp-relay/0", "smtp-relay/1", "smtp-relay/2"]
        relation_ids.return_value = ["milter:54"]
        related_units.return_value = ["smtp-dkim-signing-charm/1", "smtp-dkim-signing-charm/4"]
        charm._get_milters()
        relation_get.assert_called_with(rid="milter:54", unit="smtp-dkim-signing-charm/4")

    @mock.patch("charmhelpers.core.hookenv.related_units")
    @mock.patch("charmhelpers.core.hookenv.relation_get")
    @mock.patch("charmhelpers.core.hookenv.relation_ids")
    @mock.patch("reactive.charm._get_peers")
    def test__get_milters_map_wrap_around_twice(
        self, get_peers, relation_ids, relation_get, related_units
    ):
        self.mock_local_unit.return_value = "smtp-relay/4"
        get_peers.return_value = [
            "smtp-relay/0",
            "smtp-relay/1",
            "smtp-relay/2",
            "smtp-relay/3",
            "smtp-relay/4",
        ]
        relation_ids.return_value = ["milter:54"]
        related_units.return_value = ["smtp-dkim-signing-charm/1", "smtp-dkim-signing-charm/4"]
        charm._get_milters()
        relation_get.assert_called_with(rid="milter:54", unit="smtp-dkim-signing-charm/4")

    @mock.patch("charmhelpers.core.hookenv.related_units")
    @mock.patch("charmhelpers.core.hookenv.relation_get")
    @mock.patch("charmhelpers.core.hookenv.relation_ids")
    @mock.patch("reactive.charm._get_peers")
    def test__get_milters_no_map_milter_units(
        self, get_peers, relation_ids, relation_get, related_units
    ):
        self.mock_local_unit.return_value = "smtp-relay/1"
        get_peers.return_value = ["smtp-relay/0", "smtp-relay/1"]
        relation_ids.return_value = ["milter:54"]
        related_units.return_value = []
        want = ""
        self.assertEqual(want, charm._get_milters())
        relation_get.assert_not_called()

    @mock.patch("charmhelpers.core.hookenv.related_units")
    @mock.patch("charmhelpers.core.hookenv.relation_ids")
    @mock.patch("reactive.charm._get_peers")
    def test__get_milters_no_milter_relation(self, get_peers, relation_ids, related_units):
        get_peers.return_value = ["smtp-relay/0", "smtp-relay/1"]
        want = ""
        self.assertEqual(want, charm._get_milters())
        relation_ids.assert_called_with("milter")

    @mock.patch("charms.reactive.set_flag")
    def test_set_active(self, set_flag):
        charm.set_active()
        status.active.assert_called_once_with("Ready")
        set_flag.assert_called_once_with("smtp-relay.active")

    @mock.patch("charms.reactive.set_flag")
    def test_set_active_revno(self, set_flag):
        # git - 'uax4glw'
        charm.set_active(os.path.join(self.charm_dir, "tests/unit/files/version"))
        status.active.assert_called_once_with("Ready (source version/commit uax4glw)")

    @mock.patch("charms.reactive.set_flag")
    def test_set_active_shortened_revno(self, set_flag):
        charm.set_active(os.path.join(self.charm_dir, "tests/unit/files/version_long"))
        status.active.assert_called_once_with("Ready (source version/commit somerandom…)")

    @mock.patch("charms.reactive.set_flag")
    def test_set_active_dirty_revno(self, set_flag):
        charm.set_active(os.path.join(self.charm_dir, "tests/unit/files/version_dirty"))
        status.active.assert_called_once_with("Ready (source version/commit 38c901f-dirty)")

    @mock.patch("subprocess.call")
    def test__update_aliases(self, call):

        dest = os.path.join(self.tmpdir, "aliases")

        # Empty, does not exist.
        charm._update_aliases("", dest)
        want = "devnull:       /dev/null\n"
        with open(dest, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        call.assert_called_with(["newaliases"])

        # Has something prepopulated, but not devnull.
        call.reset_mock()
        content = "postmaster:    root\n"
        with open(dest, "w") as f:
            f.write(content)
        charm._update_aliases("", dest)
        want = content + "devnull:       /dev/null\n"
        with open(dest, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        call.assert_called_with(["newaliases"])

        # Has devnull, so do nothing and do not call newaliases.
        call.reset_mock()
        content = "postmaster:    root\ndevnull:       /dev/null\n"
        with open(dest, "w") as f:
            f.write(content)
        charm._update_aliases("", dest)
        want = content
        with open(dest, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        call.assert_not_called()

        # Admin email set.
        call.reset_mock()
        content = "postmaster:    root\ndevnull:       /dev/null\n"
        with open(dest, "w") as f:
            f.write(content)
        charm._update_aliases("root@admin.mydomain.local", dest)
        want = """postmaster:    root
devnull:       /dev/null
root:          root@admin.mydomain.local
"""
        with open(dest, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        call.assert_called_with(["newaliases"])

        # Has admin email, so do nothing and do not call newaliases.
        call.reset_mock()
        content = """postmaster:    root
devnull:       /dev/null
root:          root@admin.mydomain.local
"""
        with open(dest, "w") as f:
            f.write(content)
        charm._update_aliases("root@admin.mydomain.local", dest)
        want = content
        with open(dest, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        call.assert_not_called()
