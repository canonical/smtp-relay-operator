# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""SMTP Relay charm unit tests."""

import grp
import os
import pwd
import shutil
import sys
import tempfile
import unittest
from unittest import mock

# We also need to mock up charms.layer so we can run unit tests without having
# to build the charm and pull in layers such as layer-status.
sys.modules['charms.layer'] = mock.MagicMock()

from charms.layer import status  # NOQA: E402
from charmhelpers.core import unitdata  # NOQA: E402

# Add path to where our reactive layer lives and import.
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
from reactive import smtp_relay  # NOQA: E402


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.tmpdir = tempfile.mkdtemp(prefix='charm-unittests-')
        self.addCleanup(shutil.rmtree, self.tmpdir)

        os.environ['UNIT_STATE_DB'] = os.path.join(self.tmpdir, '.unit-state.db')
        unitdata.kv().set('test', {})

        self.charm_dir = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        )

        patcher = mock.patch('charmhelpers.core.hookenv.log')
        self.mock_log = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_log.return_value = ''
        # Also needed for host.write_file()
        patcher = mock.patch('charmhelpers.core.host.log')
        self.mock_log = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_log.return_value = ''

        patcher = mock.patch('charmhelpers.core.hookenv.charm_dir')
        self.mock_charm_dir = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_charm_dir.return_value = self.charm_dir

        patcher = mock.patch('charmhelpers.core.hookenv.application_name')
        self.mock_application_name = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_application_name.return_value = 'smtp-relay'

        patcher = mock.patch('charmhelpers.core.hookenv.local_unit')
        self.mock_local_unit = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_local_unit.return_value = 'smtp-relay/0'

        patcher = mock.patch('charmhelpers.core.hookenv.config')
        self.mock_config = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_config.return_value = {
            'admin_email': '',
            'additional_smtpd_recipient_restrictions': '',
            'allowed_relay_networks': '',
            'append_x_envelope_to': False,
            'connection_limit': 100,
            'domain': '',
            'enable_rate_limits': False,
            'enable_reject_unknown_sender_domain': True,
            'enable_smtp_auth': True,
            'enable_spf': False,
            'header_checks': '',
            'message_size_limit': 61440000,
            'relay_access_sources': '',
            'relay_domains': '',
            'relay_host': '',
            'relay_recipient_maps': '',
            'restrict_recipients': '',
            'restrict_senders': '',
            'restrict_sender_access': '',
            'sender_login_maps': '',
            'smtp_auth_users': '',
            'smtp_header_checks': '',
            'tls_ciphers': 'HIGH',
            'tls_exclude_ciphers': 'aNULL, eNULL, DES, 3DES, MD5, RC4, CAMELLIA',
            'tls_policy_maps': '',
            'tls_protocols': '!SSLv2 !SSLv3',
            'tls_security_level': 'may',
            'transport_maps': '',
            'virtual_alias_domains': '',
            'virtual_alias_maps': '',
            'virtual_alias_maps_type': 'hash',
        }

        patcher = mock.patch('charmhelpers.core.hookenv.close_port')
        self.mock_close_port = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch('charmhelpers.core.hookenv.open_port')
        self.mock_open_port = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch('charmhelpers.core.host.service_reload')
        self.mock_service_reload = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch('charmhelpers.core.host.service_restart')
        self.mock_service_restart = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch('charmhelpers.core.host.service_start')
        self.mock_service_start = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch('charmhelpers.core.host.service_stop')
        self.mock_service_stop = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch('socket.getfqdn')
        self.mock_getfqdn = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_getfqdn.return_value = 'juju-87625f-hloeung-94.openstacklocal'

        patcher = mock.patch('socket.gethostname')
        self.mock_getfqdn = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_getfqdn.return_value = 'juju-87625f-hloeung-94'

        status.active.reset_mock()
        status.blocked.reset_mock()
        status.maintenance.reset_mock()

    @mock.patch('charms.reactive.clear_flag')
    def test_hook_upgrade_charm(self, clear_flag):
        smtp_relay.upgrade_charm()
        status.maintenance.assert_called()

        want = [
            mock.call('smtp-relay.active'),
            mock.call('smtp-relay.auth.configured'),
            mock.call('smtp-relay.configured'),
            mock.call('smtp-relay.installed'),
            mock.call('smtp-relay.rsyslog.configured'),
        ]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch('charms.reactive.set_flag')
    def test_hook_install(self, set_flag):
        smtp_relay.install(self.tmpdir)

        want = [mock.call('smtp-relay.installed')]
        set_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(set_flag.mock_calls))

        with open('files/fgrepmail-logs.py', 'r', encoding='utf-8') as f:
            want = f.read()
        fgrepmail_logs = os.path.join(self.tmpdir, 'fgrepmail-logs')
        with open(fgrepmail_logs, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    def test_hook_relation_peers_flags(self, clear_flag):
        smtp_relay.peer_relation_changed()
        want = [mock.call('smtp-relay.configured')]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch('charms.reactive.clear_flag')
    def test_config_changed(self, clear_flag):
        smtp_relay.config_changed()
        want = [mock.call('smtp-relay.configured')]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('reactive.smtp_relay._write_file')
    def test_update_logrotate(self, write_file, clear_flag):
        self.mock_config.return_value['log_retention'] = 30
        smtp_relay.update_logrotate()
        want = [mock.call('smtp-relay.active')]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))
        write_file.assert_called()

    @mock.patch('charms.reactive.clear_flag')
    def test_config_changed_smtp_auth(self, clear_flag):
        smtp_relay.config_changed_smtp_auth()
        want = [mock.call('smtp-relay.auth.configured')]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch('charms.reactive.clear_flag')
    def test_config_changed_policyd_spf(self, clear_flag):
        smtp_relay.config_changed_policyd_spf()
        want = [mock.call('smtp-relay.policyd-spf.configured')]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch('charms.reactive.clear_flag')
    def test_config_changed_syslog_forwarders(self, clear_flag):
        smtp_relay.config_changed_syslog_forwarders()
        want = [mock.call('smtp-relay.rsyslog.configured')]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch('subprocess.call')
    def test__create_update_map(self, call):
        postfix_relay_access = 'hash:{}'.format(os.path.join(self.tmpdir, 'relay_access'))
        self.assertTrue(smtp_relay._create_update_map('mydomain.local OK', postfix_relay_access))
        want = ['postmap', postfix_relay_access]
        call.assert_called_with(want)
        want = smtp_relay.JUJU_HEADER + 'mydomain.local OK' + '\n'
        with open(os.path.join(self.tmpdir, 'relay_access'), 'r') as f:
            got = f.read()
        self.assertEqual(want, got)

        call.reset_mock()
        self.assertFalse(smtp_relay._create_update_map('mydomain.local OK', postfix_relay_access))
        call.assert_not_called()

    @mock.patch('subprocess.call')
    def test__create_update_map_eno_content(self, call):
        postfix_relay_access = 'hash:{}'.format(os.path.join(self.tmpdir, 'relay_access'))
        self.assertTrue(smtp_relay._create_update_map('', postfix_relay_access))
        want = ['postmap', postfix_relay_access]
        call.assert_called_with(want)

        call.reset_mock()
        smtp_relay._create_update_map('', postfix_relay_access)
        call.assert_not_called()

    @mock.patch('reactive.smtp_relay._write_file')
    @mock.patch('subprocess.call')
    def test__create_update_map_manual(self, call, write_file):
        postfix_relay_access = 'hash:{}'.format(os.path.join(self.tmpdir, 'relay_access'))
        self.assertTrue(smtp_relay._create_update_map('MANUAL', postfix_relay_access))
        want = ['postmap', postfix_relay_access]
        call.assert_called_with(want)
        write_file.assert_not_called()

        call.reset_mock()
        write_file.reset_mock()
        smtp_relay._create_update_map('MANUAL', postfix_relay_access)
        call.assert_not_called()
        write_file.assert_not_called()

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('subprocess.call')
    def test_configure_smtp_auth_relay(self, call, set_flag, clear_flag):
        dovecot_config = os.path.join(self.tmpdir, 'dovecot.conf')

        self.mock_config.return_value['enable_smtp_auth'] = True
        smtp_relay.configure_smtp_auth(dovecot_config)
        self.mock_service_reload.assert_called_with('dovecot')
        # Try again, no change so no need for dovecot to be reloaded.
        self.mock_service_reload.reset_mock()
        call.reset_mock()
        smtp_relay.configure_smtp_auth(dovecot_config)
        self.mock_service_reload.assert_not_called()
        self.mock_service_start.assert_called()
        call.assert_not_called()

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('subprocess.call')
    def test_configure_smtp_auth_relay_config(self, call, set_flag, clear_flag):
        dovecot_config = os.path.join(self.tmpdir, 'dovecot.conf')

        self.mock_config.return_value['enable_smtp_auth'] = True
        smtp_relay.configure_smtp_auth(dovecot_config)
        with open('tests/unit/files/dovecot_config', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(dovecot_config, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('subprocess.call')
    def test_configure_smtp_auth_relay_config_auth_disabled(self, call, set_flag, clear_flag):
        dovecot_config = os.path.join(self.tmpdir, 'dovecot.conf')

        self.mock_config.return_value['enable_smtp_auth'] = True
        smtp_relay.configure_smtp_auth(dovecot_config)
        self.mock_config.return_value['enable_smtp_auth'] = False
        smtp_relay.configure_smtp_auth(dovecot_config)
        with open('tests/unit/files/dovecot_config_auth_disabled', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(dovecot_config, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        self.mock_service_stop.assert_called()

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('grp.getgrnam')
    @mock.patch('os.fchown')
    @mock.patch('subprocess.call')
    def test_configure_smtp_auth_relay_config_auth_users(
        self, call, fchown, getgrnam, set_flag, clear_flag
    ):
        dovecot_config = os.path.join(self.tmpdir, 'dovecot.conf')
        dovecot_users = os.path.join(self.tmpdir, 'dovecot_users')
        self.mock_config.return_value[
            'smtp_auth_users'
        ] = (
            "myuser1:$1$bPb0IPiM$kmrSMZkZvICKKHXu66daQ.\n"
            'myuser2:$6$3rGBbaMbEiGhnGKz$KLGFv8kDTjqa3xeUgA6A1Rie1zGSf3sLT85vF1s59Yj'
            '//F36qLB/J8rUfIIndaDtkxeb5iR3gs1uBn9fNyJDD1'
        )
        smtp_relay.configure_smtp_auth(dovecot_config, dovecot_users)
        with open('tests/unit/files/dovecot_users', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(dovecot_users, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._write_file')
    @mock.patch('subprocess.call')
    def test_configure_smtp_auth_relay_config_auth_users_manual(
        self, call, write_file, set_flag, clear_flag
    ):
        dovecot_config = os.path.join(self.tmpdir, 'dovecot.conf')
        dovecot_users = os.path.join(self.tmpdir, 'dovecot_users')

        self.mock_config.return_value['smtp_auth_users'] = 'MANUAL'
        smtp_relay.configure_smtp_auth(dovecot_config, dovecot_users)
        self.assertFalse(os.path.exists(dovecot_users))
        self.assertEqual(3, len(write_file.mock_calls))

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._write_file')
    def test_configure_smtp_auth_relay_flags(self, write_file, set_flag, clear_flag):
        self.mock_config.return_value['enable_smtp_auth'] = True
        smtp_relay.configure_smtp_auth()

        want = [mock.call('smtp-relay.auth.configured')]
        set_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(set_flag.mock_calls))

        want = [mock.call('smtp-relay.active'), mock.call('smtp-relay.configured')]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    def test_configure_smtp_auth_relay_flags_auth_disabled(self, set_flag, clear_flag):
        dovecot_config = os.path.join(self.tmpdir, 'dovecot.conf')

        self.mock_config.return_value['enable_smtp_auth'] = False
        smtp_relay.configure_smtp_auth(dovecot_config)

        want = [mock.call('smtp-relay.auth.configured')]
        set_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(set_flag.mock_calls))

        want = [mock.call('smtp-relay.active'), mock.call('smtp-relay.configured')]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._write_file')
    def test_configure_smtp_auth_relay_ports(self, write_file, set_flag, clear_flag):
        self.mock_config.return_value['enable_smtp_auth'] = True
        smtp_relay.configure_smtp_auth()

        want = [mock.call(465, 'TCP'), mock.call(587, 'TCP')]
        self.mock_open_port.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(self.mock_open_port.mock_calls))

        self.mock_close_port.assert_not_called()

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    def test_configure_smtp_auth_relay_ports_auth_disabled(self, set_flag, clear_flag):
        dovecot_config = os.path.join(self.tmpdir, 'dovecot.conf')

        self.mock_config.return_value['enable_smtp_auth'] = False
        smtp_relay.configure_smtp_auth(dovecot_config)

        want = [mock.call(465, 'TCP'), mock.call(587, 'TCP')]
        self.mock_close_port.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(self.mock_close_port.mock_calls))

        self.mock_open_port.assert_not_called()

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    def test_hook_relation_milter_flags(self, set_flag, clear_flag):
        smtp_relay.milter_relation_changed()

        want = [mock.call('smtp-relay.configured')]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

        set_flag.assert_not_called()

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        get_cn.return_value = ''
        get_milters.return_value = ''
        smtp_relay.configure_smtp_relay(self.tmpdir)
        self.mock_service_reload.assert_called_with('postfix')
        want = [mock.call(25, 'TCP')]
        self.mock_open_port.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(self.mock_open_port.mock_calls))
        # Try again, no change so no need for postfix to be reloaded.
        self.mock_service_reload.reset_mock()
        self.mock_open_port.reset_mock()
        smtp_relay.configure_smtp_relay(self.tmpdir)
        self.mock_service_reload.assert_not_called()
        self.mock_service_start.assert_called()

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        postfix_master_cf = os.path.join(self.tmpdir, 'master.cf')
        get_cn.return_value = ''
        get_milters.return_value = ''
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open('tests/unit/files/postfix_main.cf', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        with open('tests/unit/files/postfix_master.cf', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_master_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_auth_disabled(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        postfix_master_cf = os.path.join(self.tmpdir, 'master.cf')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['enable_smtp_auth'] = False
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open('tests/unit/files/postfix_main_auth_disabled.cf', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        with open('tests/unit/files/postfix_master_auth_disabled.cf', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_master_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_auth_sender_login_maps(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['enable_smtp_auth'] = True
        self.mock_config.return_value['sender_login_maps'] = 'MANUAL'
        self.mock_config.return_value['smtp_auth_users'] = 'MANUAL'
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_auth_sender_login_maps.cf', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_domain(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['domain'] = 'mydomain.local'
        self.mock_config.return_value['enable_smtp_auth'] = False
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open('tests/unit/files/postfix_main_domain.cf', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_with_milter(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        get_cn.return_value = ''
        get_milters.return_value = 'inet:10.48.129.221:8892'
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open('tests/unit/files/postfix_main_with_milter.cf', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_with_milter_auth_disabled(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        get_cn.return_value = ''
        get_milters.return_value = 'inet:10.48.129.221:8892'
        self.mock_config.return_value['enable_smtp_auth'] = False
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_with_milter_auth_disabled.cf', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_tls_cert_key(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        get_cn.return_value = 'smtp.mydomain.local'
        get_milters.return_value = ''
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open('tests/unit/files/postfix_main_tls_cert_key.cf', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_tls_no_ciphers_and_protocols(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['tls_ciphers'] = ''
        self.mock_config.return_value['tls_exclude_ciphers'] = ''
        self.mock_config.return_value['tls_protocols'] = ''
        self.mock_config.return_value['tls_security_level'] = ''
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_tls_no_ciphers_and_protocols.cf', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._create_update_map')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('reactive.smtp_relay._write_file')
    @mock.patch('subprocess.call')
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
        dhparams = os.path.join(self.tmpdir, 'dhparams.pem')
        get_cn.return_value = ''
        get_milters.return_value = ''
        smtp_relay.configure_smtp_relay(self.tmpdir, dhparams)
        want = [mock.call(['openssl', 'dhparam', '-out', dhparams, '2048'])]
        call.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(call.mock_calls))

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._create_update_map')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('reactive.smtp_relay._write_file')
    @mock.patch('subprocess.call')
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
        dhparams = os.path.join(self.tmpdir, 'dhparams.pem')
        with open(dhparams, 'a'):
            os.utime(dhparams, None)
        get_cn.return_value = ''
        get_milters.return_value = ''
        smtp_relay.configure_smtp_relay(self.tmpdir, dhparams)
        create_update_map.assert_called()

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_rate_limits(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['enable_rate_limits'] = True
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open('tests/unit/files/postfix_main_rate_limits.cf', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_rate_limits_auth_disabled(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['enable_rate_limits'] = True
        self.mock_config.return_value['enable_smtp_auth'] = False
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_rate_limits_auth_disabled.cf', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_header_checks(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        postfix_header_checks = os.path.join(self.tmpdir, 'header_checks')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['header_checks'] = '/^Received:/ HOLD'
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open('tests/unit/files/postfix_main_header_checks.cf', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        want = smtp_relay.JUJU_HEADER + '/^Received:/ HOLD' + "\n"
        with open(postfix_header_checks, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_smtp_header_checks(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        postfix_smtp_header_checks = os.path.join(self.tmpdir, 'smtp_header_checks')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['smtp_header_checks'] = '/^Received:/ HOLD'
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_smtp_header_checks.cf', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        want = smtp_relay.JUJU_HEADER + '/^Received:/ HOLD' + "\n"
        with open(postfix_smtp_header_checks, 'r', encoding='utf-8') as f:
            got = f.read()

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_reject_unknown_sender_domain(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['enable_reject_unknown_sender_domain'] = False
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_reject_unknown_sender_domain.cf', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_relay_access_sources(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        postfix_relay_access = os.path.join(self.tmpdir, 'relay_access')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value[
            'relay_access_sources'
        ] = """# Reject some made user.
10.10.10.5    REJECT
10.10.10.0/24 OK
"""
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_relay_access_sources.cf', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        with open(
            'tests/unit/files/relay_access_relay_access_sources', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        with open(postfix_relay_access, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_relay_access_sources_auth_disabled(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        postfix_relay_access = os.path.join(self.tmpdir, 'relay_access')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value[
            'relay_access_sources'
        ] = """# Reject some made user.
10.10.10.5    REJECT
10.10.10.0/24 OK
"""
        self.mock_config.return_value['enable_smtp_auth'] = False
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_relay_access_sources_auth_disabled.cf',
            'r',
            encoding='utf-8',
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        with open(
            'tests/unit/files/relay_access_relay_access_sources', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        with open(postfix_relay_access, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_restrict_both_senders_and_recpients(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['restrict_recipients'] = 'mydomain.local  OK'
        self.mock_config.return_value['restrict_senders'] = 'noreply@mydomain.local  OK'
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_restrict_both_senders_and_recipients.cf',
            'r',
            encoding='utf-8',
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_restrict_recpients(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        postfix_restricted_recipients = os.path.join(self.tmpdir, 'restricted_recipients')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['restrict_recipients'] = 'mydomain.local  OK'
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_restrict_recipients.cf', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        with open('tests/unit/files/restricted_recipients', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_restricted_recipients, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_restrict_senders(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        postfix_restricted_senders = os.path.join(self.tmpdir, 'restricted_senders')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['restrict_senders'] = 'noreply@mydomain.local  OK'
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open('tests/unit/files/postfix_main_restrict_senders.cf', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        with open('tests/unit/files/restricted_senders', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_restricted_senders, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_restrict_sender_access(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        postfix_access = os.path.join(self.tmpdir, 'access')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['restrict_sender_access'] = (
            ' canonical.com ubuntu.com,mydomain.local mydomain2.local'
        )
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_restrict_sender_access.cf', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        with open('tests/unit/files/access_restrict_sender_access', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_access, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_restrict_sender_manual(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        postfix_access = os.path.join(self.tmpdir, 'access')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['restrict_sender_access'] = 'MANUAL'
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_restrict_sender_access.cf', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        want = ''
        with open(postfix_access, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_restrict_sender_access_reset(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_access = os.path.join(self.tmpdir, 'access')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['restrict_sender_access'] = (
            ' canonical.com ubuntu.com,mydomain.local mydomain2.local'
        )
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open('tests/unit/files/access_restrict_sender_access', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_access, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

        self.mock_config.return_value['restrict_sender_access'] = ''
        smtp_relay.configure_smtp_relay(self.tmpdir)
        want = smtp_relay.JUJU_HEADER + "\n"
        with open(postfix_access, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_tls_policy_map(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        postfix_tls_policy_map = os.path.join(self.tmpdir, 'tls_policy')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value[
            'tls_policy_maps'
        ] = """# Google hosted
gapps.mydomain.local secure match=mx.google.com
# Some place enforce encryption
someplace.local encrypt
.someplace.local encrypt
"""
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open('tests/unit/files/postfix_main_tls_policy.cf', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        with open('tests/unit/files/tls_policy', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_tls_policy_map, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_relay_domains(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['relay_domains'] = 'mydomain.local mydomain2.local'
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open('tests/unit/files/postfix_main_relay_domains.cf', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_relay_domains_with_relay_recipient_maps(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        postfix_relay_recipient_maps = os.path.join(self.tmpdir, 'relay_recipient')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['relay_domains'] = 'mydomain.local mydomain2.local'
        self.mock_config.return_value['relay_recipient_maps'] = (
            'noreply@mydomain.local noreply@mydomain.local'
        )
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_relay_domains_with_relay_recipient_maps.cf',
            'r',
            encoding='utf-8',
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        want = smtp_relay.JUJU_HEADER + 'noreply@mydomain.local noreply@mydomain.local' + "\n"
        with open(postfix_relay_recipient_maps, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_relay_domains_with_relay_recipient_maps_manual(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        postfix_relay_recipient_maps = os.path.join(self.tmpdir, 'relay_recipient')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['relay_domains'] = 'mydomain.local mydomain2.local'
        self.mock_config.return_value['relay_recipient_maps'] = 'MANUAL'
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_relay_domains_with_relay_recipient_maps.cf',
            'r',
            encoding='utf-8',
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        want = ''
        with open(postfix_relay_recipient_maps, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_relay_domains_with_relay_recipient_maps_combined(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        postfix_relay_recipient_maps = os.path.join(self.tmpdir, 'relay_recipient')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['relay_domains'] = 'mydomain.local mydomain2.local'
        self.mock_config.return_value['relay_recipient_maps'] = 'COMBINED'
        self.mock_config.return_value['transport_maps'] = (
            '.mydomain.local  smtp:[smtp.mydomain.local]'
        )
        self.mock_config.return_value['virtual_alias_maps'] = (
            'abuse@mydomain.local sysadmin@mydomain.local'
        )
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_relay_domains_with_relay_recipient_maps_combined.cf',
            'r',
            encoding='utf-8',
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        want = ''
        with open(postfix_relay_recipient_maps, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_transport_maps(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        postfix_transport_maps = os.path.join(self.tmpdir, 'transport')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['transport_maps'] = (
            '.mydomain.local  smtp:[smtp.mydomain.local]'
        )
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open('tests/unit/files/postfix_main_transport_maps.cf', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        want = smtp_relay.JUJU_HEADER + '.mydomain.local  smtp:[smtp.mydomain.local]' + "\n"
        with open(postfix_transport_maps, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_transport_maps_with_header_checks(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        postfix_transport_maps = os.path.join(self.tmpdir, 'transport')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['header_checks'] = '/^Received:/ HOLD'
        self.mock_config.return_value['transport_maps'] = (
            '.mydomain.local  smtp:[smtp.mydomain.local]'
        )
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_transport_maps_with_header_checks.cf',
            'r',
            encoding='utf-8',
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        want = smtp_relay.JUJU_HEADER + '.mydomain.local  smtp:[smtp.mydomain.local]' + "\n"
        with open(postfix_transport_maps, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_transport_maps_with_virtual_alias_maps(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        postfix_virtual_alias_maps = os.path.join(self.tmpdir, 'virtual_alias')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['relay_domains'] = 'mydomain.local mydomain2.local'
        self.mock_config.return_value['transport_maps'] = (
            '.mydomain.local  smtp:[smtp.mydomain.local]'
        )
        self.mock_config.return_value['virtual_alias_domains'] = 'mydomain.local mydomain2.local'
        self.mock_config.return_value['virtual_alias_maps'] = (
            'abuse@mydomain.local sysadmin@mydomain.local'
        )
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_transport_maps_with_virtual_alias_maps.cf',
            'r',
            encoding='utf-8',
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        want = smtp_relay.JUJU_HEADER + 'abuse@mydomain.local sysadmin@mydomain.local' + "\n"
        with open(postfix_virtual_alias_maps, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_virtual_alias_maps_type(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['virtual_alias_maps'] = (
            'abuse@mydomain.local sysadmin@mydomain.local'
        )
        self.mock_config.return_value['virtual_alias_maps_type'] = 'regexp'
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_transport_maps_with_virtual_alias_maps_type.cf',
            'r',
            encoding='utf-8',
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_append_x_envelope_to(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['append_x_envelope_to'] = True
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_append_x_envelope_to.cf', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_spf(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        postfix_master_cf = os.path.join(self.tmpdir, 'master.cf')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['enable_spf'] = True
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open('tests/unit/files/postfix_main_spf.cf', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        with open('tests/unit/files/postfix_master_spf.cf', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(postfix_master_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_policyd_spf(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        policyd_spf_config = os.path.join(self.tmpdir, 'policyd-spf.conf')
        self.mock_config.return_value['enable_spf'] = True
        self.mock_config.return_value['spf_skip_addresses'] = ''
        smtp_relay.configure_policyd_spf(policyd_spf_config)
        with open('tests/unit/files/policyd_spf_config', 'r', encoding='utf-8') as f:
            want = f.read()
        with open(policyd_spf_config, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

        want = [mock.call('smtp-relay.policyd-spf.configured')]
        set_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

        want = [mock.call('smtp-relay.active')]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_policyd_spf_disabled(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        policyd_spf_config = os.path.join(self.tmpdir, 'policyd-spf.conf')
        self.mock_config.return_value['enable_spf'] = False
        self.mock_config.return_value['spf_skip_addresses'] = ''
        smtp_relay.configure_policyd_spf(policyd_spf_config)
        self.assertFalse(os.path.exists(policyd_spf_config))

        want = [mock.call('smtp-relay.policyd-spf.configured')]
        set_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

        want = [mock.call('smtp-relay.active')]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_policyd_spf_skip_addresses(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        policyd_spf_config = os.path.join(self.tmpdir, 'policyd-spf.conf')
        self.mock_config.return_value['enable_spf'] = True
        self.mock_config.return_value['spf_skip_addresses'] = '10.0.114.0/24,10.1.1.0/24'
        smtp_relay.configure_policyd_spf(policyd_spf_config)
        with open(
            'tests/unit/files/policyd_spf_config_skip_addresses', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        with open(policyd_spf_config, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_config_spf_with_restrict_senders(
        self, call, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        postfix_main_cf = os.path.join(self.tmpdir, 'main.cf')
        get_cn.return_value = ''
        get_milters.return_value = ''
        self.mock_config.return_value['enable_spf'] = True
        self.mock_config.return_value['restrict_senders'] = 'noreply@mydomain.local  OK'
        smtp_relay.configure_smtp_relay(self.tmpdir)
        with open(
            'tests/unit/files/postfix_main_spf_with_restrict_senders.cf', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        with open(postfix_main_cf, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.set_flag')
    def test_configure_syslog_forwarders(self, set_flag):
        self.mock_config.return_value[
            'syslog_forwarders'
        ] = 'myunit/0:192.0.2.1, myunit/1:192.0.2.2'
        smtp_relay.configure_syslog_forwarders(self.tmpdir)
        want = [
            mock.call('Setting up syslog forwarders'),
            mock.call('Restarting rsyslog due to config changes'),
        ]
        status.maintenance.assert_has_calls(want, any_order=True)
        self.mock_service_restart.assert_called_with('rsyslog')
        want = [mock.call('smtp-relay.rsyslog.configured')]
        set_flag.assert_has_calls(want, any_order=True)

        with open(
            'tests/unit/files/rsyslog-45-rsyslog-replication.conf', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        dest = os.path.join(self.tmpdir, '45-rsyslog-replication.conf')
        with open(dest, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

        # Call again, no change.
        status.maintenance.reset_mock()
        self.mock_service_restart.reset_mock()
        smtp_relay.configure_syslog_forwarders(self.tmpdir)
        want = [mock.call('Setting up syslog forwarders')]
        status.maintenance.assert_has_calls(want, any_order=True)
        self.mock_service_restart.assert_not_called()

        # Various combinations.
        self.mock_config.return_value[
            'syslog_forwarders'
        ] = 'myunit/0:192.0.2.1,myunit/1:192.0.2.2'
        smtp_relay.configure_syslog_forwarders(self.tmpdir)
        with open(
            'tests/unit/files/rsyslog-45-rsyslog-replication.conf', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        dest = os.path.join(self.tmpdir, '45-rsyslog-replication.conf')
        with open(dest, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        self.mock_config.return_value[
            'syslog_forwarders'
        ] = 'myunit/0:192.0.2.1,  myunit/1:192.0.2.2'
        smtp_relay.configure_syslog_forwarders(self.tmpdir)
        with open(
            'tests/unit/files/rsyslog-45-rsyslog-replication.conf', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        dest = os.path.join(self.tmpdir, '45-rsyslog-replication.conf')
        with open(dest, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        self.mock_config.return_value[
            'syslog_forwarders'
        ] = '  myunit/0:192.0.2.1,	myunit/1:192.0.2.2  '
        smtp_relay.configure_syslog_forwarders(self.tmpdir)
        with open(
            'tests/unit/files/rsyslog-45-rsyslog-replication.conf', 'r', encoding='utf-8'
        ) as f:
            want = f.read()
        dest = os.path.join(self.tmpdir, '45-rsyslog-replication.conf')
        with open(dest, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.set_flag')
    def test_configure_syslog_forwarders_disabled(self, set_flag):
        self.mock_config.return_value['syslog_forwarders'] = ''
        smtp_relay.configure_syslog_forwarders(self.tmpdir)
        status.maintenance.assert_not_called()
        self.mock_service_restart.assert_not_called()
        want = [mock.call('smtp-relay.rsyslog.configured')]
        set_flag.assert_has_calls(want, any_order=True)

        # Was previously enabled.
        dest = os.path.join(self.tmpdir, '45-rsyslog-replication.conf')
        with open(dest, 'w') as f:
            f.write('')
        smtp_relay.configure_syslog_forwarders(self.tmpdir)
        status.maintenance.assert_called_with('Disabling syslog forwards')
        self.assertFalse(os.path.exists(dest))
        self.mock_service_restart.assert_called_with('rsyslog')

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('reactive.smtp_relay._get_autocert_cn')
    @mock.patch('reactive.smtp_relay._get_milters')
    @mock.patch('reactive.smtp_relay._update_aliases')
    @mock.patch('reactive.smtp_relay._write_file')
    @mock.patch('subprocess.call')
    def test_configure_smtp_relay_flags(
        self, call, write_file, update_aliases, get_milters, get_cn, set_flag, clear_flag
    ):
        get_milters.return_value = ''
        smtp_relay.configure_smtp_relay(self.tmpdir)

        want = [mock.call('smtp-relay.configured')]
        set_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(set_flag.mock_calls))

        want = [mock.call('smtp-relay.active')]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    def test__calculate_offset(self):
        self.assertEqual(33, smtp_relay._calculate_offset('smtp-relay'))

        self.assertEqual(153, smtp_relay._calculate_offset('smtp-relay-canonical'))
        self.assertEqual(146, smtp_relay._calculate_offset('smtp-relay-internal'))

        self.assertEqual(8607, smtp_relay._calculate_offset('smtp-relay', 4))

    def test__get_autocert_cn(self):
        autocert_conf_dir = os.path.join(self.tmpdir, 'autocert')
        want = ''
        self.assertEqual(want, smtp_relay._get_autocert_cn(autocert_conf_dir))

        autocert_conf_dir = os.path.join(self.tmpdir, 'autocert')
        autocert_conf = os.path.join(autocert_conf_dir, 'smtp.mydomain.local.ini')
        os.mkdir(autocert_conf_dir)
        with open(autocert_conf, 'a'):
            os.utime(autocert_conf, None)
        want = 'smtp.mydomain.local'
        self.assertEqual(want, smtp_relay._get_autocert_cn(autocert_conf_dir))

    def test__get_autocert_cn_multiple_files(self):
        autocert_conf_dir = os.path.join(self.tmpdir, 'autocert')
        os.mkdir(autocert_conf_dir)
        files = ['abc', 'smtp.mydomain.local.ini', 'zzz.mydomain.local.ini']
        for fn in files:
            fff = os.path.join(autocert_conf_dir, fn)
            with open(fff, 'a'):
                os.utime(fff, None)
        want = 'smtp.mydomain.local'
        self.assertEqual(want, smtp_relay._get_autocert_cn(autocert_conf_dir))

    def test__get_autocert_cn_non_exists(self):
        autocert_conf_dir = os.path.join(self.tmpdir, 'autocert')
        os.mkdir(autocert_conf_dir)
        want = ''
        self.assertEqual(want, smtp_relay._get_autocert_cn(autocert_conf_dir))

    def test__generate_fqdn(self):
        want = 'smtp-relay-0.mydomain.local'
        self.assertEqual(want, smtp_relay._generate_fqdn('mydomain.local'))

    @mock.patch('charmhelpers.core.hookenv.related_units')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    def test__get_peers(self, relation_ids, related_units):
        relation_ids.return_value = ['peer:53']
        related_units.return_value = ['smtp-relay/3', 'smtp-relay/4']
        want = ['smtp-relay/0', 'smtp-relay/3', 'smtp-relay/4']
        self.assertEqual(want, smtp_relay._get_peers())
        relation_ids.assert_called_with('peer')
        related_units.assert_called_with('peer:53')

    @mock.patch('charmhelpers.core.hookenv.related_units')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    def test__get_peers_no_peer_relation(self, relation_ids, related_units):
        relation_ids.return_value = []
        want = ['smtp-relay/0']
        self.assertEqual(want, smtp_relay._get_peers())
        relation_ids.assert_called_with('peer')
        related_units.assert_not_called()

    @mock.patch('charmhelpers.core.hookenv.related_units')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    def test__get_peers_no_peers(self, relation_ids, related_units):
        relation_ids.return_value = ['peer:53']
        related_units.return_value = []
        want = ['smtp-relay/0']
        self.assertEqual(want, smtp_relay._get_peers())
        relation_ids.assert_called_with('peer')
        related_units.assert_called_with('peer:53')

    @mock.patch('charmhelpers.core.hookenv.related_units')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    def test__get_peers_single_peer(self, relation_ids, related_units):
        relation_ids.return_value = ['peer:53']
        related_units.return_value = ['smtp-relay/1']
        want = ['smtp-relay/0', 'smtp-relay/1']
        self.assertEqual(want, smtp_relay._get_peers())
        relation_ids.assert_called_with('peer')
        related_units.assert_called_with('peer:53')

    @mock.patch('charmhelpers.core.hookenv.related_units')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    def test__get_peers_single_sorted(self, relation_ids, related_units):
        relation_ids.return_value = ['peer:53']
        related_units.return_value = ['smtp-relay/4', 'smtp-relay/3', 'smtp-relay/2']
        want = ['smtp-relay/0', 'smtp-relay/2', 'smtp-relay/3', 'smtp-relay/4']
        self.assertEqual(want, smtp_relay._get_peers())
        relation_ids.assert_called_with('peer')
        related_units.assert_called_with('peer:53')

    @mock.patch('charmhelpers.core.hookenv.related_units')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    def test__get_peers_duplicates(self, relation_ids, related_units):
        # Duplicate, shouldn't happen but just in case.
        relation_ids.return_value = ['peer:53']
        related_units.return_value = ['smtp-relay/0', 'smtp-relay/4']
        want = ['smtp-relay/0', 'smtp-relay/4']
        self.assertEqual(want, smtp_relay._get_peers())

    @mock.patch('charmhelpers.core.hookenv.related_units')
    @mock.patch('charmhelpers.core.hookenv.relation_get')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('reactive.smtp_relay._get_peers')
    def test__get_milters(self, get_peers, relation_ids, relation_get, related_units):
        get_peers.return_value = ['smtp-relay/0', 'smtp-relay/1']
        relation_ids.return_value = ['milter:54']
        related_units.return_value = ['smtp-dkim-signing-charm/1', 'smtp-dkim-signing-charm/4']
        relation_get.return_value = {
            'ingress-address': '10.48.129.221',
            'port': 8892,
        }
        want = 'inet:10.48.129.221:8892'
        self.assertEqual(want, smtp_relay._get_milters())
        relation_ids.assert_called_with('milter')
        related_units.assert_called_with('milter:54')
        relation_get.assert_called_with(rid='milter:54', unit='smtp-dkim-signing-charm/4')

    @mock.patch('charmhelpers.core.hookenv.related_units')
    @mock.patch('charmhelpers.core.hookenv.relation_get')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('reactive.smtp_relay._get_peers')
    def test__get_milters_multiple(self, get_peers, relation_ids, relation_get, related_units):
        get_peers.return_value = ['smtp-relay/0', 'smtp-relay/1']
        relation_ids.return_value = ['milter:54', 'milter:55']
        related_units.return_value = ['smtp-dkim-signing-charm/1', 'smtp-dkim-signing-charm/4']
        relation_get.return_value = {
            'ingress-address': '10.48.129.221',
            'port': 8892,
        }
        want = 'inet:10.48.129.221:8892 inet:10.48.129.221:8892'
        self.assertEqual(want, smtp_relay._get_milters())
        relation_ids.assert_called_with('milter')
        want = [mock.call('milter:54'), mock.call('milter:55')]
        related_units.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(related_units.mock_calls))
        want = [
            mock.call(rid='milter:54', unit='smtp-dkim-signing-charm/4'),
            mock.call(rid='milter:55', unit='smtp-dkim-signing-charm/4'),
        ]
        relation_get.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(relation_get.mock_calls))

    @mock.patch('charmhelpers.core.hookenv.related_units')
    @mock.patch('charmhelpers.core.hookenv.relation_get')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('reactive.smtp_relay._calculate_offset')
    @mock.patch('reactive.smtp_relay._get_peers')
    def test__get_milters_map_offset(
        self, get_peers, calculate_offset, relation_ids, relation_get, related_units
    ):
        calculate_offset.return_value = 1
        get_peers.return_value = ['smtp-relay/0', 'smtp-relay/1']
        relation_ids.return_value = ['milter:54']
        related_units.return_value = [
            'smtp-dkim-signing-charm/1',
            'smtp-dkim-signing-charm/2',
            'smtp-dkim-signing-charm/3',
        ]
        smtp_relay._get_milters()
        relation_get.assert_called_with(rid='milter:54', unit='smtp-dkim-signing-charm/2')

    @mock.patch('charmhelpers.core.hookenv.related_units')
    @mock.patch('charmhelpers.core.hookenv.relation_get')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('reactive.smtp_relay._get_peers')
    def test__get_milters_map_second(self, get_peers, relation_ids, relation_get, related_units):
        self.mock_local_unit.return_value = 'smtp-relay/1'
        get_peers.return_value = ['smtp-relay/0', 'smtp-relay/1']
        relation_ids.return_value = ['milter:54']
        related_units.return_value = ['smtp-dkim-signing-charm/1', 'smtp-dkim-signing-charm/4']
        smtp_relay._get_milters()
        relation_get.assert_called_with(rid='milter:54', unit='smtp-dkim-signing-charm/1')

    @mock.patch('charmhelpers.core.hookenv.related_units')
    @mock.patch('charmhelpers.core.hookenv.relation_get')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('reactive.smtp_relay._get_peers')
    def test__get_milters_map_wrap_around(
        self, get_peers, relation_ids, relation_get, related_units
    ):
        self.mock_local_unit.return_value = 'smtp-relay/2'
        get_peers.return_value = ['smtp-relay/0', 'smtp-relay/1', 'smtp-relay/2']
        relation_ids.return_value = ['milter:54']
        related_units.return_value = ['smtp-dkim-signing-charm/1', 'smtp-dkim-signing-charm/4']
        smtp_relay._get_milters()
        relation_get.assert_called_with(rid='milter:54', unit='smtp-dkim-signing-charm/4')

    @mock.patch('charmhelpers.core.hookenv.related_units')
    @mock.patch('charmhelpers.core.hookenv.relation_get')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('reactive.smtp_relay._get_peers')
    def test__get_milters_map_wrap_around_twice(
        self, get_peers, relation_ids, relation_get, related_units
    ):
        self.mock_local_unit.return_value = 'smtp-relay/4'
        get_peers.return_value = [
            'smtp-relay/0', 'smtp-relay/1', 'smtp-relay/2', 'smtp-relay/3', 'smtp-relay/4'
        ]
        relation_ids.return_value = ['milter:54']
        related_units.return_value = ['smtp-dkim-signing-charm/1', 'smtp-dkim-signing-charm/4']
        smtp_relay._get_milters()
        relation_get.assert_called_with(rid='milter:54', unit='smtp-dkim-signing-charm/4')

    @mock.patch('charmhelpers.core.hookenv.related_units')
    @mock.patch('charmhelpers.core.hookenv.relation_get')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('reactive.smtp_relay._get_peers')
    def test__get_milters_no_map_milter_units(
        self, get_peers, relation_ids, relation_get, related_units
    ):
        self.mock_local_unit.return_value = 'smtp-relay/1'
        get_peers.return_value = ['smtp-relay/0', 'smtp-relay/1']
        relation_ids.return_value = ['milter:54']
        related_units.return_value = []
        want = ''
        self.assertEqual(want, smtp_relay._get_milters())
        relation_get.assert_not_called()

    @mock.patch('charmhelpers.core.hookenv.related_units')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('reactive.smtp_relay._get_peers')
    def test__get_milters_no_milter_relation(self, get_peers, relation_ids, related_units):
        get_peers.return_value = ['smtp-relay/0', 'smtp-relay/1']
        want = ''
        self.assertEqual(want, smtp_relay._get_milters())
        relation_ids.assert_called_with('milter')

    @mock.patch('charms.reactive.set_flag')
    def test_set_active(self, set_flag):
        smtp_relay.set_active()
        status.active.assert_called_once_with('Ready')
        set_flag.assert_called_once_with('smtp-relay.active')

    @mock.patch('charms.reactive.set_flag')
    def test_set_active_revno(self, set_flag):
        # git - 'uax4glw'
        smtp_relay.set_active(os.path.join(self.charm_dir, 'tests/unit/files/version'))
        status.active.assert_called_once_with('Ready (source version/commit uax4glw)')

    @mock.patch('charms.reactive.set_flag')
    def test_set_active_shortened_revno(self, set_flag):
        smtp_relay.set_active(os.path.join(self.charm_dir, 'tests/unit/files/version_long'))
        status.active.assert_called_once_with('Ready (source version/commit somerandom…)')

    @mock.patch('charms.reactive.set_flag')
    def test_set_active_dirty_revno(self, set_flag):
        smtp_relay.set_active(os.path.join(self.charm_dir, 'tests/unit/files/version_dirty'))
        status.active.assert_called_once_with('Ready (source version/commit 38c901f-dirty)')

    def test__copy_file(self):
        source = os.path.join(self.charm_dir, 'templates/postfix_main_cf.tmpl')
        dest = os.path.join(self.tmpdir, os.path.basename(source))

        self.assertTrue(smtp_relay._copy_file(source, dest))
        # Write again, should return False and not True per above.
        self.assertFalse(smtp_relay._copy_file(source, dest))

        # Check contents
        with open(source, 'r') as f:
            want = f.read()
        with open(dest, 'r') as f:
            got = f.read()
        self.assertEqual(got, want)

    def test__write_file(self):
        source = '# User-provided config added here'
        dest = os.path.join(self.tmpdir, 'my-test-file')

        self.assertTrue(smtp_relay._write_file(source, dest))
        # Write again, should return False and not True per above.
        self.assertFalse(smtp_relay._write_file(source, dest))

        # Check contents
        with open(dest, 'r') as f:
            got = f.read()
        self.assertEqual(got, source)

    @mock.patch('charmhelpers.core.host.write_file')
    @mock.patch('os.rename')
    def test__write_file_owner_group(self, rename, write_file):
        source = '# User-provided config added here'
        dest = os.path.join(self.tmpdir, 'my-test-file')

        self.assertTrue(smtp_relay._write_file(source, dest, owner='root', group='root'))
        want = [
            mock.call(path=dest + '.new', content=source, perms=420, owner='root', group='root')
        ]
        write_file.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(write_file.mock_calls))

        write_file.reset_mock()
        with mock.patch('builtins.open', side_effect=FileNotFoundError):
            smtp_relay._write_file(source, dest, owner='root', group='root')
        want = [
            mock.call(path=dest + '.new', content=source, perms=420, owner='root', group='root')
        ]
        write_file.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(write_file.mock_calls))

        write_file.reset_mock()
        with mock.patch('builtins.open', side_effect=FileNotFoundError):
            smtp_relay._write_file(source, dest)
        current_usr = pwd.getpwuid(os.getuid()).pw_name
        current_grp = grp.getgrgid(pwd.getpwnam(current_usr).pw_gid).gr_name
        want = [
            mock.call(
                path=dest + '.new', content=source, perms=420, owner=current_usr, group=current_grp
            )
        ]
        write_file.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(write_file.mock_calls))

        write_file.reset_mock()
        with mock.patch('builtins.open', side_effect=FileNotFoundError):
            smtp_relay._write_file(source, dest, owner='nobody')
        current_grp = grp.getgrgid(pwd.getpwnam('nobody').pw_gid).gr_name
        want = [
            mock.call(
                path=dest + '.new', content=source, perms=420, owner='nobody', group=current_grp
            )
        ]
        write_file.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(write_file.mock_calls))

    @mock.patch('subprocess.call')
    def test__update_aliases(self, call):
        dest = os.path.join(self.tmpdir, 'aliases')

        # Empty, does not exist.
        smtp_relay._update_aliases('', dest)
        want = 'devnull:       /dev/null\n'
        with open(dest, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        call.assert_called_with(['newaliases'])

        # Has something prepopulated, but not devnull.
        call.reset_mock()
        content = 'postmaster:    root\n'
        with open(dest, 'w') as f:
            f.write(content)
        smtp_relay._update_aliases('', dest)
        want = content + 'devnull:       /dev/null\n'
        with open(dest, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        call.assert_called_with(['newaliases'])

        # Has devnull, so do nothing and do not call newaliases.
        call.reset_mock()
        content = 'postmaster:    root\ndevnull:       /dev/null\n'
        with open(dest, 'w') as f:
            f.write(content)
        smtp_relay._update_aliases('', dest)
        want = content
        with open(dest, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        call.assert_not_called()

        # Admin email set.
        call.reset_mock()
        content = 'postmaster:    root\ndevnull:       /dev/null\n'
        with open(dest, 'w') as f:
            f.write(content)
        smtp_relay._update_aliases('root@admin.mydomain.local', dest)
        want = """postmaster:    root
devnull:       /dev/null
root:          root@admin.mydomain.local
"""
        with open(dest, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        call.assert_called_with(['newaliases'])

        # Has admin email, so do nothing and do not call newaliases.
        call.reset_mock()
        content = """postmaster:    root
devnull:       /dev/null
root:          root@admin.mydomain.local
"""
        with open(dest, 'w') as f:
            f.write(content)
        smtp_relay._update_aliases('root@admin.mydomain.local', dest)
        want = content
        with open(dest, 'r', encoding='utf-8') as f:
            got = f.read()
        self.assertEqual(want, got)
        call.assert_not_called()
