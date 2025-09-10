import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

# We also need to mock up charms.layer so we can run unit tests without having
# to build the charm and pull in layers such as layer-status.
sys.modules["charms.layer"] = mock.MagicMock()

from charms.layer import status  # NOQA: E402
from charmhelpers.core import unitdata  # NOQA: E402

# Add path to where our reactive layer lives and import.
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
from reactive import utils, postfix  # NOQA: E402


class TestCharm(unittest.TestCase):
    def setUp(self):
        # TODO: copied from test_charm, needs reduction
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

    @mock.patch("subprocess.call")
    def test__create_update_map(self, call):
        postfix_relay_access = "hash:{}".format(os.path.join(self.tmpdir, "relay_access"))
        self.assertTrue(postfix._create_update_map("mydomain.local OK", postfix_relay_access))
        want = ["postmap", postfix_relay_access]
        call.assert_called_with(want)
        want = utils.JUJU_HEADER + "mydomain.local OK" + "\n"
        with open(os.path.join(self.tmpdir, "relay_access"), "r") as f:
            got = f.read()
        self.assertEqual(want, got)

        call.reset_mock()
        self.assertFalse(postfix._create_update_map("mydomain.local OK", postfix_relay_access))
        call.assert_not_called()

    @mock.patch("subprocess.call")
    def test__create_update_map_eno_content(self, call):
        postfix_relay_access = "hash:{}".format(os.path.join(self.tmpdir, "relay_access"))
        self.assertTrue(postfix._create_update_map("", postfix_relay_access))
        want = ["postmap", postfix_relay_access]
        call.assert_called_with(want)

        call.reset_mock()
        postfix._create_update_map("", postfix_relay_access)
        call.assert_not_called()
