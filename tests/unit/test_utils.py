# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import os
import shutil
import sys
import tempfile
import unittest

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
from lib import utils  # NOQA: E402


class TestLibUtils(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.tmpdir = tempfile.mkdtemp(prefix='charm-unittests-')
        self.addCleanup(shutil.rmtree, self.tmpdir)

    def test_rsyslog_default_conf(self):
        with open('tests/unit/files/rsyslog-50-default_without_mail_kern.conf', 'r') as f:
            want = f.read()
        self.assertEqual(
            utils.update_rsyslog_default_conf('tests/unit/files/rsyslog-50-default.conf'), want
        )

    def test_rsyslog_default_conf_non_exists(self):
        self.assertEqual(
            utils.update_rsyslog_default_conf(
                'tests/unit/files/rsyslog-50-default_does_not_exist'
            ),
            '',
        )
