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

    def test_logrotate_frequency(self):
        with open('tests/unit/files/logrotate_frequency', 'r') as f:
            want = f.read()
        self.assertEqual(utils.update_logrotate_conf('tests/unit/files/logrotate'), want)
