# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from reactive import utils


class TestLibUtils(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.tmpdir = tempfile.mkdtemp(prefix='charm-unittests-')
        self.charm_dir = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        )
        self.addCleanup(shutil.rmtree, self.tmpdir)

    def test_logrotate_frequency(self):
        want = Path('tests/unit/files/logrotate_frequency').read_text(encoding="utf-8")
        got = utils.update_logrotate_conf('tests/unit/files/logrotate')
        self.assertEqual(got, want.strip())

    def test__copy_file(self):
        source = os.path.join(self.charm_dir, 'templates/postfix_main_cf.tmpl')
        dest = os.path.join(self.tmpdir, os.path.basename(source))

        self.assertTrue(utils.copy_file(source, dest))
        # Write again, should return False and not True per above.
        self.assertFalse(utils.copy_file(source, dest))

        # Check contents
        with open(source, 'r') as f:
            want = f.read()
        with open(dest, 'r') as f:
            got = f.read()
        self.assertEqual(got, want)

    def test__write_file(self):
        source = '# User-provided config added here'
        dest = os.path.join(self.tmpdir, 'my-test-file')

        self.assertTrue(utils.write_file(source, dest))
        # Write again, should return False and not True per above.
        self.assertFalse(utils.write_file(source, dest))

        # Check contents
        with open(dest, 'r') as f:
            got = f.read()
        self.assertEqual(got, source)
