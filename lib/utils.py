# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import os
import re


def update_rsyslog_default_conf(path):
    """Updating existing rsyslog 50-default.conf to work around LP:581360."""

    if not os.path.exists(path):
        return ''

    with open(path, 'r', encoding='utf-8') as f:
        config = f.read().split('\n')

    new = []
    regex = re.compile(r'^(\*\.\*;auth,authpriv\.none)(\s+.*)')
    for line in config:
        m = regex.match(line)
        if not m:
            new.append(line)
            continue

        conf = m.group(1)
        dest = m.group(2)

        new.append('{},mail.none,kern.none{}'.format(conf, dest))

    return '\n'.join(new)
