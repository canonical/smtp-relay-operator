# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import os
import re


def update_logrotate_conf(path):
    """Update existing logrotate config with log retention settings."""

    if not os.path.exists(path):
        return ''

    with open(path, 'r', encoding='utf-8') as f:
        config = f.read().split('\n')

    new = []
    regex = re.compile(r'^(\s+)(daily|weekly|monthly|rotate|dateext)')
    for line in config:
        m = regex.match(line)
        if not m:
            new.append(line)
            continue

        conf = m.group(2)
        indent = m.group(1)

        # Rotation frequency.
        if conf in ('daily', 'weekly', 'monthly'):
            new.append('{}daily'.format(indent))
        elif conf == 'dateext':
            # Ignore 'dateext', we'll put it back on updating 'rotate'.
            continue
        elif conf == 'rotate':
            new.append('{}dateext'.format(indent))
            new.append('{}rotate 730'.format(indent))
        else:
            new.append(line)

    return '\n'.join(new)
