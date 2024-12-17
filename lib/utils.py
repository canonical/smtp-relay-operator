import os
import re


def update_logrotate_conf(path, frequency=None, retention=0, dateext=True):
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
        if frequency and conf in ('daily', 'weekly', 'monthly'):
            new.append('{}{}'.format(indent, frequency))
        elif retention and conf == 'dateext':
            # Ignore 'dateext', we'll put it back on updating 'rotate'.
            continue
        elif retention and conf == 'rotate':
            if dateext:
                new.append('{}dateext'.format(indent))
            new.append('{}rotate {}'.format(indent, retention))
        else:
            new.append(line)

    return '\n'.join(new)


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
