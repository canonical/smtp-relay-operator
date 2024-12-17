#!/usr/bin/python3

# Copyright (C) 2021 Canonical Ltd.
# Author: Haw Loeung <haw.loeung@canonical.com>
#
# Easily search mail logs pulling all associated lines for specific matches.

import datetime
import glob
import os
import re
import subprocess
import sys

LOG_PATH = '/var/log'


def build_maillogs_list(logs=None):  # NOQA: C901
    """Build list of unique mail log filenames on disk."""

    default = os.path.join(LOG_PATH, 'mail.log')

    if not logs:
        return [default]

    # We need a separate option to include the default log at the end
    # after sorting so it's always processed last.
    include_default = False

    search_logs = []
    for log in logs:
        if log == 'mail.log' or log == '.' or log == 'now':
            include_default = True
            continue

        # If it starts with 'mail.log', add as is.
        if log.startswith('mail.log'):
            name = os.path.join(LOG_PATH, log)
            search_logs.append(name)
            # gzip compressed.
            search_logs.append(name + '.gz')
            continue

        # Date format (e.g. 20220209 or 2022-02-09).
        if log.startswith('202'):
            # Date hyphened, `date -I`.
            date = log.replace('-', '')

            # systemd logrotate.timer runs at 00:00 UTC so we need to use the day after.
            date = '{}-{}-{}'.format(date[:4], date[4:6], date[6:8])
            dt = datetime.date.fromisoformat(date)
            daydelta = datetime.timedelta(days=1)
            after = dt + daydelta
            # Current day is mail.log so include that if 202X-XX-XX is today.
            if date == (str(datetime.date.today())):
                include_default = True
                continue
            date = str(after).replace('-', '')

            name = '{}-{}'.format(default, date)
            search_logs.append(name)
            # Just the date and gzip compressed.
            search_logs.append(name + '.gz')
            continue

        print('Unsupported format {}'.format(log))
        return []

    maillogs = []
    for log in search_logs:
        if os.path.exists(log):
            maillogs.append(log)
        # Support for glob matches
        maillogs.extend(glob.glob(log))

    if not maillogs:
        return []

    # Sort and remove duplicates.
    maillogs = sorted(set(maillogs))

    if include_default:
        # We add this at the very end to ensure chronological order.
        maillogs.append(default)
    return maillogs


def search_maillogs(search_term, log):  # NOQA: C901
    """Search / grep for specified search term in provided log file name."""

    # Message IDs can be longer than 10 chars.
    pattern = re.compile(r'^([0-9A-F]{10,}):$')

    grep_cmd = 'grep'
    if log.endswith('.gz'):
        grep_cmd = 'zgrep'

    # Support for specific search terms
    if search_term.startswith('from=') and not search_term.startswith('from=<'):
        search_term = 'from=<' + search_term[5:]
    elif search_term.startswith('to=') and not search_term.startswith('to=<'):
        search_term = 'to=<' + search_term[3:]
    elif search_term.startswith('user='):
        search_term = 'sasl_username=' + search_term[5:]
    elif search_term.startswith('message-id=') and not search_term.startswith('message-id=<'):
        search_term = 'message-id=<' + search_term[11:]
    elif search_term.startswith('msgid='):
        if search_term.startswith('msgid=<'):
            search_term = 'message-id=' + search_term[6:]
        else:
            search_term = 'message-id=<' + search_term[6:]

    # Find all message IDs matching search term.
    cmd = [grep_cmd, '-P', search_term, log]
    try:
        output = subprocess.check_output(cmd)
    except subprocess.CalledProcessError:
        # None found so grep returns non-zero exit status.
        return

    msgids = []
    for line in output.decode('utf-8').split('\n'):
        ls = line.split()
        # Message IDs are usually the 5th column so skip if it's too short.
        if len(ls) < 5:
            print(line)
            continue
        res = pattern.match(ls[5])
        if not res:
            print(line)
            continue
        msgids.append(res.groups()[0])

    # Find all lines matching message IDs.
    search = ']: ({}): '.format('|'.join(msgids))
    cmd = [grep_cmd, '-E', search, log]
    subprocess.call(cmd)


def main():
    args = sys.argv

    prog_name = args[0]
    if len(args) < 2:
        print('Usage: {} [search term] [[mail logs]...]'.format(prog_name))
        sys.exit(1)
    search_term = args[1]
    maillogs = build_maillogs_list(args[2:])

    for log in maillogs:
        search_maillogs(search_term, log)


if __name__ == '__main__':
    main()
