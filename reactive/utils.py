# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utils."""

import grp
import os
import pwd
import re
from pathlib import Path
from typing import Any

import jinja2
from charmhelpers.core import host

JUJU_HEADER = "# This file is Juju managed - do not edit by hand #\n\n"


def update_logrotate_conf(path):
    """Update existing logrotate config with log retention settings.

    Args:
        path: path to the logrotate configuration.
    """
    if not Path(path).exists():
        return ""

    config = Path(path).read_text(encoding="utf-8")
    new = []
    regex = re.compile(r'^(\s+)(daily|weekly|monthly|rotate|dateext)')
    for line in config.splitlines():
        m = regex.match(line)
        if not m:
            new.append(line)
            continue

        conf = m.group(2)
        indent = m.group(1)

        # Rotation frequency.
        if conf in ("daily", "weekly", "monthly"):
            new.append(f"{indent}daily")
        elif conf == "dateext":
            # Ignore 'dateext', we'll put it back on updating 'rotate'.
            continue
        elif conf == "rotate":
            new.append(f"{indent}dateext")
            new.append(f"{indent}rotate 730")
        else:
            new.append(line)
    return "\n".join(new)


def copy_file(source_path, destination_path, perms=0o644):
    """Copy file.

    Args:
        source_path: path to the source file.
        destination_path: destination path.
        perms: permissions.
    """
    content = Path(source_path).read_text(encoding="utf-8")
    return write_file(content, destination_path, perms=perms)


def write_file(content, destination_path, perms=0o644, group=None):
    """Write file only on changes and return True if changes written.

    Args:
        content: file content.
        destination_path: destination path.
        perms: permissions.
        group: file group.
    """
    # Compare and only write out file on change.
    try:
        dest = Path(destination_path).read_text(encoding="utf-8")
        if content == dest:
            return False
    except FileNotFoundError:
        pass

    owner = pwd.getpwuid(os.getuid()).pw_name
    if group is None:
        group = grp.getgrgid(pwd.getpwnam(owner).pw_gid).gr_name

    host.write_file(
        path=f"{destination_path}.new",
        content=content,
        perms=perms,
        owner=owner,
        group=group,
    )
    Path(f"{destination_path}.new").rename(destination_path)
    return True


def render_jinja2_template(
    context: dict[str, Any],
    template_path: str,
    base_path: str | None = None,
) -> str:
    """Render jinja2 template given the context.
    
    Args:
        context: Variables to render into the template.
        template_path: path of the Jinja2 template (relative to base_path).
        base_path: base path to the template, defaults to the project root.
    """
    base = Path(base_path) if base_path else Path(__file__).resolve().parent.parent
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(base))
    template = env.get_template(template_path)
    return template.render(context)
