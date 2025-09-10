# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from reactive import utils

def construct_dovecot_config_file_content(dovecot_users_path: str, enable_smtp_auth: bool):
    context = {
        "JUJU_HEADER": utils.JUJU_HEADER,
        # TODO: Allow overriding passdb driver.
        "passdb_driver": "passwd-file",
        "passdb_args": f"scheme=CRYPT username_format=%u {dovecot_users_path}",
        # We need to use /var/spool/postfix/private/auth because
        # by default postfix runs chroot'ed in /var/spool/postfix.
        "path": "/var/spool/postfix/private/auth",
        "smtp_auth": enable_smtp_auth,
    }
    contents = utils.render_jinja2_template(context, "templates/dovecot_conf.tmpl")
    return contents


def construct_dovecot_user_file_content(smtp_auth_users: list[str]) -> str:
    """Write Dovecot users file."""
    return f"{utils.JUJU_HEADER}{'\n'.join(smtp_auth_users)}\n"
