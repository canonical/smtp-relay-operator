# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""SMTP Relay charm."""

import hashlib
import os
import socket
import subprocess  # nosec

from charms import reactive
from charms.layer import status
from charmhelpers.core import hookenv, host

from postfix import construct_postfix_config_file_content, ensure_postmap_files
from dovecot import construct_dovecot_config_file_content, construct_dovecot_user_file_content
from reactive import utils
from reactive.state import State
from tls import get_tls_config_paths


@reactive.hook('upgrade-charm')
def upgrade_charm():
    status.maintenance('forcing reconfiguration on upgrade-charm')
    reactive.clear_flag('smtp-relay.active')
    reactive.clear_flag('smtp-relay.auth.configured')
    reactive.clear_flag('smtp-relay.configured')
    reactive.clear_flag('smtp-relay.installed')


@reactive.when_not('smtp-relay.installed')
def install(logrotate_conf_path='/etc/logrotate.d/rsyslog'):
    reactive.set_flag('smtp-relay.installed')

    _configure_smtp_relay_logging(logrotate_conf_path)


def _configure_smtp_relay_logging(logrotate_conf_path: str) -> None:
    """Configure logging for the SMTP relay."""
    utils.copy_file("files/fgrepmail-logs.py", "/usr/local/bin/fgrepmail-logs", perms=0o755)
    utils.copy_file("files/50-default.conf", "/etc/rsyslog.d/50-default.conf", perms=0o644)
    contents = utils.update_logrotate_conf(logrotate_conf_path)
    utils.write_file(contents, logrotate_conf_path)


@reactive.hook('peer-relation-joined', 'peer-relation-changed')
def peer_relation_changed():
    reactive.clear_flag('smtp-relay.configured')


@reactive.when_any(
    'config.changed.enable_smtp_auth',
    'config.changed.smtp_auth_users',
)
def config_changed_smtp_auth():
    reactive.clear_flag('smtp-relay.auth.configured')


@reactive.when('smtp-relay.installed')
@reactive.when_not('smtp-relay.auth.configured')
def configure_smtp_auth(
    dovecot_config='/etc/dovecot/dovecot.conf', dovecot_users='/etc/dovecot/users'
):
    reactive.clear_flag('smtp-relay.active')
    reactive.clear_flag('smtp-relay.configured')
    charm_state = State.from_charm(hookenv.config())

    status.maintenance('Setting up SMTP authentication (dovecot)')

    contents = construct_dovecot_config_file_content(dovecot_users, charm_state.enable_smtp_auth)
    changed = utils.write_file(contents, dovecot_config)

    if charm_state.smtp_auth_users:
        contents = construct_dovecot_user_file_content(charm_state.smtp_auth_users)
        utils.write_file(contents, dovecot_users, perms=0o640, group="dovecot")


    if not charm_state.enable_smtp_auth:
        status.maintenance('SMTP authentication not enabled, ensuring ports are closed')
        hookenv.close_port(465, 'TCP')
        hookenv.close_port(587, 'TCP')
        host.service_stop('dovecot')
        # XXX: mask systemd service disable

        reactive.set_flag('smtp-relay.auth.configured')
        return

    status.maintenance('Opening additional ports for SMTP authentication')
    hookenv.open_port(465, 'TCP')
    hookenv.open_port(587, 'TCP')

    if changed:
        status.maintenance('Restarting Dovecot due to config changes')
        host.service_reload('dovecot')
    # Ensure service is running.
    host.service_start('dovecot')

    reactive.set_flag('smtp-relay.auth.configured')

@reactive.when_any(
    'config.changed.admin_email',
    'config.changed.additional_smtpd_recipient_restrictions',
    'config.changed.allowed_relay_networks',
    'config.changed.append_x_envelope_to',
    'config.changed.connection_limit',
    'config.changed.domain',
    'config.changed.enable_rate_limits',
    'config.changed.enable_smtp_auth',
    'config.changed.enable_spf',
    'config.changed.header_checks',
    'config.changed.relay_access_sources',
    'config.changed.relay_domains',
    'config.changed.relay_host',
    'config.changed.relay_recipient_maps',
    'config.changed.restrict_recipients',
    'config.changed.restrict_senders',
    'config.changed.restrict_sender_access',
    'config.changed.sender_login_maps',
    'config.changed.smtp_header_checks',
    'config.changed.tls_ciphers',
    'config.changed.tls_exclude_ciphers',
    'config.changed.tls_policy_maps',
    'config.changed.tls_protocols',
    'config.changed.tls_security_level',
    'config.changed.transport_maps',
    'config.changed.virtual_alias_domains',
    'config.changed.virtual_alias_maps',
    'config.changed.virtual_alias_maps_type',
)
def config_changed():
    reactive.clear_flag('smtp-relay.configured')


@reactive.hook('milter-relation-joined', 'milter-relation-changed')
def milter_relation_changed():
    reactive.clear_flag('smtp-relay.configured')


@reactive.when('smtp-relay.installed')
@reactive.when('smtp-relay.auth.configured')
@reactive.when_not('smtp-relay.configured')
def configure_smtp_relay(
    postfix_conf_dir='/etc/postfix', tls_dh_params='/etc/ssl/private/dhparams.pem'
):
    reactive.clear_flag('smtp-relay.active')
    charm_state = State.from_charm(hookenv.config())

    status.maintenance('Setting up SMTP relay')

    tls_config_paths = get_tls_config_paths(tls_dh_params)
    fqdn = _generate_fqdn(charm_state.domain) if charm_state.domain else socket.getfqdn()
    hostname = socket.gethostname()
    milters = _get_milters()

    contents = construct_postfix_config_file_content(
        charm_state=charm_state,
        tls_config_paths=tls_config_paths,
        fqdn=fqdn,
        hostname=hostname,
        milters=milters,
        template_path='templates/postfix_main_cf.tmpl'

    )
    changed = utils.write_file(contents, os.path.join(postfix_conf_dir, 'main.cf'))
    
    contents = construct_postfix_config_file_content(
        charm_state=charm_state,
        tls_config_paths=tls_config_paths,
        fqdn=fqdn,
        hostname=hostname,
        milters=milters,
        template_path='templates/postfix_master_cf.tmpl'
    )
    changed = utils.write_file(contents, os.path.join(postfix_conf_dir, 'master.cf')) or changed

    changed = ensure_postmap_files(postfix_conf_dir, charm_state) or changed

    _update_aliases(charm_state.admin_email)

    host.service_start('postfix')
    if changed:
        status.maintenance('Reloading postfix due to config changes')
        host.service_reload('postfix')
        hookenv.open_port(25, 'TCP')
    # Ensure service is running.
    host.service_start('postfix')

    reactive.set_flag('smtp-relay.configured')

@reactive.when_any(
    'config.changed.enable_spf',
    'config.changed.spf_skip_addresses',
)
def config_changed_policyd_spf():
    reactive.clear_flag('smtp-relay.policyd-spf.configured')


@reactive.when('smtp-relay.installed')
@reactive.when_not('smtp-relay.policyd-spf.configured')
def configure_policyd_spf(policyd_spf_config='/etc/postfix-policyd-spf-python/policyd-spf.conf'):
    reactive.clear_flag('smtp-relay.active')
    charm_state = State.from_charm(hookenv.config())

    if not charm_state.enable_spf:
        status.maintenance('Postfix policy server for SPF checking (policyd-spf) disabled')
        reactive.set_flag('smtp-relay.policyd-spf.configured')
        return

    status.maintenance('Setting up Postfix policy server for SPF checking (policyd-spf)')

    context = {
        'JUJU_HEADER': utils.JUJU_HEADER,
        'skip_addresses': ",".join(
            [str(address) for address in charm_state.spf_skip_addresses]
        ),
    }
    contents = utils.render_jinja2_template(context, 'templates/policyd_spf_conf.tmpl')
    utils.write_file(contents, policyd_spf_config)

    reactive.set_flag('smtp-relay.policyd-spf.configured')


def _generate_fqdn(domain):
    return f"{hookenv.local_unit().replace('/', '-')}.{domain}"


def _calculate_offset(seed, length=2):
    result = hashlib.md5(seed.encode('utf-8')).hexdigest()[0:length]  # nosec
    return int(result, 16)


def _get_peers():
    # Build a list of peer units so we can map it to milters.
    peers = [hookenv.local_unit()]
    if hookenv.relation_ids('peer'):
        peers += hookenv.related_units(hookenv.relation_ids('peer')[0])
    return sorted(set(peers))


def _get_milters() -> str:
    # TODO: We'll bring up a balancer in front of the list of
    # backend/related milters but for now, let's just map 1-to-1 and
    # try spread depending on how many available units.

    peers = _get_peers()
    index = peers.index(hookenv.local_unit())
    # We want to ensure multiple applications related to the same set
    # of milters are better spread across them. e.g. smtp-relay-A with
    # 2 units, smtp-relay-B also with 2 units, but dkim-signing with 5
    # units. We don't want only the first 2 dkim-signing units to be
    # used.
    offset = index + _calculate_offset(hookenv.application_name())

    result = []

    for relid in hookenv.relation_ids('milter'):
        units = sorted(hookenv.related_units(relid))
        if not units:
            continue
        unit = units[offset % len(units)]
        reldata = hookenv.relation_get(rid=relid, unit=unit)
        addr = reldata['ingress-address']
        # Default to TCP/8892
        port = reldata.get('port', 8892)
        result.append(f"inet:{addr}:{port}")

    return ' '.join(result)


@reactive.when('smtp-relay.configured')
@reactive.when_not('smtp-relay.active')
def set_active(version_file='version'):
    revision = ''
    if os.path.exists(version_file):
        with open(version_file, encoding="utf-8") as f:
            line = f.readline().strip()
        # We only want the first 10 characters, that's enough to tell
        # which version of the charm we're using. But include the
        # entire version if it's 'dirty' according to charm build.
        if len(line) > 10 and not line.endswith('-dirty'):
            revision = f" (source version/commit {line[:10]}…)"
        else:
            revision = f" (source version/commit {line})"

    # XXX include postfix main.cf hash and dovecot users
    # (maybe first 8 chars too? comes before the revision one)
    postfix_cf_hash = ''
    users_hash = ''

    status.active(f"Ready{postfix_cf_hash}{users_hash}{revision}")
    reactive.set_flag('smtp-relay.active')


def _update_aliases(admin_email, aliases_path='/etc/aliases'):
    aliases = []
    try:
        with open(aliases_path, 'r', encoding="utf-8") as f:
            aliases = f.readlines()
    except FileNotFoundError:
        pass

    add_devnull = True
    new_aliases = []
    for line in aliases:
        if line.startswith('devnull:'):
            add_devnull = False
        if line.startswith('root:'):
            continue
        new_aliases.append(line)

    if add_devnull:
        new_aliases.append('devnull:       /dev/null\n')
    if admin_email:
        new_aliases.append(f"root:          {admin_email}\n")

    changed = utils.write_file(''.join(new_aliases), aliases_path)
    if changed:
        subprocess.call(['newaliases'])  # nosec
