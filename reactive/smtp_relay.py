# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""SMTP Relay charm."""

import grp
import hashlib
import os
import pwd
import socket
import subprocess  # nosec

import jinja2
import yaml

from charms import reactive
from charms.layer import status
from charmhelpers.core import hookenv, host

from lib import utils


JUJU_HEADER = '# This file is Juju managed - do not edit by hand #\n\n'


@reactive.hook('upgrade-charm')
def upgrade_charm():
    status.maintenance('forcing reconfiguration on upgrade-charm')
    reactive.clear_flag('smtp-relay.active')
    reactive.clear_flag('smtp-relay.auth.configured')
    reactive.clear_flag('smtp-relay.configured')
    reactive.clear_flag('smtp-relay.installed')
    reactive.clear_flag('smtp-relay.rsyslog.configured')


@reactive.when_not('smtp-relay.installed')
def install(script_dir='/usr/local/bin'):
    reactive.set_flag('smtp-relay.installed')

    fgrepmail_logs = os.path.join(script_dir, 'fgrepmail-logs')
    _copy_file('files/fgrepmail-logs.py', fgrepmail_logs, perms=0o755)


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
    config = hookenv.config()

    status.maintenance('Setting up SMTP authentication (dovecot)')

    changed = False
    context = {
        'JUJU_HEADER': JUJU_HEADER,
        # TODO: Allow overriding passdb driver.
        'passdb_driver': 'passwd-file',
        'passdb_args': f"scheme=CRYPT username_format=%u {dovecot_users}",
        # We need to use /var/spool/postfix/private/auth because
        # by default postfix runs chroot'ed in /var/spool/postfix.
        'path': '/var/spool/postfix/private/auth',
        'smtp_auth': config['enable_smtp_auth'],
    }
    base = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    env = jinja2.Environment(autoescape=True, loader=jinja2.FileSystemLoader(base))
    template = env.get_template('templates/dovecot_conf.tmpl')
    contents = template.render(context)
    changed = _write_file(contents, dovecot_config) or changed

    smtp_auth_users = config['smtp_auth_users']
    if smtp_auth_users and not smtp_auth_users.startswith('MANUAL'):
        contents = JUJU_HEADER + smtp_auth_users + '\n'
        _write_file(contents, dovecot_users, perms=0o640, group='dovecot')

    if not config.get('enable_smtp_auth'):
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
    'config.changed.enable_reject_unknown_recipient_domain',
    'config.changed.enable_smtp_auth',
    'config.changed.enable_spf',
    'config.changed.header_checks',
    'config.changed.message_size_limit',
    'config.changed.relay_access_sources',
    'config.changed.relay_domains',
    'config.changed.relay_host',
    'config.changed.relay_recipient_maps',
    'config.changed.restrict_recipients',
    'config.changed.restrict_senders',
    'config.changed.restrict_sender_access',
    'config.changed.sender_login_maps',
    'config.changed.smtp_header_checks',
    'config.changed.smtpd_forbid_bare_newline',
    'config.changed.smtpd_forbid_bare_newline_exclusions',
    'config.changed.smtpd_forbid_bare_newline_reject_code',
    'config.changed.spf_check_maps',
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


@reactive.when('config.changed.log_retention')
def update_logrotate(logrotate_conf_path='/etc/logrotate.d/rsyslog'):
    reactive.clear_flag('smtp-relay.active')
    status.maintenance('Updating log retention / rotation configs')

    config = hookenv.config()
    retention = config['log_retention']
    contents = utils.update_logrotate_conf(logrotate_conf_path, frequency='daily', retention=retention)
    _write_file(contents, logrotate_conf_path)


@reactive.hook('milter-relation-joined', 'milter-relation-changed')
def milter_relation_changed():
    reactive.clear_flag('smtp-relay.configured')


def _create_update_map(content, postmap):
    changed = False

    (pmtype, pmfname) = postmap.split(':')
    if not os.path.exists(pmfname):
        with open(pmfname, 'a', encoding="utf-8"):
            os.utime(pmfname, None)
        changed = True

    if content.startswith('MANUAL'):
        hookenv.log(f"Map {pmfname} manually managed")
    elif content.startswith('COMBINED'):
        hookenv.log(f"Map {pmfname} using combined maps")
    else:
        contents = JUJU_HEADER + content + '\n'
        changed = _write_file(contents, pmfname) or changed

    if changed and pmtype == 'hash':
        subprocess.call(['postmap', postmap])  # nosec

    return changed


@reactive.when('smtp-relay.installed')
@reactive.when('smtp-relay.auth.configured')
@reactive.when_not('smtp-relay.configured')
def configure_smtp_relay(
    postfix_conf_dir='/etc/postfix', tls_dh_params='/etc/ssl/private/dhparams.pem'
):
    reactive.clear_flag('smtp-relay.active')
    config = hookenv.config()

    status.maintenance('Setting up SMTP relay')

    tls_cert_key = ''
    tls_cert = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
    tls_key = '/etc/ssl/private/ssl-cert-snakeoil.key'
    tls_cn = _get_autocert_cn()
    if tls_cn:
        # autocert currently bundles certs with the key at the end which postfix doesn't like:
        # `warning: error loading chain from /etc/postfix/ssl/{...}.pem: key not first`
        # Let's not use the newer `smtpd_tls_chain_files` postfix config for now.
        # tls_cert_key = f"/etc/postfix/ssl/{tls_cn}.pem"
        tls_cert = f"/etc/postfix/ssl/{tls_cn}.crt"
        tls_key = f"/etc/postfix/ssl/{tls_cn}.key"
        tls_dh_params = '/etc/postfix/ssl/dhparams.pem'
    if not os.path.exists(tls_dh_params):
        subprocess.call(['openssl', 'dhparam', '-out', tls_dh_params, '2048'])  # nosec

    fqdn = socket.getfqdn()
    if config['domain']:
        fqdn = _generate_fqdn(config['domain'])

    smtpd_recipient_restrictions = _smtpd_recipient_restrictions(config)
    smtpd_relay_restrictions = _smtpd_relay_restrictions(config)
    smtpd_sender_restrictions = _smtpd_sender_restrictions(config)

    virtual_alias_maps_type = config['virtual_alias_maps_type']

    changed = False
    context = {
        'JUJU_HEADER': JUJU_HEADER,
        'fqdn': fqdn,
        'hostname': socket.gethostname(),
        'connection_limit': config['connection_limit'],
        'enable_rate_limits': config['enable_rate_limits'],
        'enable_sender_login_map': bool(config['sender_login_maps']),
        'enable_smtp_auth': config['enable_smtp_auth'],
        'enable_spf': config['enable_spf'],
        'enable_tls_policy_map': bool(config['tls_policy_maps']),
        'header_checks': bool(config['header_checks']),
        'message_size_limit': config['message_size_limit'],
        'milter': _get_milters(),
        'myorigin': False,  # XXX: Configurable when given hostname override
        'mynetworks': config['allowed_relay_networks'],
        'relayhost': config['relay_host'],
        'relay_domains': config['relay_domains'],
        'relay_recipient_maps': bool(config['relay_recipient_maps']),
        'relay_recipient_maps_combined': config['relay_recipient_maps'] == 'COMBINED',
        'restrict_recipients': bool(config['restrict_recipients']),
        'smtp_header_checks': bool(config['smtp_header_checks']),
        'smtpd_recipient_restrictions': ', '.join(smtpd_recipient_restrictions),
        'smtpd_relay_restrictions': ', '.join(smtpd_relay_restrictions),
        'smtpd_sender_restrictions': ', '.join(smtpd_sender_restrictions),
        'smtpd_forbid_bare_newline': config['smtpd_forbid_bare_newline'],
        'smtpd_forbid_bare_newline_exclusions': config['smtpd_forbid_bare_newline_exclusions'],
        'smtpd_forbid_bare_newline_reject_code': config['smtpd_forbid_bare_newline_reject_code'],
        'spf_check_maps': bool(config['spf_check_maps']),
        'tls_cert_key': tls_cert_key,
        'tls_cert': tls_cert,
        'tls_key': tls_key,
        'tls_ciphers': config['tls_ciphers'],
        'tls_dh_params': tls_dh_params,
        'tls_exclude_ciphers': config['tls_exclude_ciphers'],
        'tls_protocols': config['tls_protocols'],
        'tls_security_level': config['tls_security_level'],
        'transport_maps': bool(config['transport_maps']),
        'virtual_alias_domains': config['virtual_alias_domains'],
        'virtual_alias_maps': bool(config['virtual_alias_maps']),
        'virtual_alias_maps_type': virtual_alias_maps_type,
    }
    base = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    env = jinja2.Environment(autoescape=True, loader=jinja2.FileSystemLoader(base))
    template = env.get_template('templates/postfix_main_cf.tmpl')
    contents = template.render(context)
    changed = _write_file(contents, os.path.join(postfix_conf_dir, 'main.cf')) or changed
    template = env.get_template('templates/postfix_master_cf.tmpl')
    contents = template.render(context)
    changed = _write_file(contents, os.path.join(postfix_conf_dir, 'master.cf')) or changed
    maps = {
        'append_envelope_to_header': (
            f"regexp:{os.path.join(postfix_conf_dir, 'append_envelope_to_header')}"
        ),
        'header_checks': f"regexp:{os.path.join(postfix_conf_dir, 'header_checks')}",
        'relay_access_sources': f"cidr:{os.path.join(postfix_conf_dir, 'relay_access')}",
        'relay_recipient_maps': f"hash:{os.path.join(postfix_conf_dir, 'relay_recipient')}",
        'restrict_recipients': f"hash:{os.path.join(postfix_conf_dir, 'restricted_recipients')}",
        'restrict_senders': f"hash:{os.path.join(postfix_conf_dir, 'restricted_senders')}",
        'sender_access': f"hash:{os.path.join(postfix_conf_dir, 'access')}",
        'sender_login_maps': f"hash:{os.path.join(postfix_conf_dir, 'sender_login')}",
        'smtp_header_checks': f"regexp:{os.path.join(postfix_conf_dir, 'smtp_header_checks')}",
        'spf_check_maps': f"hash:{os.path.join(postfix_conf_dir, 'spf_checks')}",
        'tls_policy_maps': f"hash:{os.path.join(postfix_conf_dir, 'tls_policy')}",
        'transport_maps': f"hash:{os.path.join(postfix_conf_dir, 'transport')}",
        'virtual_alias_maps': (
            f"{virtual_alias_maps_type}:{os.path.join(postfix_conf_dir, 'virtual_alias')}"
        ),
    }
    sender_access_content = config['restrict_sender_access']
    if sender_access_content and not sender_access_content.startswith('MANUAL'):
        domains = ' '.join(config['restrict_sender_access'].split(',')).split()
        sender_access_content = "".join([f"{domain:35} OK\n" for domain in domains])
    map_contents = {
        'append_envelope_to_header': '/^(.*)$/ PREPEND X-Envelope-To: $1',
        'header_checks': config['header_checks'],
        'relay_access_sources': config['relay_access_sources'],
        'relay_recipient_maps': config['relay_recipient_maps'],
        'restrict_recipients': config['restrict_recipients'],
        'restrict_senders': config['restrict_senders'],
        'sender_access': sender_access_content,
        'sender_login_maps': config['sender_login_maps'],
        'smtp_header_checks': config['smtp_header_checks'],
        'spf_check_maps': config['spf_check_maps'],
        'tls_policy_maps': config['tls_policy_maps'],
        'transport_maps': config['transport_maps'],
        'virtual_alias_maps': config['virtual_alias_maps'],
    }

    # Ensure various maps exists before starting/restarting postfix.
    for key, pmap in maps.items():
        changed = _create_update_map(map_contents[key], pmap) or changed

    _update_aliases(config['admin_email'])

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
    config = hookenv.config()

    if not config['enable_spf']:
        status.maintenance('Postfix policy server for SPF checking (policyd-spf) disabled')
        reactive.set_flag('smtp-relay.policyd-spf.configured')
        return

    status.maintenance('Setting up Postfix policy server for SPF checking (policyd-spf)')

    context = {
        'JUJU_HEADER': JUJU_HEADER,
        'skip_addresses': config['spf_skip_addresses'],
    }
    base = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    env = jinja2.Environment(autoescape=True, loader=jinja2.FileSystemLoader(base))
    template = env.get_template('templates/policyd_spf_conf.tmpl')
    contents = template.render(context)
    _write_file(contents, policyd_spf_config)

    reactive.set_flag('smtp-relay.policyd-spf.configured')


def _get_autocert_cn(autocert_conf_dir='/etc/autocert/postfix'):
    # autocert relation is reversed so we can't get this info from
    # juju relations but rather try work it out from the shipped out
    # config.
    if os.path.exists(autocert_conf_dir):
        for f in sorted(os.listdir(autocert_conf_dir)):
            if not f.endswith('.ini'):
                continue
            return f[:-4]
    return ''


def _generate_fqdn(domain):
    hostname = hookenv.local_unit().replace('/', '-')
    return f"{hostname}.{domain}"


def _calculate_offset(seed, length=2):
    result = hashlib.md5(seed.encode('utf-8')).hexdigest()[0:length]  # nosec
    return int(result, 16)


def _get_peers():
    # Build a list of peer units so we can map it to milters.
    peers = [hookenv.local_unit()]
    if hookenv.relation_ids('peer'):
        peers += hookenv.related_units(hookenv.relation_ids('peer')[0])
    peers = sorted(set(peers))
    return peers


def _get_milters():
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

    if len(result) == 0:
        return ''

    return ' '.join(result)


@reactive.when('config.changed.syslog_forwarders')
def config_changed_syslog_forwarders():
    reactive.clear_flag('smtp-relay.rsyslog.configured')


@reactive.when('smtp-relay.installed')
@reactive.when_not('smtp-relay.rsyslog.configured')
def configure_syslog_forwarders(rsyslog_conf_d='/etc/rsyslog.d'):
    reactive.clear_flag('smtp-relay.active')
    config = hookenv.config()
    forwarder_config = os.path.join(rsyslog_conf_d, '45-rsyslog-replication.conf')

    # TODO: Add support for relations (cross-model too).

    if not config['syslog_forwarders']:
        if os.path.exists(forwarder_config):
            status.maintenance('Disabling syslog forwards')
            os.unlink(forwarder_config)
            host.service_restart('rsyslog')

        reactive.set_flag('smtp-relay.rsyslog.configured')
        return

    status.maintenance('Setting up syslog forwarders')

    changed = False
    context = {
        'JUJU_HEADER': JUJU_HEADER,
        'syslog_forwarders': [i.strip() for i in config['syslog_forwarders'].split(',')],
    }
    base = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(base))  # nosec
    template = env.get_template('templates/syslog_forwarders.tmpl')
    contents = template.render(context)
    changed = _write_file(contents, forwarder_config) or changed

    # Work around LP:581360.
    default_config = os.path.join(rsyslog_conf_d, '50-default.conf')
    contents = utils.update_rsyslog_default_conf(default_config)
    changed = _write_file(contents, default_config) or changed

    if changed:
        status.maintenance('Restarting rsyslog due to config changes')
        host.service_restart('rsyslog')

    reactive.set_flag('smtp-relay.rsyslog.configured')


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


def _copy_file(source_path, dest_path, **kwargs):
    with open(source_path, 'r', encoding="utf-8") as f:
        source = f.read()
    return _write_file(source, dest_path, **kwargs)


def _write_file(source, dest_path, perms=0o644, owner=None, group=None):
    """Write file only on changes and return True if changes written."""
    # Compare and only write out file on change.
    dest = ''

    try:
        with open(dest_path, 'r', encoding="utf-8") as f:
            dest = f.read()
        if source == dest:
            return False
    except FileNotFoundError:
        pass

    if owner is None:
        owner = pwd.getpwuid(os.getuid()).pw_name
    if group is None:
        group = grp.getgrgid(pwd.getpwnam(owner).pw_gid).gr_name

    host.write_file(path=dest_path + '.new', content=source, perms=perms, owner=owner, group=group)
    os.rename(dest_path + '.new', dest_path)
    return True


def _smtpd_recipient_restrictions(config):
    smtpd_recipient_restrictions = []
    if config['append_x_envelope_to']:
        smtpd_recipient_restrictions.append(
            'check_recipient_access regexp:/etc/postfix/append_envelope_to_header'
        )

    if config['enable_reject_unknown_recipient_domain']:
        smtpd_recipient_restrictions.append('reject_unknown_recipient_domain')

    if config['restrict_senders']:
        smtpd_recipient_restrictions.append(
            'check_sender_access hash:/etc/postfix/restricted_senders'
        )

    if config['additional_smtpd_recipient_restrictions']:
        smtpd_recipient_restrictions += yaml.safe_load(
            config['additional_smtpd_recipient_restrictions']
        )

    if config['enable_spf']:
        if config['spf_check_maps']:
            smtpd_recipient_restrictions.append('check_sender_access hash:/etc/postfix/spf_checks')
        else:
            smtpd_recipient_restrictions.append('check_policy_service unix:private/policyd-spf')

    return smtpd_recipient_restrictions


def _smtpd_relay_restrictions(config):
    smtpd_relay_restrictions = ['permit_mynetworks']
    if bool(config['relay_access_sources']):
        smtpd_relay_restrictions.append('check_client_access cidr:/etc/postfix/relay_access')

    if config['enable_smtp_auth']:
        if bool(config['sender_login_maps']):
            smtpd_relay_restrictions.append('reject_known_sender_login_mismatch')
        if bool(config['restrict_senders']):
            smtpd_relay_restrictions.append('reject_sender_login_mismatch')
        smtpd_relay_restrictions.append('permit_sasl_authenticated')

    smtpd_relay_restrictions.append('defer_unauth_destination')

    return smtpd_relay_restrictions


def _smtpd_sender_restrictions(config):
    smtpd_sender_restrictions = []
    if config['enable_reject_unknown_sender_domain']:
        smtpd_sender_restrictions.append('reject_unknown_sender_domain')
    smtpd_sender_restrictions.append('check_sender_access hash:/etc/postfix/access')
    if bool(config['restrict_sender_access']):
        smtpd_sender_restrictions.append('reject')

    return smtpd_sender_restrictions


def _update_aliases(admin_email='', aliases_path='/etc/aliases'):
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

    changed = _write_file(''.join(new_aliases), aliases_path)
    if changed:
        subprocess.call(['newaliases'])  # nosec
