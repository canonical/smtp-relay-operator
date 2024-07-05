#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Smtp relay charm the service."""

import logging
import socket
import os
import subprocess
import yaml
from jinja2 import Environment, FileSystemLoader
from pathlib import Path

import ops
from charms.operator_libs_linux.v0 import apt
from charm_state import CharmConfigInvalidError, CharmState

logger = logging.getLogger(__name__)

JUJU_HEADER = "# This file is Juju managed - do not edit by hand #\n\n"
POSTFIX_CONF_DIR = "/etc/postfix"


class SmtpRelayCharm(ops.CharmBase):
    """SMTP relay charm."""

    def __init__(self, *args):
        """Construct.

        Args:
            args: Arguments passed to the CharmBase parent constructor.
        """
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)
        self.certificates = TLSCertificatesRequiresV3(self, TLS_CERT)
        try:
            self._charm_state = CharmState.from_charm(charm=self)
        except CharmConfigInvalidError as exc:
            self.model.unit.status = ops.BlockedStatus(exc.msg)
            return
        self.framework.observe(self.on.config_changed, self._on_config_changed)

    def _on_install(self, _) -> None:
        """Install needed apt packages."""
        self.unit.status = ops.MaintenanceStatus("Installing packages")
        apt.add_package(
            ["dovecot-common", "postfix", "postfix-policyd-spf-python"], update_cache=True
        )
        self.unit.status = ops.ActiveStatus()

    def _on_config_changed(self, _) -> None:
        """Handle changes in configuration."""
        self.unit.status = ops.MaintenanceStatus("Configuring charm")
        self.configure_smtp_auth()
        self.configure_smtp_relay()
        self.configure_policyd_spf()
        self.unit.status = ops.ActiveStatus()
    
    def configure_smtp_auth(self) -> None:
        """Configure SMTP authentication."""
        context = {
            "smtp_auth": self._charm_state.smtp_relay_config.enable_smtp_auth
        }
        file_loader = FileSystemLoader(Path("./templates"), followlinks=True)
        env = Environment(loader=file_loader, autoescape=True)
        template = env.get_template("dovecot_conf.tmpl")
        content = template.render(context)
        with open("/etc/dovecot/dovecot.conf", "w") as file:
            file.write(content)
        
        smtp_auth_users = self._charm_state.smtp_relay_config.smtp_auth_users
        if smtp_auth_users and not smtp_auth_users.startswith("MANUAL"):
            contents = JUJU_HEADER + smtp_auth_users + "\n"
            with open("/etc/dovecot/users", "w") as file:
                # TODO perms=0o640, group='dovecot'
                file.write(contents)

    def _smtpd_recipient_restrictions(self):
        smtpd_recipient_restrictions = []
        if self._charm_state.smtp_relay_config.append_x_envelope_to:
            smtpd_recipient_restrictions.append(
                "check_recipient_access regexp:/etc/postfix/append_envelope_to_header"
            )
        if self._charm_state.smtp_relay_config.enable_reject_unknown_recipient_domain:
            smtpd_recipient_restrictions.append("reject_unknown_recipient_domain")
        if self._charm_state.smtp_relay_config.restrict_senders:
            smtpd_recipient_restrictions.append(
                "check_sender_access hash:/etc/postfix/restricted_senders"
            )
        if self._charm_state.smtp_relay_config.additional_smtpd_recipient_restrictions:
            smtpd_recipient_restrictions += yaml.safe_load(
                self._charm_state.smtp_relay_config.additional_smtpd_recipient_restrictions
            )
        if self._charm_state.smtp_relay_config.enable_spf:
            if self._charm_state.smtp_relay_config.spf_check_maps:
                smtpd_recipient_restrictions.append(
                    "check_sender_access hash:/etc/postfix/spf_checks"
                )
            else:
                smtpd_recipient_restrictions.append("check_policy_service unix:private/policyd-spf")
        return smtpd_recipient_restrictions


    def _smtpd_relay_restrictions(self):
        smtpd_relay_restrictions = ["permit_mynetworks"]
        if self._charm_state.smtp_relay_config.relay_access_sources:
            smtpd_relay_restrictions.append("check_client_access cidr:/etc/postfix/relay_access")
        if self._charm_state.smtp_relay_config.enable_smtp_auth:
            if self._charm_state.smtp_relay_config.sender_login_maps:
                smtpd_relay_restrictions.append("reject_known_sender_login_mismatch")
            if self._charm_state.smtp_relay_config.restrict_senders:
                smtpd_relay_restrictions.append("reject_sender_login_mismatch")
            smtpd_relay_restrictions.append("permit_sasl_authenticated")
        smtpd_relay_restrictions.append("defer_unauth_destination")
        return smtpd_relay_restrictions


    def _smtpd_sender_restrictions(self):
        smtpd_sender_restrictions = []
        if self._charm_state.smtp_relay_config.enable_reject_unknown_sender_domain:
            smtpd_sender_restrictions.append("reject_unknown_sender_domain")
        smtpd_sender_restrictions.append("check_sender_access hash:/etc/postfix/access")
        if self._charm_state.smtp_relay_config.restrict_sender_access:
            smtpd_sender_restrictions.append("reject")
        return smtpd_sender_restrictions
    
    # TODO: WTF is this?
    def _get_milters(self):
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

        def _calculate_offset(seed, length=2):
            result = hashlib.md5(seed.encode('utf-8')).hexdigest()[0:length]
            return int(result, 16)
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
            result.append('inet:{}:{}'.format(addr, port))

        if len(result) == 0:
            return ''

        return ' '.join(result)

    def _update_aliases(self, admin_email: str) -> None:
        aliases_path="/etc/aliases"
        aliases = []
        try:
            with open(aliases_path, "r") as file:
                aliases = file.readlines()
        except FileNotFoundError:
            pass

        add_devnull = True
        new_aliases = []
        for line in aliases:
            if line.startswith("devnull:"):
                add_devnull = False
            if line.startswith("root:"):
                continue
            new_aliases.append(line)

        if add_devnull:
            new_aliases.append("devnull:       /dev/null\n")
        if admin_email:
            new_aliases.append(f"root:          {admin_email}\n")

        with open(aliases_path, "w") as file:
            file.write(new_aliases)
        subprocess.call(['newaliases'])
    
    def configure_smtp_relay(self):
        tls_cert_key = ""
        tls_cert = "/etc/ssl/certs/ssl-cert-snakeoil.pem"
        tls_key = "/etc/ssl/private/ssl-cert-snakeoil.key"
        tls_dh_params = "/etc/ssl/private/dhparams.pem"
        # TODO Fetch a cert via relation instead
        tls_cn = _get_autocert_cn()
        if tls_cn:
            # autocert currently bundles certs with the key at the end which postfix doesn't like:
            # `warning: error loading chain from /etc/postfix/ssl/{...}.pem: key not first`
            # Let's not use the newer `smtpd_tls_chain_files` postfix config for now.
            # tls_cert_key = '/etc/postfix/ssl/{}.pem'.format(tls_cn)
            tls_cert = "/etc/postfix/ssl/{}.crt".format(tls_cn)
            tls_key = "/etc/postfix/ssl/{}.key".format(tls_cn)
            tls_dh_params = "/etc/postfix/ssl/dhparams.pem"
        if not os.path.exists(tls_dh_params):
            subprocess.call(["openssl", "dhparam", "-out", tls_dh_params, "2048"])

        fqdn = socket.getfqdn()
        if self._charm_state.smtp_relay_config.domain:
            fqdn = (
                f"{self.unit.name.replace("/", "-")}.{self._charm_state.smtp_relay_config.domain}"
            )

        smtpd_recipient_restrictions = self._smtpd_recipient_restrictions()
        smtpd_relay_restrictions = self._smtpd_relay_restrictions()
        smtpd_sender_restrictions = self._smtpd_sender_restrictions()

        virtual_alias_maps_type = self._charm_state.smtp_relay_config.virtual_alias_maps_type

        context = {
            "JUJU_HEADER": JUJU_HEADER,
            "fqdn": fqdn,
            "hostname": socket.gethostname(),
            "connection_limit": self._charm_state.smtp_relay_config.connection_limit,
            "enable_rate_limits": self._charm_state.smtp_relay_config.enable_rate_limits,
            "enable_sender_login_map": self._charm_state.smtp_relay_config.sender_login_maps,
            "enable_smtp_auth": self._charm_state.smtp_relay_config.enable_smtp_auth,
            "enable_spf": self._charm_state.smtp_relay_config.enable_spf,
            "enable_tls_policy_map": self._charm_state.smtp_relay_config.tls_policy_maps,
            "header_checks": self._charm_state.smtp_relay_config.header_checks,
            "message_size_limit": self._charm_state.smtp_relay_config.message_size_limit,
            "milter": self._get_milters(),
            "myorigin": False,  # XXX: Configurable when given hostname override
            "mynetworks": self._charm_state.smtp_relay_config.allowed_relay_networks,
            "relayhost": self._charm_state.smtp_relay_config.relay_host,
            "relay_domains": self._charm_state.smtp_relay_config.relay_domains,
            "relay_recipient_maps": self._charm_state.smtp_relay_config.relay_recipient_maps,
            "relay_recipient_maps_combined": self._charm_state.smtp_relay_config.relay_recipient_maps == "COMBINED",
            "restrict_recipients": self._charm_state.smtp_relay_config.restrict_recipients,
            "smtp_header_checks": self._charm_state.smtp_relay_config.smtp_header_checks,
            "smtpd_recipient_restrictions": ", ".join(smtpd_recipient_restrictions),
            "smtpd_relay_restrictions": ", ".join(smtpd_relay_restrictions),
            "smtpd_sender_restrictions": ", ".join(smtpd_sender_restrictions),
            "spf_check_maps": self._charm_state.smtp_relay_config.spf_check_maps,
            "tls_cert_key": tls_cert_key,
            "tls_cert": tls_cert,
            "tls_key": tls_key,
            "tls_ciphers": self._charm_state.smtp_relay_config.tls_ciphers,
            "tls_dh_params": tls_dh_params,
            "tls_exclude_ciphers": self._charm_state.smtp_relay_config.tls_exclude_ciphers,
            "tls_protocols": self._charm_state.smtp_relay_config.tls_protocols,
            "tls_security_level": self._charm_state.smtp_relay_config.tls_security_level,
            "transport_maps": self._charm_state.smtp_relay_config.transport_maps,
            "virtual_alias_domains": self._charm_state.smtp_relay_config.virtual_alias_domains,
            "virtual_alias_maps": self._charm_state.smtp_relay_config.virtual_alias_maps,
            "virtual_alias_maps_type": virtual_alias_maps_type,
        }
        base = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        env = Environment(loader=FileSystemLoader(base))
        template = env.get_template("templates/postfix_main_cf.tmpl")
        contents = template.render(context)
        with open(os.path.join(POSTFIX_CONF_DIR, "main.cf"), "w") as file:
            file.write(contents)
        template = env.get_template("templates/postfix_master_cf.tmpl")
        with open(os.path.join(POSTFIX_CONF_DIR, "master.cf"), "w") as file:
            file.write(contents)
        maps = {
            "append_envelope_to_header": "regexp:{}".format(os.path.join(POSTFIX_CONF_DIR, 'append_envelope_to_header')),
            "header_checks": "regexp:{}".format(os.path.join(POSTFIX_CONF_DIR, 'header_checks')),
            "relay_access_sources": "cidr:{}".format(os.path.join(POSTFIX_CONF_DIR, 'relay_access')),
            "relay_recipient_maps": "hash:{}".format(os.path.join(POSTFIX_CONF_DIR, 'relay_recipient')),
            "restrict_recipients": "hash:{}".format(os.path.join(POSTFIX_CONF_DIR, 'restricted_recipients')),
            "restrict_senders": "hash:{}".format(os.path.join(POSTFIX_CONF_DIR, 'restricted_senders')),
            "sender_access": "hash:{}".format(os.path.join(POSTFIX_CONF_DIR, 'access')),
            "sender_login_maps": "hash:{}".format(os.path.join(POSTFIX_CONF_DIR, 'sender_login')),
            "smtp_header_checks": "regexp:{}".format(os.path.join(POSTFIX_CONF_DIR, 'smtp_header_checks')),
            "spf_check_maps": "hash:{}".format(os.path.join(POSTFIX_CONF_DIR, 'spf_checks')),
            "tls_policy_maps": "hash:{}".format(os.path.join(POSTFIX_CONF_DIR, 'tls_policy')),
            "transport_maps": "hash:{}".format(os.path.join(POSTFIX_CONF_DIR, 'transport')),
            "virtual_alias_maps": "{}:{}".format(virtual_alias_maps_type, os.path.join(POSTFIX_CONF_DIR, 'virtual_alias')),
        }
        sender_access_content = self._charm_state.smtp_relay_config.restrict_sender_access
        if sender_access_content and not sender_access_content.startswith("MANUAL"):
            sender_access_content = ''
            for domain in ' '.join(self._charm_state.smtp_relay_config.restrict_sender_access.split(',')).split():
                sender_access_content += '{:35s} OK\n'.format(domain)
        map_contents = {
            "append_envelope_to_header": "/^(.*)$/ PREPEND X-Envelope-To: $1",
            "header_checks": self._charm_state.smtp_relay_config.header_checks,
            "relay_access_sources": self._charm_state.smtp_relay_config.relay_access_sources,
            "relay_recipient_maps": self._charm_state.smtp_relay_config.relay_recipient_maps,
            "restrict_recipients": self._charm_state.smtp_relay_config.restrict_recipients,
            "restrict_senders": self._charm_state.smtp_relay_config.restrict_senders,
            "sender_access": sender_access_content,
            "sender_login_maps": self._charm_state.smtp_relay_config.sender_login_maps,
            "smtp_header_checks": self._charm_state.smtp_relay_config.smtp_header_checks,
            "spf_check_maps": self._charm_state.smtp_relay_config.spf_check_maps,
            "tls_policy_maps": self._charm_state.smtp_relay_config.tls_policy_maps,
            "transport_maps": self._charm_state.smtp_relay_config.transport_maps,
            "virtual_alias_maps": self._charm_state.smtp_relay_config.virtual_alias_maps,
        }

        # Ensure various maps exists before starting/restarting postfix.
        for key, pmap in maps.items():
            create_update_map(map_contents[key], pmap)

        # TODO Perhaps just a template?
        self._update_aliases(self._charm_state.smtp_relay_config.admin_email)

        host.service_start("postfix")
        self.unit.status = ops.MaintenanceStatus("Reloading postfix due to config changes")
        host.service_reload("postfix")
        self.model.open_port("tcp", 25)
        # Ensure service is running.
        host.service_start("postfix")
    
    def configure_policyd_spf(self):
        if not self._charm_state.smtp_relay_config.enable_spf:
            self.unit.status = ops.MaintenanceStatus("Postfix policy server for SPF checking (policyd-spf) disabled")
            return

        self.unit.status = ops.MaintenanceStatus("Setting up Postfix policy server for SPF checking (policyd-spf)")

        context = {
            "JUJU_HEADER": JUJU_HEADER,
            "skip_addresses": self._charm_state.smtp_relay_config.spf_skip_addresses,
        }
        base = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        env = Environment(loader=FileSystemLoader(base))
        template = env.get_template("templates/policyd_spf_conf.tmpl")
        contents = template.render(context)
        with open("/etc/postfix-policyd-spf-python/policyd-spf.conf", "w") as file:
            file.write(contents)


if __name__ == "__main__":  # pragma: nocover
    ops.main.main(SmtpRelayCharm)
