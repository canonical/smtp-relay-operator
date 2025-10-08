#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Postfix Relay charm."""

import hashlib
import logging
import socket
import subprocess  # nosec
from pathlib import Path
from typing import Any

import ops
from charms.operator_libs_linux.v0 import apt
from charms.operator_libs_linux.v1 import systemd

import utils
from dovecot import (
    construct_dovecot_config_file_content,
    construct_dovecot_user_file_content,
)
from postfix import (
    PostfixMap,
    build_postfix_maps,
    construct_policyd_spf_config_file_content,
    construct_postfix_config_params,
)
from state import ConfigurationError, PostfixLookupTableType, State
from tls import get_tls_config_paths

logger = logging.getLogger(__name__)


APT_PACKAGES = [
    "dovecot-core",
    "postfix",
    "postfix-policyd-spf-python",
]

TEMPLATES_DIRPATH = Path("templates")
FILES_DIRPATH = Path("files")

POSTFIX_NAME = "postfix"
POSTFIX_PORT = ops.Port("tcp", 25)
POSTFIX_CONF_DIRPATH = Path("/etc/postfix")
ALIASES_FILEPATH = Path("/etc/aliases")
POLICYD_SPF_FILEPATH = Path("/etc/postfix-policyd-spf-python/policyd-spf.conf")
TLS_DH_PARAMS_FILEPATH = Path("/etc/ssl/private/dhparams.pem")
MILTER_PORT = ops.Port("tcp", 8892)
MAIN_CF = "main.cf"
MAIN_CF_TMPL = "postfix_main_cf.tmpl"
MASTER_CF = "master.cf"
MASTER_CF_TMPL = "postfix_master_cf.tmpl"

DOVECOT_NAME = "dovecot"
DOVECOT_PORTS = (ops.Port("tcp", 465), ops.Port("tcp", 587))
DOVECOT_CONFIG_FILEPATH = Path("/etc/dovecot/dovecot.conf")
DOVECOT_USERS_FILEPATH = Path("/etc/dovecot/users")

LOG_ROTATE_SYSLOG = Path("/etc/logrotate.d/rsyslog")
FGREPMAIL_LOGS_SRC = FILES_DIRPATH / "fgrepmail-logs.py"
FGREPMAIL_LOGS_DST = Path("/usr/local/bin/fgrepmail-logs")
RSYSLOG_CONF_SRC = FILES_DIRPATH / "50-default.conf"
RSYSLOG_CONF_DST = Path("/etc/rsyslog.d/50-default.conf")

MILTER_RELATION_NAME = "milter"
PEER_RELATION_NAME = "peer"


class PostfixRelayCharm(ops.CharmBase):
    """Postfix Relay."""

    def __init__(self, *args: Any) -> None:
        """Postfix Relay."""
        super().__init__(*args)

        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed, self._reconcile)
        self.framework.observe(self.on[PEER_RELATION_NAME].relation_changed, self._reconcile)
        self.framework.observe(self.on[MILTER_RELATION_NAME].relation_changed, self._reconcile)

    def _on_install(self, _: ops.InstallEvent) -> None:
        """Handle the install event."""
        self.unit.status = ops.MaintenanceStatus("Installing packages")
        apt.add_package(APT_PACKAGES, update_cache=True)

        utils.copy_file(FGREPMAIL_LOGS_SRC, FGREPMAIL_LOGS_DST, perms=0o755)
        utils.copy_file(RSYSLOG_CONF_SRC, RSYSLOG_CONF_DST, perms=0o644)
        contents = utils.update_logrotate_conf(LOG_ROTATE_SYSLOG)
        utils.write_file(contents, LOG_ROTATE_SYSLOG)

        self.unit.status = ops.WaitingStatus()

    def _reconcile(self, _: ops.EventBase) -> None:
        self.unit.status = ops.MaintenanceStatus("Reconciling SMTP relay")
        try:
            charm_state = State.from_charm(self.config)
        except ConfigurationError:
            logger.exception("Error validating the charm configuration.")
            self.unit.status = ops.BlockedStatus("Invalid config")
            return

        self._configure_auth(charm_state)
        self._configure_relay(charm_state)
        self._configure_policyd_spf(charm_state)
        self.unit.status = ops.ActiveStatus()

    def _configure_auth(self, charm_state: State) -> None:
        """Ensure SMTP authentication is configured or disabled via Dovecot."""
        self.unit.status = ops.MaintenanceStatus("Setting up SMTP authentication (dovecot)")

        contents = construct_dovecot_config_file_content(
            DOVECOT_USERS_FILEPATH, charm_state.enable_smtp_auth
        )
        utils.write_file(contents, DOVECOT_CONFIG_FILEPATH)

        if charm_state.smtp_auth_users:
            contents = construct_dovecot_user_file_content(charm_state.smtp_auth_users)
            utils.write_file(contents, DOVECOT_USERS_FILEPATH, perms=0o640, group=DOVECOT_NAME)

        if not charm_state.enable_smtp_auth:
            logger.info("SMTP authentication not enabled, ensuring ports are closed")
            for port in DOVECOT_PORTS:
                self.unit.close_port(port.protocol, port.port)
            systemd.service_pause(DOVECOT_NAME)
            return

        logger.info("Opening additional ports for SMTP authentication")
        for port in DOVECOT_PORTS:
            self.unit.open_port(port.protocol, port.port)

        if not systemd.service_running(DOVECOT_NAME):
            systemd.service_resume(DOVECOT_NAME)
            return

        systemd.service_reload(DOVECOT_NAME)

    def _generate_fqdn(self, domain: str) -> str:
        return f"{self.unit.name.replace('/', '-')}.{domain}"

    def _configure_relay(self, charm_state: State) -> None:
        """Generate and apply Postfix configuration."""
        self.unit.status = ops.MaintenanceStatus("Setting up Postfix relay")

        tls_config_paths = get_tls_config_paths(TLS_DH_PARAMS_FILEPATH)
        fqdn = self._generate_fqdn(charm_state.domain) if charm_state.domain else socket.getfqdn()
        hostname = socket.gethostname()
        milters = self._get_milters()

        context = construct_postfix_config_params(
            charm_state=charm_state,
            tls_dh_params_path=tls_config_paths.tls_dh_params,
            tls_cert_path=tls_config_paths.tls_cert,
            tls_key_path=tls_config_paths.tls_key,
            tls_cert_key_path=tls_config_paths.tls_cert_key,
            fqdn=fqdn,
            hostname=hostname,
            milters=milters,
        )
        contents = utils.render_jinja2_template(context, TEMPLATES_DIRPATH / MAIN_CF_TMPL)
        utils.write_file(contents, POSTFIX_CONF_DIRPATH / MAIN_CF)
        contents = utils.render_jinja2_template(context, TEMPLATES_DIRPATH / MASTER_CF_TMPL)
        utils.write_file(contents, POSTFIX_CONF_DIRPATH / MASTER_CF)

        postfix_maps = build_postfix_maps(POSTFIX_CONF_DIRPATH, charm_state)
        self._apply_postfix_maps(list(postfix_maps.values()))

        logger.info("Updating aliases")
        self._update_aliases(charm_state.admin_email)

        self.unit.open_port(POSTFIX_PORT.protocol, POSTFIX_PORT.port)

        if not systemd.service_running(POSTFIX_NAME):
            systemd.service_resume(POSTFIX_NAME)
            return

        systemd.service_reload(POSTFIX_NAME)

    @staticmethod
    def _apply_postfix_maps(postfix_maps: list[PostfixMap]) -> None:
        logger.info("Applying postfix maps")
        for postfix_map in postfix_maps:
            changed = utils.write_file(postfix_map.content, postfix_map.path)
            if changed and postfix_map.type == PostfixLookupTableType.HASH:
                subprocess.check_call(["postmap", postfix_map.source])  # nosec

    @staticmethod
    def _calculate_offset(seed: str, length: int = 2) -> int:
        result = hashlib.md5(seed.encode("utf-8")).hexdigest()[:length]  # nosec
        return int(result, 16)

    def _get_peers(self) -> list[str]:
        """Build a sorted list of all peer unit names."""
        peers = {self.unit.name}

        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        if peer_relation:
            peers |= {unit.name for unit in peer_relation.units}

        # Sorting ensures a consistent, stable order on all units.
        # The index of this list becomes the unit's "rank".
        return sorted(peers)

    def _get_milters(self) -> str:
        # TODO: We'll bring up a balancer in front of the list of
        # backend/related milters but for now, let's just map 1-to-1 and
        # try spread depending on how many available units.

        peers = self._get_peers()
        index = peers.index(self.unit.name)
        # We want to ensure multiple applications related to the same set
        # of milters are better spread across them. e.g. postfix-relay-A with
        # 2 units, postfix-relay-B also with 2 units, but dkim-signing with 5
        # units. We don't want only the first 2 dkim-signing units to be
        # used.
        offset = index + self._calculate_offset(self.app.name)

        result = []

        for relation in self.model.relations[MILTER_RELATION_NAME]:
            if not relation.units:
                continue

            remote_units = sorted(relation.units, key=lambda u: u.name)
            selected_unit = remote_units[offset % len(remote_units)]

            address = relation.data[selected_unit].get("ingress-address")
            # Default to TCP/8892
            port = relation.data[selected_unit].get("port", MILTER_PORT.port)

            if address:
                result.append(f"inet:{address}:{port}")

        return " ".join(result)

    @staticmethod
    def _update_aliases(admin_email: str | None) -> None:

        aliases = []
        if ALIASES_FILEPATH.is_file():
            with ALIASES_FILEPATH.open("r", encoding="utf-8") as f:
                aliases = f.readlines()

        add_devnull = True
        new_aliases = []
        for line in aliases:
            if add_devnull and line.startswith("devnull:"):
                add_devnull = False
            if not line.startswith("root:"):
                new_aliases.append(line)

        if add_devnull:
            new_aliases.append("devnull:       /dev/null\n")
        if admin_email:
            new_aliases.append(f"root:          {admin_email}\n")

        changed = utils.write_file("".join(new_aliases), ALIASES_FILEPATH)
        if changed:
            subprocess.check_call(["newaliases"])  # nosec

    def _configure_policyd_spf(self, charm_state: State) -> None:
        """Configure Postfix SPF policy server (policyd-spf) based on charm state."""
        self.unit.status = ops.MaintenanceStatus("Configuring Postfix policy server")
        if not charm_state.enable_spf:
            logger.info("Postfix policy server for SPF checking (policyd-spf) disabled")
            return

        logger.info("Setting up Postfix policy server for SPF checking (policyd-spf)")

        contents = construct_policyd_spf_config_file_content(charm_state.spf_skip_addresses)
        utils.write_file(contents, POLICYD_SPF_FILEPATH)


if __name__ == "__main__":  # pragma: nocover
    ops.main(PostfixRelayCharm)
