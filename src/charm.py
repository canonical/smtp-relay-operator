# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""SMTP Relay charm."""

import hashlib
import socket
import subprocess  # nosec
from pathlib import Path
from typing import Any

import ops

import utils
from dovecot import (
    construct_dovecot_config_file_content,
    construct_dovecot_user_file_content,
)
from lib.charms.operator_libs_linux.v0 import apt
from lib.charms.operator_libs_linux.v1 import systemd
from postfix import (
    PostfixMap,
    build_postfix_maps,
    construct_policyd_spf_config_file_content,
    construct_postfix_config_params,
)
from state import ConfigurationError, State
from tls import get_tls_config_paths

APT_PACKAGES = ["dovecot-common", "postfix-policyd-spf-python", "postfix"]

LOGROTATE_CONF_PATH = Path("/etc/logrotate.d/rsyslog")


class SMTPRelayCharm(ops.CharmBase):
    """SMTP Relay."""

    def __init__(self, *args: Any) -> None:
        """SMTP Relay."""
        super().__init__(*args)

        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed, self._reconcile)
        self.framework.observe(self.on.peer_relation_changed, self._reconcile)
        self.framework.observe(self.on.milter_relation_changed, self._reconcile)

    def _on_install(self, _: ops.InstallEvent) -> None:
        """Handle the install event."""
        self.unit.status = ops.MaintenanceStatus("Installing packages")
        apt.add_package(APT_PACKAGES)
        self._configure_logrotate()

    def _reconcile(self, _: ops.EventBase) -> None:
        self.unit.status = ops.MaintenanceStatus("Reconciling SMTP relay")
        try:
            charm_state = State.from_charm(self.config)
        except ConfigurationError as ex:
            self.unit.status = ops.BlockedStatus(str(ex))
            return

        try:
            self._configure_smtp_auth(charm_state)
            self._configure_smtp_relay(charm_state)
            self._configure_policyd_spf(charm_state)
            self.unit.status = ops.ActiveStatus()
        except Exception as ex:
            self.unit.status = ops.ErrorStatus(str(ex))

    @staticmethod
    def _configure_logrotate(logrotate_conf_path: Path = LOGROTATE_CONF_PATH) -> None:
        """Configure logging."""
        utils.copy_file("files/fgrepmail-logs.py", "/usr/local/bin/fgrepmail-logs", perms=0o755)
        utils.copy_file("files/50-default.conf", "/etc/rsyslog.d/50-default.conf", perms=0o644)
        contents = utils.update_logrotate_conf(logrotate_conf_path)
        utils.write_file(contents, logrotate_conf_path)

    def _configure_smtp_auth(
        self,
        charm_state: State,
        dovecot_config: str = "/etc/dovecot/dovecot.conf",
        dovecot_users: str = "/etc/dovecot/users",
    ) -> None:
        """Ensure SMTP authentication is configured or disabled via Dovecot."""
        self.unit.status = ops.MaintenanceStatus("Setting up SMTP authentication (dovecot)")

        contents = construct_dovecot_config_file_content(
            dovecot_users, charm_state.enable_smtp_auth
        )
        changed = utils.write_file(contents, dovecot_config)

        if charm_state.smtp_auth_users:
            contents = construct_dovecot_user_file_content(charm_state.smtp_auth_users)
            changed = (
                utils.write_file(contents, dovecot_users, perms=0o640, group="dovecot") or changed
            )

        if not charm_state.enable_smtp_auth:
            self.unit.status = ops.MaintenanceStatus(
                "SMTP authentication not enabled, ensuring ports are closed"
            )
            self.unit.close_port("tcp", 465)
            self.unit.close_port("tcp", 587)
            systemd.service_stop("dovecot")
            # XXX: mask systemd service disable
            return

        self.unit.status = ops.MaintenanceStatus(
            "Opening additional ports for SMTP authentication"
        )
        self.unit.open_port("tcp", 465)
        self.unit.open_port("tcp", 587)

        if changed:
            self.unit.status = ops.MaintenanceStatus("Restarting Dovecot due to config changes")
            systemd.service_reload("dovecot")

        # Ensure service is running.
        systemd.service_start("dovecot")

    def _generate_fqdn(self, domain: str) -> str:
        return f"{self.unit.name.replace('/', '-')}.{domain}"

    def _configure_smtp_relay(
        self,
        charm_state: State,
        postfix_conf_dir: str = "/etc/postfix",
        tls_dh_params: str = "/etc/ssl/private/dhparams.pem",
    ) -> None:
        """Generate and apply SMTP relay (Postfix) configuration."""
        self.unit.status = ops.MaintenanceStatus("Setting up SMTP relay")

        tls_config_paths = get_tls_config_paths(tls_dh_params)
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
        contents = utils.render_jinja2_template(context, "templates/postfix_main_cf.tmpl")
        changed = utils.write_file(contents, Path(postfix_conf_dir) / "main.cf")
        contents = utils.render_jinja2_template(context, "templates/postfix_master_cf.tmpl")
        changed = utils.write_file(contents, Path(postfix_conf_dir) / "master.cf") or changed

        postfix_maps = build_postfix_maps(postfix_conf_dir, charm_state)
        changed = self._apply_postfix_maps(list(postfix_maps.values())) or changed

        self._update_aliases(charm_state.admin_email)

        systemd.service_start("postfix")
        if changed:
            self.unit.status = ops.MaintenanceStatus("Reloading postfix due to config changes")
            systemd.service_reload("postfix")
            self.unit.open_port("tcp", 25)
        systemd.service_start("postfix")

    @staticmethod
    def _apply_postfix_maps(postfix_maps: list[PostfixMap]) -> bool:
        any_changed = False
        for postfix_map in postfix_maps:
            changed = False
            if not postfix_map.path.is_file():
                postfix_map.path.touch()
                changed = True
            changed = utils.write_file(postfix_map.content, str(postfix_map.path)) or changed
            if changed and postfix_map.type == "hash":
                subprocess.check_call(["postmap", postfix_map.source])

            any_changed = any_changed or changed
        return changed

    @staticmethod
    def _calculate_offset(seed: str, length: int = 2) -> int:
        result = hashlib.md5(seed.encode("utf-8")).hexdigest()[:length]  # nosec
        return int(result, 16)

    def _get_peers(self) -> list[str]:
        """Build a sorted list of all peer unit names."""
        peers = {self.unit.name}

        peer_relation = self.model.get_relation("peer")
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
        # of milters are better spread across them. e.g. smtp-relay-A with
        # 2 units, smtp-relay-B also with 2 units, but dkim-signing with 5
        # units. We don't want only the first 2 dkim-signing units to be
        # used.
        offset = index + self._calculate_offset(self.app.name)

        result = []

        for relation in self.model.relations["milter"]:
            if not relation.units:
                continue

            remote_units = sorted(relation.units, key=lambda u: u.name)
            selected_unit = remote_units[offset % len(remote_units)]

            address = relation.data[selected_unit]["ingress-address"]
            # Default to TCP/8892
            port = relation.data[selected_unit].get("port", 8892)

            if address:
                result.append(f"inet:{address}:{port}")

        return " ".join(result)

    @staticmethod
    def _update_aliases(admin_email: str | None, aliases_path: str = "/etc/aliases") -> None:
        path = Path(aliases_path)

        aliases = []
        if path.is_file():
            with path.open("r", encoding="utf-8") as f:
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

        changed = utils.write_file("".join(new_aliases), aliases_path)
        if changed:
            subprocess.check_call(["newaliases"])

    def _configure_policyd_spf(
        self,
        charm_state: State,
        policyd_spf_config: str = "/etc/postfix-policyd-spf-python/policyd-spf.conf",
    ) -> None:
        """Configure Postfix SPF policy server (policyd-spf) based on charm state."""
        if not charm_state.enable_spf:
            self.unit.status = ops.MaintenanceStatus(
                "Postfix policy server for SPF checking (policyd-spf) disabled"
            )
            return

        self.unit.status = ops.MaintenanceStatus(
            "Setting up Postfix policy server for SPF checking (policyd-spf)"
        )

        contents = construct_policyd_spf_config_file_content(charm_state.spf_skip_addresses)
        utils.write_file(contents, policyd_spf_config)
