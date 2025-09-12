# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Postfix Service Layer."""

import os
import subprocess  # nosec
from typing import TYPE_CHECKING, NamedTuple

from reactive import utils

if TYPE_CHECKING:
    from pydantic import IPvAnyNetwork

    from state import State


def _smtpd_relay_restrictions(charm_state: "State") -> list[str]:
    smtpd_relay_restrictions = ["permit_mynetworks"]
    if bool(charm_state.relay_access_sources):
        smtpd_relay_restrictions.append("check_client_access cidr:/etc/postfix/relay_access")

    if charm_state.enable_smtp_auth:
        if charm_state.sender_login_maps:
            smtpd_relay_restrictions.append("reject_known_sender_login_mismatch")
        if charm_state.restrict_senders:
            smtpd_relay_restrictions.append("reject_sender_login_mismatch")
        smtpd_relay_restrictions.append("permit_sasl_authenticated")

    smtpd_relay_restrictions.append("defer_unauth_destination")

    return smtpd_relay_restrictions


def _smtpd_sender_restrictions(charm_state: "State") -> list[str]:
    smtpd_sender_restrictions = []
    if charm_state.enable_reject_unknown_sender_domain:
        smtpd_sender_restrictions.append("reject_unknown_sender_domain")
    smtpd_sender_restrictions.append("check_sender_access hash:/etc/postfix/access")
    if charm_state.restrict_sender_access:
        smtpd_sender_restrictions.append("reject")

    return smtpd_sender_restrictions


def _smtpd_recipient_restrictions(charm_state: "State") -> list[str]:
    smtpd_recipient_restrictions = []
    if charm_state.append_x_envelope_to:
        smtpd_recipient_restrictions.append(
            "check_recipient_access regexp:/etc/postfix/append_envelope_to_header"
        )

    if charm_state.restrict_senders:
        smtpd_recipient_restrictions.append(
            "check_sender_access hash:/etc/postfix/restricted_senders"
        )
    smtpd_recipient_restrictions.extend(charm_state.additional_smtpd_recipient_restrictions)

    if charm_state.enable_spf:
        smtpd_recipient_restrictions.append("check_policy_service unix:private/policyd-spf")

    return smtpd_recipient_restrictions


def construct_postfix_config_file_content(  # pylint: disable=too-many-arguments
    *,
    charm_state: "State",
    tls_dh_params_path: str,
    tls_cert_path: str,
    tls_key_path: str,
    tls_cert_key_path,
    fqdn: str,
    hostname: str,
    milters: str,
    template_path: str,
) -> str:
    context = {
        "JUJU_HEADER": utils.JUJU_HEADER,
        "fqdn": fqdn,
        "hostname": hostname,
        "connection_limit": charm_state.connection_limit,
        "enable_rate_limits": charm_state.enable_rate_limits,
        "enable_sender_login_map": bool(charm_state.sender_login_maps),
        "enable_smtp_auth": charm_state.enable_smtp_auth,
        "enable_spf": charm_state.enable_spf,
        "enable_tls_policy_map": bool(charm_state.tls_policy_maps),
        "header_checks": bool(charm_state.header_checks),
        "milter": milters,
        "mynetworks": ",".join(charm_state.allowed_relay_networks),
        "relayhost": charm_state.relay_host,
        "relay_domains": " ".join(charm_state.relay_domains),
        "relay_recipient_maps": bool(charm_state.relay_recipient_maps),
        "restrict_recipients": bool(charm_state.restrict_recipients),
        "smtp_header_checks": bool(charm_state.smtp_header_checks),
        "smtpd_recipient_restrictions": ", ".join(_smtpd_recipient_restrictions(charm_state)),
        "smtpd_relay_restrictions": ", ".join(_smtpd_relay_restrictions(charm_state)),
        "smtpd_sender_restrictions": ", ".join(_smtpd_sender_restrictions(charm_state)),
        "tls_cert_key": tls_cert_key_path,
        "tls_cert": tls_cert_path,
        "tls_key": tls_key_path,
        "tls_ciphers": charm_state.tls_ciphers.value if charm_state.tls_ciphers else None,
        "tls_dh_params": tls_dh_params_path,
        "tls_exclude_ciphers": ", ".join(charm_state.tls_exclude_ciphers),
        "tls_protocols": " ".join(charm_state.tls_protocols),
        "tls_security_level": (
            charm_state.tls_security_level.value if charm_state.tls_security_level else None
        ),
        "transport_maps": bool(charm_state.transport_maps),
        "virtual_alias_domains": " ".join(charm_state.virtual_alias_domains),
        "virtual_alias_maps": bool(charm_state.virtual_alias_maps),
        "virtual_alias_maps_type": charm_state.virtual_alias_maps_type.value,
    }

    return utils.render_jinja2_template(context, template_path)


def _create_update_map(content, postmap: str) -> bool:
    changed = False

    (pmtype, pmfname) = postmap.split(":")
    if not os.path.exists(pmfname):
        with open(pmfname, "a", encoding="utf-8"):
            os.utime(pmfname, None)
        changed = True

    contents = utils.JUJU_HEADER + content + "\n"
    changed = utils.write_file(contents, pmfname) or changed

    if changed and pmtype == "hash":
        subprocess.call(["postmap", postmap])  # nosec

    return changed


def ensure_postmap_files(postfix_conf_dir: str, charm_state: "State") -> bool:
    """Ensure various postfix files exist and are up-to-date with the current charm state.

    Args:
        postfix_conf_dir: directory where postfix config files are stored.
        charm_state: current charm state.

    Returns:
        True if any map was created or updated.
    """

    class PostmapEntry(NamedTuple):
        """A container for the postmap and its content.

        Attributes:
            postmap: The full Postfix lookup table string.
            content: The content to be written to the map's source file.
        """
        postmap: str
        content: str

        @classmethod
        def create(cls, pmap_type: str, pmap_name: str, content: str) -> "PostmapEntry":
            return cls(
                postmap=f"{pmap_type}:{os.path.join(postfix_conf_dir, pmap_name)}",
                content=content,
            )

    # Create a map of all the maps we may need to create/update from the charm state.
    maps = {
        "append_envelope_to_header": PostmapEntry.create(
            "regexp",
            "append_envelope_to_header",
            "/^(.*)$/ PREPEND X-Envelope-To: $1",
        ),
        "header_checks": PostmapEntry.create(
            "regexp",
            "header_checks",
            ";".join(charm_state.header_checks),
        ),
        "relay_access_sources": PostmapEntry.create(
            "cidr",
            "relay_access",
            "\n".join(charm_state.relay_access_sources),
        ),
        "relay_recipient_maps": PostmapEntry.create(
            "hash",
            "relay_recipient",
            "\n".join(
                [f"{key} {value}" for key, value in charm_state.relay_recipient_maps.items()]
            ),
        ),
        "restrict_recipients": PostmapEntry.create(
            "hash",
            "restricted_recipients",
            "\n".join(
                [f"{key} {value.value}" for key, value in charm_state.restrict_recipients.items()]
            ),
        ),
        "restrict_senders": PostmapEntry.create(
            "hash",
            "restricted_senders",
            "\n".join(
                [f"{key} {value.value}" for key, value in charm_state.restrict_senders.items()]
            ),
        ),
        "sender_access": PostmapEntry.create(
            "hash",
            "access",
            "".join([f"{domain:35} OK\n" for domain in charm_state.restrict_sender_access]),
        ),
        "sender_login_maps": PostmapEntry.create(
            "hash",
            "sender_login",
            "\n".join([f"{key} {value}" for key, value in charm_state.sender_login_maps.items()]),
        ),
        "smtp_header_checks": PostmapEntry.create(
            "regexp",
            "smtp_header_checks",
            ";".join(charm_state.smtp_header_checks),
        ),
        "tls_policy_maps": PostmapEntry.create(
            "hash",
            "tls_policy",
            "\n".join([f"{key} {value}" for key, value in charm_state.tls_policy_maps.items()]),
        ),
        "transport_maps": PostmapEntry.create(
            "hash",
            "transport",
            "\n".join([f"{key} {value}" for key, value in charm_state.transport_maps.items()]),
        ),
        "virtual_alias_maps": PostmapEntry.create(
            charm_state.virtual_alias_maps_type.value,
            "virtual_alias",
            "\n".join([f"{key} {value}" for key, value in charm_state.virtual_alias_maps.items()]),
        ),
    }

    # Ensure various maps exists before starting/restarting postfix.
    changed = False
    for entry in maps.values():
        changed = _create_update_map(entry.content, entry.postmap) or changed
    return changed


def construct_policyd_spf_config_file_content(spf_skip_addresses: "IPvAnyNetwork"):
    context = {
        "JUJU_HEADER": utils.JUJU_HEADER,
        "skip_addresses": ",".join([str(address) for address in spf_skip_addresses]),
    }
    contents = utils.render_jinja2_template(context, "templates/policyd_spf_conf.tmpl")
    return contents
