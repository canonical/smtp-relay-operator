from typing import TYPE_CHECKING

import utils

if TYPE_CHECKING:
    from state import State
    from charm import TLSConfigPaths


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


def construct_postfix_config_file_content(
    charm_state: "State",
    tls_config_paths: "TLSConfigPaths",
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
        "tls_cert_key": tls_config_paths.tls_cert_key,
        "tls_cert": tls_config_paths.tls_cert,
        "tls_key": tls_config_paths.tls_key,
        "tls_ciphers": charm_state.tls_ciphers.value if charm_state.tls_ciphers else None,
        "tls_dh_params": tls_config_paths.tls_dh_params,
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
