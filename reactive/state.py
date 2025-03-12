# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm state."""
import dataclasses
import itertools
import logging
import typing
from enum import Enum

from typing_extensions import Annotated
from pydantic import EmailStr, Field, IPvAnyNetwork, ValidationError

logger = logging.getLogger(__name__)


class CharmStateBaseError(Exception):
    """Represents an error with charm state."""


class ConfigurationError(CharmStateBaseError):
    """Exception raised when a charm configuration is found to be invalid.

    Attributes:
        msg: Explanation of the error.
    """

    def __init__(self, msg: str):
        """Initialize a new instance of the ConfigurationError exception.

        Args:
            msg: Explanation of the error.
        """
        self.msg = msg


class SmtpTlsCipherGrade(str, Enum):
    """TLS cipher grade.

    Attributes:
        HIGH: "HIGH"
        MEDIUM: "MEDIUM"
        NULL: "NULL"
        LOW: "LOW"º
        EXPORT: "EXPORT"
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    NULL = "NULL"
    LOW = "LOW"
    EXPORT = "EXPORT"


class SmtpTlsSecurityLevel(str, Enum):
    """TLS secutiry level.

    Attributes:
        NONE: "none"
        MAY: "may"
        ENCRYPT: "encrypt"
    """

    NONE = "none"
    MAY = "may"
    ENCRYPT = "encrypt"


class SmtpRecipientRestrictions(str, Enum):
    """SMTPD recipient restrictions.

    Attributes:
        CHECK_RECIPIENT_ACCESS: "check_recipient_access"
        CHECK_RECIPIENT_A_ACCESS: "check_recipient_a_access"
        CHECK_RECIPIENT_MX_ACCESS: "check_recipient_mx_access"
        CHECK_RECIPIENT_NS_ACCESS: "check_recipient_ns_access"
        PERMIT_AUTH_DESTINATION: "permit_auth_destination"
        PERMIT_MX_BACKUP: "permit_mx_backup"
        REJECT_NON_FQDN_RECIPIENT: "reject_non_fqdn_recipient"
        REJECT_RHSBL_RECIPIENT: "reject_rhsbl_recipient rbl_domain=d.d.d.d"
        REJECT_UNAUTH_DESTINATION: "reject_unauth_destination"
        DEFER_UNAUTH_DESTINATION: "defer_unauth_destination"
        REJECT_UNKNOWN_RECIPIENT_DOMAIN: "reject_unknown_recipient_domain"
        REJECT_UNLISTED_RECIPIENT: "reject_unlisted_recipient"
        REJECT_UNVERIFIED_RECIPIENT: "reject_unverified_recipient"
    """

    CHECK_RECIPIENT_ACCESS = "check_recipient_access"
    CHECK_RECIPIENT_A_ACCESS = "check_recipient_a_access"
    CHECK_RECIPIENT_MX_ACCESS = "check_recipient_mx_access"
    CHECK_RECIPIENT_NS_ACCESS = "check_recipient_ns_access"
    PERMIT_AUTH_DESTINATION = "permit_auth_destination"
    PERMIT_MX_BACKUP = "permit_mx_backup"
    REJECT_NON_FQDN_RECIPIENT = "reject_non_fqdn_recipient"
    REJECT_RHSBL_RECIPIENT = "reject_rhsbl_recipient rbl_domain=d.d.d.d"
    REJECT_UNAUTH_DESTINATION = "reject_unauth_destination"
    DEFER_UNAUTH_DESTINATION = "defer_unauth_destination"
    REJECT_UNKNOWN_RECIPIENT_DOMAIN = "reject_unknown_recipient_domain"
    REJECT_UNLISTED_RECIPIENT = "reject_unlisted_recipient"
    REJECT_UNVERIFIED_RECIPIENT = "reject_unverified_recipient"


class PostfixLookupTableType(str, Enum):
    """Postfix lookup table types.

    Attributes:
        HASH: "hash"
        REGEXP: "regexp"
    """

    HASH = "hash"
    REGEXP = "regexp"


@dataclasses.dataclass()
class State:  # pylint: disable=too-few-public-methods,too-many-instance-attributes
    """The Indico operator charm state.

    Attributes:
        admin_email: Administrator's email address where root@ emails will go to
        additional_smtpd_recipient_restrictions: List of additional recipient restrictions.
        allowed_relay_networks: List of allowed networks to relay without authenticating.
        append_x_envelope_to: Append the X-Envelope-To header.
        domain: Primary domain for hostname generation.
        enable_smtp_auth: If SMTP authentication is enabled.
        enable_spf: If SPF checks are enabled.
        log_retention: the log retention period.
        relay_domains: List of destination domains to relay mail to.
        relay_host: SMTP relay host to forward mail to.
        restrict_sender_access: List of domains, addresses or hosts to restrict relay from
        smtp_auth_users: List of user and crypt password hashe pairs separated by ':'.
        spf_skip_addresses: List of CIDR addresses to skip SPF checks.
        tls_ciphers: Minimum TLS cipher grade for TLS encryption.
        tls_exclude_ciphers: List of TLS ciphers or cipher types to exclude from the cipher list.
        tls_protocols: List of TLS protocols accepted by the Postfix SMTP.
        tls_security_level: The TLS security level.
        virtual_alias_domains: List of domains for which all addresses are aliased.
        virtual_alias_maps_type: The virtual alias map type.
    """

    admin_email: EmailStr
    additional_smtpd_recipient_restrictions: list[SmtpRecipientRestrictions]
    allowed_relay_networks: list[IPvAnyNetwork]
    append_x_envelope_to: bool
    domain: str | None
    enable_smtp_auth: bool
    enable_spf: bool
    log_retention: int
    relay_domains: list[Annotated[str, Field(min_length=1)]]
    relay_host: Annotated[str, Field(min_length=1)]
    restrict_sender_access: list[Annotated[str, Field(min_length=1)]]
    smtp_auth_users: list[str]
    spf_skip_addresses: list[IPvAnyNetwork]
    tls_ciphers: SmtpTlsCipherGrade
    tls_exclude_ciphers: list[Annotated[str, Field(min_length=1)]]
    tls_protocols: list[Annotated[str, Field(min_length=1)]]
    tls_security_level: SmtpTlsSecurityLevel
    virtual_alias_domains: list[Annotated[str, Field(min_length=1)]]
    virtual_alias_maps_type: PostfixLookupTableType

    @classmethod
    def from_charm(cls, config: dict[str, typing.Any]) -> "State":
        """Initialize the state from charm.

        Args:
            config: the charm configuration.

        Returns:
            Current charm state.

        Raises:
            ConfigurationError: if invalid state values were encountered.
        """
        try:
            allowed_relay_networks = (
                config["allowed_relay_networks"].split(",")
                if "allowed_relay_networks" in config
                else []
            )
            additional_smtpd_recipient_restrictions = (
                config["additional_smtpd_recipient_restrictions"].split(",")
                if "additional_smtpd_recipient_restrictions" in config
                else []
            )
            relay_domains = config["relay_domains"].split(",") if "relay_domains" in config else []
            restrict_sender_access = (
                config["restrict_sender_access"].split(",")
                if "restrict_sender_access" in config
                else []
            )
            spf_skip_addresses = (
                config["spf_skip_addresses"].split(",") if "spf_skip_addresses" in config else []
            )
            tls_exclude_ciphers = (
                config["tls_exclude_ciphers"].split(",") if "tls_exclude_ciphers" in config else []
            )
            tls_protocols = (
                config["tls_protocols"].split(",") if "tls_protocols" in config else []
            )
            virtual_alias_domains = (
                config["virtual_alias_domains"].split(",")
                if "virtual_alias_domains"
                in config else []
            )

            return cls(
                admin_email=config["admin_email"],
                additional_smtpd_recipient_restrictions=additional_smtpd_recipient_restrictions,
                allowed_relay_networks=allowed_relay_networks,
                append_x_envelope_to=config["append_x_envelope_to"],
                domain=config["domain"],
                enable_smtp_auth=config["enable_smtp_auth"],
                enable_spf=config["enable_spf"],
                log_retention=config["log_retention"],
                relay_domains=relay_domains,
                relay_host=config["relay_host"],
                restrict_sender_access=restrict_sender_access,
                smtp_auth_users=(
                    config["smtp_auth_users"].split(",") if config["smtp_auth_users"] else []
                ),
                spf_skip_addresses=spf_skip_addresses,
                tls_ciphers=config["tls_ciphers"],
                tls_exclude_ciphers=tls_exclude_ciphers,
                tls_protocols=tls_protocols,
                tls_security_level=config["tls_security_level"],
                virtual_alias_domains=virtual_alias_domains,
                virtual_alias_maps_type=config["virtual_alias_maps_type"],
            )

        except ValidationError as exc:
            error_fields = set(
                itertools.chain.from_iterable(error["loc"] for error in exc.errors())
            )
            error_field_str = " ".join(f"{f}" for f in error_fields)
            raise ConfigurationError(f"invalid configuration: {error_field_str}") from exc
