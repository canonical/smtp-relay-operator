# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm state."""
import dataclasses
import itertools
import logging
import typing
from enum import Enum

from typing_extensions import Annotated
from pydantic import BaseModel, EmailStr, Field, IPvAnyNetwork, ValidationError

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


class SmtpTlsCipherGrade(Enum):
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


class SmtpTlsSecurityLevel(Enum):
    """TLS secutiry level.

    Attributes:
        NONE: "none"
        MAY: "may"
        ENCRYPT: "encrypt"
    """

    NONE = "none"
    MAY = "may"
    ENCRYPT = "encrypt"


class PostfixLookupTableType(Enum):
    """Postfix lookup table types.

    Attributes:
        HASH: "hash"
        REGEXP: "regexp"
    """

    HASH = "hash"
    REGEXP = "regexp"


class AccessMapValue(Enum):
    """Postfix access map valid values.

    Attributes:
        OK: "OK"
        REJECT: "REJECT"
        RESTRICTED: "restricted"
    """

    OK = "OK"
    REJECT = "REJECT"
    RESTRICTED = "restricted"


def _parse_map(raw_map: str) -> dict[str, str]:
    """Parse map input.

    Returns:
        a list of tuples with the map key and value.

    Raises:
        ConfigurationError: if the map is invalid.
    """
    if not raw_map:
        return {}
    access_map_lines = raw_map.split(",")
    access_map = {}
    for raw_line in access_map_lines:
        line = raw_line.split()
        if len(line) != 2:
            raise ConfigurationError(f"Invalid map {raw_map}")
        access_map.update({line[0]: line[1]})
    return access_map


def _parse_access_map(raw_map: str) -> dict[str, AccessMapValue]:
    """Parse access map input.

    Args:
        raw_map: the raw map content.

    Returns:
        a list of tuples with the key and the value.
    """
    parsed_map = _parse_map(raw_map)
    return {key: AccessMapValue(parsed_map[key]) for key in parsed_map.keys()}


def _parse_list(raw_list: str) -> list[str]:
    """Parse list input.

    Args:
        raw_list: the list map content.

    Returns:
        a list of strings.
    """
    return raw_list.split(",") if raw_list else []


@dataclasses.dataclass()
class State(BaseModel):  # pylint: disable=too-few-public-methods,too-many-instance-attributes
    """The Indico operator charm state.

    Attributes:
        additional_smtpd_recipient_restrictions: List of additional recipient restrictions.
        admin_email: Administrator's email address where root@ emails will go to.
        allowed_relay_networks: List of allowed networks to relay without authenticating.
        append_x_envelope_to: Append the X-Envelope-To header.
        connection_limit: Maximum number of SMTP connections allowed.
        domain: Primary domain for hostname generation.
        enable_rate_limits: Enable default rate limiting features.
        enable_reject_unknown_sender_domain: Reject email when sender's domain cannot be resolved.
        enable_smtp_auth: If SMTP authentication is enabled.
        enable_spf: If SPF checks are enabled.
        header_checks: Header checks to perform on inbound email.
        relay_access_sources: List of  entries to restrict access based on CIDR source.
        relay_domains: List of destination domains to relay mail to.
        restrict_recipients: Access map for restrictions by recipient address or domain.
        restrict_senders: Access map for restrictions by sender address or domain.
        relay_host: SMTP relay host to forward mail to.
        relay_recipient_maps: List of of mappings that alias mail addresses or domains to
            addresses.
        restrict_sender_access: List of domains, addresses or hosts to restrict relay from.
        sender_login_maps: List of authenticated users that can send mail.
        smtp_auth_users: List of user and crypt password hashe pairs separated by ':'.
        smtp_header_checks: List of header checks to perform on outbound email.
        spf_skip_addresses: List of CIDR addresses to skip SPF checks.
        tls_ciphers: Minimum TLS cipher grade for TLS encryption.
        tls_exclude_ciphers: List of TLS ciphers or cipher types to exclude from the cipher list.
        tls_policy_maps: List of of mappings for TLS policy.
        tls_protocols: List of TLS protocols accepted by the Postfix SMTP.
        tls_security_level: The TLS security level.
        transport_maps: List of mappings from recipient address to message delivery transport
            or next-hop destination.
        virtual_alias_domains: List of domains for which all addresses are aliased.
        virtual_alias_maps: List of aliases of mail addresses or domains to other local or
            remote addresses.
        virtual_alias_maps_type: The virtual alias map type.
    """

    additional_smtpd_recipient_restrictions: list[str]
    admin_email: EmailStr | None
    allowed_relay_networks: list[IPvAnyNetwork]
    append_x_envelope_to: bool
    domain: str
    enable_rate_limits: bool
    enable_reject_unknown_sender_domain: bool
    enable_smtp_auth: bool
    enable_spf: bool
    header_checks: list[str]
    relay_access_sources: list[str]
    relay_domains: list[Annotated[str, Field(min_length=1)]]
    restrict_recipients: dict[str, AccessMapValue]
    restrict_senders: dict[str, AccessMapValue]
    relay_host: Annotated[str, Field(min_length=1)] | None
    relay_recipient_maps: list[str]
    restrict_sender_access: list[Annotated[str, Field(min_length=1)]]
    sender_login_maps: dict[str, str]
    smtp_auth_users: list[str]
    smtp_header_checks: list[str]
    spf_skip_addresses: list[IPvAnyNetwork]
    tls_ciphers: SmtpTlsCipherGrade | None
    tls_exclude_ciphers: list[Annotated[str, Field(min_length=1)]]
    tls_policy_maps: list[str]
    tls_protocols: list[Annotated[str, Field(min_length=1)]]
    tls_security_level: SmtpTlsSecurityLevel | None
    transport_maps: list[str]
    virtual_alias_domains: list[Annotated[str, Field(min_length=1)]]
    virtual_alias_maps: list[str]
    virtual_alias_maps_type: PostfixLookupTableType
    connection_limit: int = Field(ge=0)


    def __init__(  # pylint: disable=too-many-arguments, too-many-positional-arguments
        self,
        additional_smtpd_recipient_restrictions: list[str],
        admin_email: EmailStr | None,
        allowed_relay_networks: list[IPvAnyNetwork],
        append_x_envelope_to: bool,
        domain: str,
        enable_rate_limits: bool,
        enable_reject_unknown_sender_domain: bool,
        enable_smtp_auth: bool,
        enable_spf: bool,
        header_checks: list[str],
        relay_access_sources: list[str],
        relay_domains: list[Annotated[str, Field(min_length=1)]],
        restrict_recipients: dict[str, AccessMapValue],
        restrict_senders: dict[str, AccessMapValue],
        relay_host: Annotated[str, Field(min_length=1)],
        relay_recipient_maps: list[str],
        restrict_sender_access: list[Annotated[str, Field(min_length=1)]],
        sender_login_maps: dict[str, str],
        smtp_auth_users: list[str],
        smtp_header_checks: list[str],
        spf_skip_addresses: list[IPvAnyNetwork],
        tls_ciphers: SmtpTlsCipherGrade | None,
        tls_exclude_ciphers: list[Annotated[str, Field(min_length=1)]],
        tls_policy_maps: list[str],
        tls_protocols: list[Annotated[str, Field(min_length=1)]],
        tls_security_level: SmtpTlsSecurityLevel | None,
        transport_maps: list[str],
        virtual_alias_domains: list[Annotated[str, Field(min_length=1)]],
        virtual_alias_maps: list[str],
        virtual_alias_maps_type: PostfixLookupTableType,
        connection_limit: int = Field(ge=0)
    ):
        """Initialize a new instance of the State class.

        Args:
            additional_smtpd_recipient_restrictions: List of additional recipient restrictions.
            admin_email: Administrator's email address where root@ emails will go to.
            allowed_relay_networks: List of allowed networks to relay without authenticating.
            append_x_envelope_to: Append the X-Envelope-To header.
            connection_limit: Maximum number of SMTP connections allowed.
            domain: Primary domain for hostname generation.
            enable_rate_limits: Enable default rate limiting features.
            enable_reject_unknown_sender_domain: Reject email when sender's domain cannot be
                resolved.
            enable_smtp_auth: If SMTP authentication is enabled.
            enable_spf: If SPF checks are enabled.
            header_checks: Header checks to perform on inbound email.
            relay_access_sources: List of  entries to restrict access based on CIDR source.
            relay_domains: List of destination domains to relay mail to.
            restrict_recipients: Access map for restrictions by recipient address or domain.
            restrict_senders: Access map for restrictions by sender address or domain.
            relay_host: SMTP relay host to forward mail to.
            relay_recipient_maps: List of of mappings that alias mail addresses or domains to
                addresses.
            restrict_sender_access: List of domains, addresses or hosts to restrict relay from.
            sender_login_maps: List of authenticated users that can send mail.
            smtp_auth_users: List of user and crypt password hashe pairs separated by ':'.
            smtp_header_checks: List of header checks to perform on outbound email.
            spf_skip_addresses: List of CIDR addresses to skip SPF checks.
            tls_ciphers: Minimum TLS cipher grade for TLS encryption.
            tls_exclude_ciphers: List of TLS ciphers or cipher types to exclude from the cipher
                list.
            tls_policy_maps: List of of mappings for TLS policy.
            tls_protocols: List of TLS protocols accepted by the Postfix SMTP.
            tls_security_level: The TLS security level.
            transport_maps: List of mappings from recipient address to message delivery transport
                or next-hop destination.
            virtual_alias_domains: List of domains for which all addresses are aliased.
            virtual_alias_maps: List of aliases of mail addresses or domains to other local or
                remote addresses.
            virtual_alias_maps_type: The virtual alias map type.
        """
        super().__init__(
            additional_smtpd_recipient_restrictions=additional_smtpd_recipient_restrictions,
            admin_email=admin_email,
            allowed_relay_networks=allowed_relay_networks,
            append_x_envelope_to=append_x_envelope_to,
            domain=domain,
            enable_rate_limits=enable_rate_limits,
            enable_reject_unknown_sender_domain=enable_reject_unknown_sender_domain,
            enable_smtp_auth=enable_smtp_auth,
            enable_spf=enable_spf,
            header_checks=header_checks,
            relay_access_sources=relay_access_sources,
            relay_domains=relay_domains,
            restrict_recipients=restrict_recipients,
            restrict_senders=restrict_senders,
            relay_host=relay_host,
            relay_recipient_maps=relay_recipient_maps,
            restrict_sender_access=restrict_sender_access,
            sender_login_maps=sender_login_maps,
            smtp_auth_users=smtp_auth_users,
            smtp_header_checks=smtp_header_checks,
            spf_skip_addresses=spf_skip_addresses,
            tls_ciphers=tls_ciphers,
            tls_exclude_ciphers=tls_exclude_ciphers,
            tls_policy_maps=tls_policy_maps,
            tls_protocols=tls_protocols,
            tls_security_level=tls_security_level,
            transport_maps=transport_maps,
            virtual_alias_domains=virtual_alias_domains,
            virtual_alias_maps=virtual_alias_maps,
            virtual_alias_maps_type=virtual_alias_maps_type,
            connection_limit=connection_limit
        )


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
            allowed_relay_networks = [
                IPvAnyNetwork(value)
                for value
                in _parse_list(config.get("allowed_relay_networks"))
            ]
            additional_smtpd_recipient_restrictions = _parse_list(
                config.get("additional_smtpd_recipient_restrictions")
            )
            header_checks = _parse_list(config.get("header_checks"))
            relay_access_sources = _parse_list(config.get("relay_access_sources"))
            relay_domains = _parse_list(config.get("relay_domains"))
            relay_recipient_maps = _parse_list(config.get("relay_recipient_maps"))
            restrict_sender_access = _parse_list(config.get("restrict_sender_access"))
            spf_skip_addresses = _parse_list(config.get("spf_skip_addresses"))
            tls_exclude_ciphers = _parse_list(config.get("tls_exclude_ciphers"))
            tls_policy_maps = _parse_list(config.get("tls_policy_maps"))
            tls_protocols = _parse_list(config.get("tls_protocols"))
            virtual_alias_domains = _parse_list(config.get("virtual_alias_domains"))
            restrict_recipients = _parse_access_map(config.get("restrict_recipients"))
            restrict_senders = _parse_access_map(config.get("restrict_senders"))
            sender_login_maps = _parse_map(config.get("sender_login_maps"))
            smtp_auth_users = _parse_list(config.get("smtp_auth_users"))
            smtp_header_checks = _parse_list(config.get("smtp_header_checks"))
            transport_maps = _parse_list(config.get("transport_maps"))
            virtual_alias_maps = _parse_list(config.get("virtual_alias_maps"))

            return cls(
                additional_smtpd_recipient_restrictions=additional_smtpd_recipient_restrictions,
                admin_email=config.get("admin_email"),
                allowed_relay_networks=allowed_relay_networks,
                append_x_envelope_to=config.get("append_x_envelope_to"),
                connection_limit=config.get("connection_limit"),
                domain=config.get("domain"),
                enable_rate_limits=config.get("enable_rate_limits"),
                enable_reject_unknown_sender_domain=config.get(
                    "enable_reject_unknown_sender_domain"
                ),
                enable_smtp_auth=config.get("enable_smtp_auth"),
                enable_spf=config.get("enable_spf"),
                header_checks=header_checks,
                relay_access_sources=relay_access_sources,
                relay_domains=relay_domains,
                relay_host=config.get("relay_host"),
                relay_recipient_maps=relay_recipient_maps,
                restrict_recipients=restrict_recipients,
                restrict_senders=restrict_senders,
                restrict_sender_access=restrict_sender_access,
                sender_login_maps=sender_login_maps,
                smtp_auth_users=smtp_auth_users,
                smtp_header_checks=smtp_header_checks,
                spf_skip_addresses=spf_skip_addresses,
                tls_ciphers=(
                    SmtpTlsCipherGrade(config.get("tls_ciphers"))
                    if config.get("tls_ciphers")
                    else None
                ),
                tls_exclude_ciphers=tls_exclude_ciphers,
                tls_policy_maps=tls_policy_maps,
                tls_protocols=tls_protocols,
                tls_security_level=(
                    SmtpTlsSecurityLevel(config.get("tls_security_level"))
                    if config.get("tls_security_level")
                    else None
                ),
                transport_maps=transport_maps,
                virtual_alias_domains=virtual_alias_domains,
                virtual_alias_maps=virtual_alias_maps,
                virtual_alias_maps_type=PostfixLookupTableType(
                    config.get("virtual_alias_maps_type")
                ),
            )

        except ValueError as exc:
            raise ConfigurationError(f"Invalid configuration") from exc
        except ValidationError as exc:
            error_fields = set(
                itertools.chain.from_iterable(error["loc"] for error in exc.errors())
            )
            error_field_str = " ".join(f"{f}" for f in error_fields)
            raise ConfigurationError(f"Invalid configuration: {error_field_str}") from exc
