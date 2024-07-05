#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module defining the CharmState class which represents the state of the SMTP Relay charm."""

import itertools
from enum import Enum

import ops
from pydantic import BaseModel, EmailStr, ValidationError


class TlsCipher(str, Enum):
    """Represent the TLS cipher values.

    Attributes:
        HIGH: high.
        MEDIUM: medium.
        NULL: null.
        LOW: low.
        EXPORT: export.
    """

    HIGH = "high"
    MEDIUM = "medium"
    NULL = "null"
    LOW = "low"
    EXPORT = "export"


class TlsSecurityLevel(str, Enum):
    """Represent the TLS scurity level values.

    Attributes:
        NONE: none.
        MAY: may.
        ENCRYPT: encrypt.
    """

    NONE = "none"
    MAY = "may"
    ENCRYPT = "encrypt"


class SmtpRelayConfig(BaseModel):  # pylint: disable=too-few-public-methods
    """Represent charm builtin configuration values.

    Attributes:
        admin_email: admin_email config.
        allowed_relay_networks: allowed_relay_networks config.
        additional_smtpd_recipient_restrictions: additional_smtpd_recipient_restrictions config.
        append_x_envelope_to: append_x_envelope_to config.
        connection_limit: connection_limit config.
        domain: domain config.
        enable_rate_limits: enable_rate_limits config.
        enable_reject_unknown_recipient_domain: enable_reject_unknown_recipient_domain config.
        enable_reject_unknown_sender_domain: enable_reject_unknown_sender_domain config.
        enable_spf: enable_spf config.
        enable_smtp_auth: enable_smtp_auth config.
        header_checks: header_checks config.
        message_size_limit: message_size_limit config.
        relay_access_sources: relay_access_sources config.
        relay_domains: relay_domains config.
        relay_host: relay_host config.
        relay_recipient_maps: relay_recipient_maps config.
        restrict_recipients: restrict_recipients config.
        restrict_senders: restrict_senders config.
        restrict_sender_access: restrict_sender_access config.
        sender_login_maps: sender_login_maps config.
        smtp_auth_users: smtp_auth_users config.
        smtp_header_checks: smtp_header_checks config.
        spf_check_maps: spf_check_maps config.
        spf_skip_addresses: spf_skip_addresses config.
        tls_ciphers: tls_ciphers config.
        tls_exclude_ciphers: tls_exclude_ciphers config.
        tls_policy_maps: tls_policy_maps config.
        tls_protocols: tls_protocols config.
        tls_security_level: tls_security_level config.
        transport_maps: transport_maps config.
        virtual_alias_domains: virtual_alias_domains config.
        virtual_alias_maps: virtual_alias_maps config.
        virtual_alias_maps_type: virtual_alias_maps_type config.
    """

    admin_email: EmailStr
    allowed_relay_networks: str
    additional_smtpd_recipient_restrictions: str
    append_x_envelope_to: bool
    connection_limit: int
    domain: str
    enable_rate_limits: bool
    enable_reject_unknown_recipient_domain: bool
    enable_reject_unknown_sender_domain: bool
    enable_spf: bool
    enable_smtp_auth: bool
    header_checks: str
    message_size_limit: int
    relay_access_sources: str
    relay_domains: str
    relay_host: str
    relay_recipient_maps: str
    restrict_recipients: str
    restrict_senders: str
    restrict_sender_access: str
    sender_login_maps: str
    smtp_auth_users: str
    smtp_header_checks: str
    spf_check_maps: str
    spf_skip_addresses: str
    tls_ciphers: TlsCipher
    tls_exclude_ciphers: str
    tls_policy_maps: str
    tls_protocols: str
    tls_security_level: TlsSecurityLevel
    transport_maps: str
    virtual_alias_domains: str
    virtual_alias_maps: str
    virtual_alias_maps_type: str


class CharmConfigInvalidError(Exception):
    """Exception raised when a charm configuration is found to be invalid.

    Attrs:
        msg (str): Explanation of the error.
    """

    def __init__(self, msg: str):
        """Initialize a new instance of the CharmConfigInvalidError exception.

        Args:
            msg (str): Explanation of the error.
        """
        self.msg = msg


class CharmState:
    """Represents the state of the SMTP relay charm."""

    def __init__(self, *, smtp_relay_config: SmtpRelayConfig):
        """Initialize a new instance of the CharmState class.

        Args:
            smtp_relay_config: SMTP relay configuration.
        """
        self.smtp_relay_config = smtp_relay_config

    @classmethod
    def from_charm(cls, charm: "ops.CharmBase") -> "CharmState":
        """Initialize a new instance of the CharmState class from the associated charm.

        Args:
            charm: The charm instance associated with this state.

        Return:
            The CharmState instance created by the provided charm.

        Raises:
            CharmConfigInvalidError: if the charm configuration is invalid.
        """
        try:
            valid_config = SmtpRelayConfig(**dict(charm.config.items()))
        except ValidationError as exc:
            error_fields = set(
                itertools.chain.from_iterable(error["loc"] for error in exc.errors())
            )
            error_field_str = " ".join(str(f) for f in error_fields)
            raise CharmConfigInvalidError(f"invalid configuration: {error_field_str}") from exc
        return cls(saml_integrator_config=valid_config)
