# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm state."""
import dataclasses
import itertools
import logging
import typing
from enum import Enum

from pydantic import EmailStr, IPvAnyNetwork, ValidationError

logger = logging.getLogger(__name__)


class CharmStateBaseError(Exception):
    """Represents an error with charm state."""


class CharmConfigInvalidError(CharmStateBaseError):
    """Exception raised when a charm configuration is found to be invalid.

    Attributes:
        msg: Explanation of the error.
    """

    def __init__(self, msg: str):
        """Initialize a new instance of the CharmConfigInvalidError exception.

        Args:
            msg: Explanation of the error.
        """
        self.msg = msg


class TLSCiphers(str, Enum):
    """TLS cipher.

    Attributes:
        HIGH: "HIGH"
        MEDIUM: "MEDIUM"
        NULL: "NULL"
        LOW: "LOW"
        EXPORT: "EXPORT"
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    NULL = "NULL"
    LOW = "LOW"
    EXPORT = "EXPORT"


class TLSSecurityLevel(str, Enum):
    """TLS secutiry level.

    Attributes:
        NONE: "none"
        MAY: "may"
        ENCRYPT: "encrypt"
    """

    NONE = "none"
    MAY = "may"
    ENCRYPT = "encrypt"


@dataclasses.dataclass()
class State:  # pylint: disable=too-few-public-methods
    """The Indico operator charm state.

    Attributes:
        admin_email: Administrator's email address where root@ emails will go to
        allowed_relay_networks: List of allowed networks to relay without authenticating.
        domain: Primary domain for hostname generation.
        relay_domains: List of destination domains to relay mail to.
        relay_host: SMTP relay host to forward mail to.
        tls_ciphers: Minimum TLS cipher grade for TLS encryption.
        tls_security_level: The TLS security level.
    """

    admin_email: EmailStr
    allowed_relay_networks: list[IPvAnyNetwork]
    domain: str | None
    relay_domains: list[str]
    relay_host: str
    tls_ciphers: TLSCiphers
    tls_security_level: TLSSecurityLevel

    @classmethod
    def from_charm(cls, config: dict[str, typing.Any]) -> "State":
        """Initialize the state from charm.

        Arguments:
            config: the charm configuration.

        Returns:
            Current charm state.

        Raises:
            CharmConfigInvalidError: if invalid state values were encountered.
        """
        try:
            allowed_relay_networks = config["allowed_relay_networks"].split(",")
            relay_domains = config["relay_domains"].split(",") if "relay_domains" in config else []
            return cls(
                admin_email=config["admin_email"],
                allowed_relay_networks=allowed_relay_networks,
                domain=config["domain"],
                relay_domains=relay_domains,
                relay_host=config["relay_host"],
                tls_ciphers=TLSCiphers(config["tls_ciphers"]),
                tls_security_level=TLSSecurityLevel(config["tls_security_level"]),
            )

        except ValidationError as exc:
            error_fields = set(
                itertools.chain.from_iterable(error["loc"] for error in exc.errors())
            )
            error_field_str = " ".join(f"{f}" for f in error_fields)
            raise CharmConfigInvalidError(f"invalid configuration: {error_field_str}") from exc
