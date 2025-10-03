# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Postfix service unit tests."""

import ipaddress
from pathlib import Path

import pytest

import postfix
import state
import utils


@pytest.mark.parametrize(
    (
        "relay_access_sources",
        "enable_smtp_auth",
        "sender_login_maps",
        "restrict_senders",
        "expected",
    ),
    [
        pytest.param(
            [],
            False,
            {},
            {},
            ["permit_mynetworks", "defer_unauth_destination"],
            id="no_access_sources_no_auth",
        ),
        pytest.param(
            ["source1, source2"],
            False,
            {},
            {},
            [
                "permit_mynetworks",
                "check_client_access cidr:/etc/postfix/relay_access",
                "defer_unauth_destination",
            ],
            id="has_access_sources_no_auth",
        ),
        pytest.param(
            ["source1, source2"],
            True,
            {},
            {},
            [
                "permit_mynetworks",
                "check_client_access cidr:/etc/postfix/relay_access",
                "permit_sasl_authenticated",
                "defer_unauth_destination",
            ],
            id="has_auth",
        ),
        pytest.param(
            [],
            True,
            {"group@example.com": "group"},
            {},
            [
                "permit_mynetworks",
                "reject_known_sender_login_mismatch",
                "permit_sasl_authenticated",
                "defer_unauth_destination",
            ],
            id="has_auth_and_sender_login_maps",
        ),
        pytest.param(
            [],
            True,
            {},
            {"sender": state.AccessMapValue.OK},
            [
                "permit_mynetworks",
                "reject_sender_login_mismatch",
                "permit_sasl_authenticated",
                "defer_unauth_destination",
            ],
            id="has_auth_and_restrict_senders",
        ),
        pytest.param(
            [],
            True,
            {"group@example.com": "group"},
            {"sender": state.AccessMapValue.OK},
            [
                "permit_mynetworks",
                "reject_known_sender_login_mismatch",
                "reject_sender_login_mismatch",
                "permit_sasl_authenticated",
                "defer_unauth_destination",
            ],
            id="has_auth_and_sender_login_maps_and_restrict_senders",
        ),
    ],
)
def test_smtpd_relay_restrictions(
    relay_access_sources: list[str],
    enable_smtp_auth: bool,
    sender_login_maps: dict[str, str],
    restrict_senders: dict[str, state.AccessMapValue],
    expected: list[str],
) -> None:
    """
    arrange: Create charm_state with different relay restriction settings.
    act: Call _smtpd_restrictions with the charm_state.
    assert: The returned list of restrictions is correct and in order..
    """
    charm_config = {
        "append_x_envelope_to": False,
        "connection_limit": 100,
        "domain": "example.domain.com",
        "enable_rate_limits": False,
        "enable_reject_unknown_sender_domain": True,
        "enable_spf": False,
        "enable_smtp_auth": True,
        "virtual_alias_maps_type": "hash",
    }
    charm_state = state.State.from_charm(config=charm_config)
    charm_state.relay_access_sources = relay_access_sources
    charm_state.enable_smtp_auth = enable_smtp_auth
    charm_state.sender_login_maps = sender_login_maps
    charm_state.restrict_senders = restrict_senders

    result = postfix._smtpd_relay_restrictions(charm_state)

    assert result == expected


@pytest.mark.parametrize(
    ("enable_reject_unknown_sender", "restrict_sender_access", "expected"),
    [
        pytest.param(
            False,
            [],
            ["check_sender_access hash:/etc/postfix/access"],
            id="neither_enabled",
        ),
        pytest.param(
            True,
            [],
            [
                "reject_unknown_sender_domain",
                "check_sender_access hash:/etc/postfix/access",
            ],
            id="reject_unknown_enabled",
        ),
        pytest.param(
            False,
            ["example.com"],
            ["check_sender_access hash:/etc/postfix/access", "reject"],
            id="restrict_access_enabled",
        ),
        pytest.param(
            True,
            ["example.com"],
            [
                "reject_unknown_sender_domain",
                "check_sender_access hash:/etc/postfix/access",
                "reject",
            ],
            id="both_enabled",
        ),
    ],
)
def test_smtpd_sender_restrictions(
    enable_reject_unknown_sender: bool,
    restrict_sender_access: list[str],
    expected: list[str],
) -> None:
    """
    arrange: Create charm_state with different sender restriction settings.
    act: Call _smtpd_sender_restrictions with the charm_state.
    assert: The returned list of restrictions is correct and in order.
    """
    charm_config = {
        "append_x_envelope_to": False,
        "connection_limit": 100,
        "domain": "example.domain.com",
        "enable_rate_limits": False,
        "enable_reject_unknown_sender_domain": True,
        "enable_spf": False,
        "enable_smtp_auth": True,
        "virtual_alias_maps_type": "hash",
    }
    charm_state = state.State.from_charm(config=charm_config)
    charm_state.enable_reject_unknown_sender_domain = enable_reject_unknown_sender
    charm_state.restrict_sender_access = restrict_sender_access

    result = postfix._smtpd_sender_restrictions(charm_state)

    assert result == expected


@pytest.mark.parametrize(
    (
        "append_x_envelope_to",
        "restrict_senders",
        "additional_restrictions",
        "enable_spf",
        "expected",
    ),
    [
        pytest.param(False, {}, [], False, [], id="all_disabled"),
        pytest.param(
            True,
            {},
            [],
            False,
            ["check_recipient_access regexp:/etc/postfix/append_envelope_to_header"],
            id="append_x_envelope_enabled",
        ),
        pytest.param(
            False,
            {"sender": "value"},
            [],
            False,
            ["check_sender_access hash:/etc/postfix/restricted_senders"],
            id="restrict_senders_enabled",
        ),
        pytest.param(
            False,
            {},
            ["custom_restriction_1"],
            False,
            ["custom_restriction_1"],
            id="additional_restrictions_enabled",
        ),
        pytest.param(
            False,
            {},
            [],
            True,
            ["check_policy_service unix:private/policyd-spf"],
            id="spf_enabled",
        ),
        pytest.param(
            True,
            {"sender": "value"},
            ["custom_restriction_1", "custom_restriction_2"],
            True,
            [
                "check_recipient_access regexp:/etc/postfix/append_envelope_to_header",
                "check_sender_access hash:/etc/postfix/restricted_senders",
                "custom_restriction_1",
                "custom_restriction_2",
                "check_policy_service unix:private/policyd-spf",
            ],
            id="all_enabled",
        ),
    ],
)
def test_smtpd_recipient_restrictions(
    append_x_envelope_to: bool,
    restrict_senders: dict,
    additional_restrictions: list[str],
    enable_spf: bool,
    expected: list[str],
) -> None:
    """
    arrange: Create charm_state with different recipient restriction settings.
    act: Call _smtpd_recipient_restrictions with the charm_state.
    assert: The returned list of restrictions is correct and in order.
    """
    charm_config = {
        "append_x_envelope_to": False,
        "connection_limit": 100,
        "domain": "example.domain.com",
        "enable_rate_limits": False,
        "enable_reject_unknown_sender_domain": True,
        "enable_spf": False,
        "enable_smtp_auth": True,
        "virtual_alias_maps_type": "hash",
    }
    charm_state = state.State.from_charm(config=charm_config)
    charm_state.append_x_envelope_to = append_x_envelope_to
    charm_state.restrict_senders = restrict_senders
    charm_state.additional_smtpd_recipient_restrictions = additional_restrictions
    charm_state.enable_spf = enable_spf

    result = postfix._smtpd_recipient_restrictions(charm_state)

    assert result == expected


def test_construct_policyd_spf_content() -> None:
    """
    arrange: Given a list of IP addresses to skip for SPF checks.
    act: Call construct_policyd_spf_config_file_content.
    assert: The Jinja2 renderer is called with the correctly formatted context.
    """
    spf_skip_addresses = [
        ipaddress.ip_network("10.0.114.0/24"),
        ipaddress.ip_network("10.1.1.0/24"),
    ]

    expected_path = Path(__file__).parent / "files/policyd_spf_config_skip_addresses"
    expected = expected_path.read_text()

    result = postfix.construct_policyd_spf_config_file_content(spf_skip_addresses)

    assert result == expected


def test_build_postfix_maps_returns_correct_data() -> None:
    """
    arrange: Define the charm state and expected dictionary of PostfixMap objects.
    act: Call build_postfix_maps.
    assert: The returned dictionary is identical to the expected dictionary.
    """
    charm_config = {
        # Values directly used by the function under test
        "header_checks": "- '/^Subject:/ WARN'",
        "relay_access_sources": "- 192.168.1.0/24",
        "relay_recipient_maps": "user@example.com: OK",
        "restrict_recipients": "bad@example.com: REJECT",
        "restrict_senders": "spammer@example.com: REJECT",
        "restrict_sender_access": "- unwanted.com",
        "sender_login_maps": "sender@example.com: user@example.com",
        "smtp_header_checks": "- '/^Received:/ IGNORE'",
        "tls_policy_maps": "example.com: secure",
        "transport_maps": "domain.com: smtp:relay.example.com",
        "virtual_alias_maps": "alias@example.com: real@example.com",
        "virtual_alias_maps_type": "hash",
        # Values required for State object instantiation
        "domain": "example.domain.com",
        "append_x_envelope_to": False,
        "enable_rate_limits": False,
        "enable_reject_unknown_sender_domain": False,
        "enable_smtp_auth": False,
        "enable_spf": False,
        "connection_limit": 0,
    }
    charm_state = state.State.from_charm(config=charm_config)
    postfix_conf_dir = "/etc/postfix"

    conf_path = Path(postfix_conf_dir)
    expected_maps = {
        "append_envelope_to_header": postfix.PostfixMap(
            type="regexp",
            path=conf_path / "append_envelope_to_header",
            content=f"{utils.JUJU_HEADER}\n/^(.*)$/ PREPEND X-Envelope-To: $1\n",
        ),
        "header_checks": postfix.PostfixMap(
            type="regexp",
            path=conf_path / "header_checks",
            content=f"{utils.JUJU_HEADER}\n/^Subject:/ WARN\n",
        ),
        "relay_access_sources": postfix.PostfixMap(
            type="cidr",
            path=conf_path / "relay_access",
            content=f"{utils.JUJU_HEADER}\n192.168.1.0/24\n",
        ),
        "relay_recipient_maps": postfix.PostfixMap(
            type="hash",
            path=conf_path / "relay_recipient",
            content=f"{utils.JUJU_HEADER}\nuser@example.com OK\n",
        ),
        "restrict_recipients": postfix.PostfixMap(
            type="hash",
            path=conf_path / "restricted_recipients",
            content=f"{utils.JUJU_HEADER}\nbad@example.com REJECT\n",
        ),
        "restrict_senders": postfix.PostfixMap(
            type="hash",
            path=conf_path / "restricted_senders",
            content=f"{utils.JUJU_HEADER}\nspammer@example.com REJECT\n",
        ),
        "sender_access": postfix.PostfixMap(
            type="hash",
            path=conf_path / "access",
            content=f"{utils.JUJU_HEADER}\n{'unwanted.com':35} OK\n\n",
        ),
        "sender_login_maps": postfix.PostfixMap(
            type="hash",
            path=conf_path / "sender_login",
            content=f"{utils.JUJU_HEADER}\nsender@example.com user@example.com\n",
        ),
        "smtp_header_checks": postfix.PostfixMap(
            type="regexp",
            path=conf_path / "smtp_header_checks",
            content=f"{utils.JUJU_HEADER}\n/^Received:/ IGNORE\n",
        ),
        "tls_policy_maps": postfix.PostfixMap(
            type="hash",
            path=conf_path / "tls_policy",
            content=f"{utils.JUJU_HEADER}\nexample.com secure\n",
        ),
        "transport_maps": postfix.PostfixMap(
            type="hash",
            path=conf_path / "transport",
            content=f"{utils.JUJU_HEADER}\ndomain.com smtp:relay.example.com\n",
        ),
        "virtual_alias_maps": postfix.PostfixMap(
            type="hash",
            path=conf_path / "virtual_alias",
            content=f"{utils.JUJU_HEADER}\nalias@example.com real@example.com\n",
        ),
    }

    maps = postfix.build_postfix_maps(postfix_conf_dir, charm_state)

    assert maps == expected_maps
