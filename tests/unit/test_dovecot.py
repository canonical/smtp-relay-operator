# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""dovecot service unit tests."""

import pytest

from reactive import dovecot, utils


def test_construct_dovecot_config_file_content() -> None:
    """
    arrange: Given different values for enabling SMTP auth.
    act: Call construct_dovecot_config_file_content.
    assert: The Jinja2 renderer is called with the correctly formatted context.
    """

    dovecot_users_path = "/etc/dovecot/users"
    expected = (
        f"#{utils.JUJU_HEADER}\n"
        "auth_mechanisms = plain login\n"
        "auth_verbose = yes\n"
        "\n"
        "service auth {\n"
        "    unix_listener /var/spool/postfix/private/auth {\n"
        "        mode = 0660\n"
        "        user = postfix\n"
        "        group = postfix\n"
        "    }\n"
        "}\n"
        "\n"
        "passdb {\n"
        "    driver = passwd-file\n"
        f"    args = scheme=CRYPT username_format=%u {dovecot_users_path}\n"
        "}\n"
    )

    result = dovecot.construct_dovecot_config_file_content(
        dovecot_users_path=dovecot_users_path, enable_smtp_auth=True
    )

    assert result == expected


def test_construct_dovecot_config_file_content_smtp_auth_disabled() -> None:
    """
    arrange: Nothing.
    act: Call construct_dovecot_config_file_content with smtp auth disabled.
    assert: The Jinja2 renderer is called with the correctly formatted context.
    """

    dovecot_users_path = "/etc/dovecot/users"
    expected = f"#{utils.JUJU_HEADER}\n## DISABLED\n"

    result = dovecot.construct_dovecot_config_file_content(
        dovecot_users_path=dovecot_users_path, enable_smtp_auth=False
    )

    assert result == expected


@pytest.mark.parametrize(
    ("smtp_auth_users", "expected_content"),
    [
        pytest.param([], f"{utils.JUJU_HEADER}\n", id="no_users"),
        pytest.param(
            ["user1:pass1"],
            f"{utils.JUJU_HEADER}user1:pass1\n",
            id="single_user",
        ),
        pytest.param(
            ["user1:pass1", "user2:pass2"],
            f"{utils.JUJU_HEADER}user1:pass1\nuser2:pass2\n",
            id="multiple_users",
        ),
    ],
)
def test_construct_dovecot_user_file_content(
    smtp_auth_users: list[str], expected_content: str
) -> None:
    """
    arrange: Given a list of SMTP auth users.
    act: Call construct_dovecot_user_file_content.
    assert: The returned string is correctly formatted.
    """

    result = dovecot.construct_dovecot_user_file_content(smtp_auth_users)

    assert result == expected_content
