# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""dovecot service unit tests."""

from pathlib import Path
import pytest

from reactive import dovecot, utils


def test_construct_dovecot_config_file_content() -> None:
    """
    arrange: Given different values for enabling SMTP auth.
    act: Call construct_dovecot_config_file_content.
    assert: The Jinja2 renderer is called with the correctly formatted context.
    """

    dovecot_users_path = "/etc/dovecot/users"
    expected_path = Path(__file__).parent / "files" / "dovecot_config"
    expected = expected_path.read_text()

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
    expected_path = Path(__file__).parent / "files" / "dovecot_config_auth_disabled"
    expected = expected_path.read_text()

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
