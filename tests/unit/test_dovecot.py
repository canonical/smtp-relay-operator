# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""dovecot service unit tests."""

from unittest.mock import Mock, patch

import pytest

from reactive import dovecot, utils


@pytest.mark.parametrize(
    ("enable_smtp_auth"),
    [
        pytest.param(True, id="smtp_auth_enabled"),
        pytest.param(False, id="smtp_auth_disabled"),
    ],
)
@patch("reactive.dovecot.utils.render_jinja2_template")
def test_construct_dovecot_config_file_content(mock_render: Mock, enable_smtp_auth: bool) -> None:
    """
    arrange: Given different values for enabling SMTP auth.
    act: Call construct_dovecot_config_file_content.
    assert: The Jinja2 renderer is called with the correctly formatted context.
    """
    # Arrange
    dovecot_users_path = "/etc/dovecot/users"
    expected_context = {
        "JUJU_HEADER": utils.JUJU_HEADER,
        "passdb_driver": "passwd-file",
        "passdb_args": f"scheme=CRYPT username_format=%u {dovecot_users_path}",
        "path": "/var/spool/postfix/private/auth",
        "smtp_auth": enable_smtp_auth,
    }

    # Act
    dovecot.construct_dovecot_config_file_content(dovecot_users_path, enable_smtp_auth)

    # Assert
    mock_render.assert_called_once_with(expected_context, "templates/dovecot_conf.tmpl")


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
    # Act
    result = dovecot.construct_dovecot_user_file_content(smtp_auth_users)

    # Assert
    assert result == expected_content
