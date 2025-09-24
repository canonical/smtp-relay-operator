# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the SMTP Relay charm."""

from unittest.mock import patch

import pytest
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus
from ops.testing import Harness

from charm import ConfigurationError, SMTPRelayCharm


@pytest.fixture
def harness():
    """Create a Harness instance for the SMTPRelayCharm."""
    harness = Harness(SMTPRelayCharm)
    harness.begin()
    yield harness
    harness.cleanup()


def test_initial_status(harness: Harness[SMTPRelayCharm]):
    """Test that the charm starts in a MaintenanceStatus."""
    # The initial status should be Maintenance as the first reconcile runs.
    assert isinstance(harness.model.unit.status, MaintenanceStatus)


def test_config_changed_sets_active(harness: Harness[SMTPRelayCharm]):
    """Test that a basic config-changed event makes the charm active."""
    # Mock the external dependencies that would be called during reconcile
    patch("charm.SMTPRelayCharm._install")
    patch("charm.SMTPRelayCharm._configure_smtp_auth")
    patch("charm.SMTPRelayCharm._configure_smtp_relay")
    patch("charm.SMTPRelayCharm._configure_policyd_spf")

    # Simulate a config-changed event
    harness.update_config()

    # Check that the final status is Active
    assert isinstance(harness.model.unit.status, ActiveStatus)


def test_smtp_auth_disabled(harness):
    """Test the charm's behavior when SMTP auth is disabled."""
    # Mock the service and port helpers
    mock_service_stop = patch("charm.systemd.service_stop")
    mock_close_port = patch.object(harness.charm.unit, "close_port")

    # Set the config to disable SMTP auth
    harness.update_config({"enable_smtp_auth": False})

    # The charm should close the correct ports
    mock_close_port.assert_any_call("tcp", 465)
    mock_close_port.assert_any_call("tcp", 587)

    # The charm should stop the dovecot service
    mock_service_stop.assert_called_with("dovecot")


def test_smtp_auth_enabled(harness):
    """Test the charm's behavior when SMTP auth is enabled."""
    # Mock the service and port helpers
    mock_service_start = patch("charm.systemd.service_start")
    mock_open_port = patch.object(harness.charm.unit, "open_port")

    # The default config has enable_smtp_auth=True, so just trigger a reconcile
    harness.update_config()

    # The charm should open the correct ports
    mock_open_port.assert_any_call("tcp", 465)
    mock_open_port.assert_any_call("tcp", 587)

    # The charm should ensure the dovecot service is running
    mock_service_start.assert_called_with("dovecot")


def test_invalid_config_blocks(harness):
    """Test that invalid config handled by the State class blocks the charm."""
    # Mock the State class's factory to raise a validation error
    patch("charm.State.from_charm", side_effect=ConfigurationError("Invalid setting"))

    # Trigger a reconcile
    harness.update_config()

    # The charm should be in a BlockedStatus
    assert isinstance(harness.model.unit.status, BlockedStatus)
    assert "Invalid setting" in harness.model.unit.status.message
