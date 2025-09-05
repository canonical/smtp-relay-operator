#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests."""

import jubilant
import pytest


@pytest.mark.abort_on_fail
def test_build_and_deploy(juju: jubilant.Juju, smtp_relay_app):
    """TODO"""
