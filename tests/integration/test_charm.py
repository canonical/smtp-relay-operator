#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests."""

import datetime
import requests
import smtplib
import socket
import logging
import time

import jubilant
import pytest


logger = logging.getLogger(__name__)

@pytest.fixture(scope="session", name="machine_ip_address")
def machine_ip_address_fixture() -> str:
    """IP address for the jobmanager tests."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_address = s.getsockname()[0]
    logger.info("IP Address for the current test runner: %s", ip_address)
    s.close()
    return ip_address



@pytest.mark.abort_on_fail
def test_build_and_deploy(juju: jubilant.Juju, smtp_relay_app, machine_ip_address):
    """TODO"""
    mailcatcher_url = "http://127.0.0.1:1080/messages"
    messages = requests.get(mailcatcher_url, timeout=5).json()
    assert len(messages) == 0
    status = juju.status()

    unit = list(status.apps[smtp_relay_app].units.values())[0]
    unit_ip = unit.public_address
    port = 25

    command_to_put_domain = f'echo {machine_ip_address} testrelay.internal | sudo tee -a /etc/hosts'
    juju.exec(machine=unit.machine, command=command_to_put_domain)

    with smtplib.SMTP(unit_ip) as server:
        server.set_debuglevel(2)
        from_addr = "Some One <someone@testrelay.internal>"
        to_addrs = ["otherone@testrelay.internal"]
        msg = "Hello World!"
        server.sendmail(from_addr, to_addrs, msg)

    for _ in range(5):
        messages = requests.get(mailcatcher_url, timeout=5).json()
        logger.info("Messages: %s", messages)
        if messages:
            break
        time.sleep(1)
    assert len(messages) == 1
    # clean up.
    requests.delete(f"{mailcatcher_url}/{messages[0]['id']}", timeout=5)
