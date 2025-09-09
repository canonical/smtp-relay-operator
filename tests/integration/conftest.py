# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import typing
from collections.abc import Generator

import jubilant
import pytest


@pytest.fixture(scope="module", name="smtp_relay_charm")
def smtp_relay_charm_fixture(pytestconfig: pytest.Config):
    """Get value from parameter charm-file."""
    charm = pytestconfig.getoption("--charm-file")
    use_existing = pytestconfig.getoption("--use-existing", default=False)
    if not use_existing:
        assert charm, "--charm-file must be set"
    return charm


@pytest.fixture(scope="module", name="smtp_relay_app")
def deploy_smtp_relay_fixture(
    smtp_relay_charm: str,
    juju: jubilant.Juju,
) -> str:
    """Deploy smtp-relay."""
    smtp_relay_app_name = "smtp-relay"

    if not juju.status().apps.get(smtp_relay_app_name):
        juju.deploy(
            f"./{smtp_relay_charm}",
            smtp_relay_app_name,
            config={"relay_domains": "- testrelay.internal"},
        )
    juju.wait(
        lambda status: status.apps[smtp_relay_app_name].is_active,
        error=jubilant.any_blocked,
        timeout=6 * 60,
    )
    return smtp_relay_app_name


@pytest.fixture(scope="session")
def juju(request: pytest.FixtureRequest) -> Generator[jubilant.Juju, None, None]:
    """Pytest fixture that wraps :meth:`jubilant.with_model`."""

    def show_debug_log(juju: jubilant.Juju):
        if request.session.testsfailed:
            log = juju.debug_log(limit=1000)
            print(log, end="")

    use_existing = request.config.getoption("--use-existing", default=False)
    if use_existing:
        juju = jubilant.Juju()
        yield juju
        show_debug_log(juju)
        return

    model = request.config.getoption("--model")
    if model:
        juju = jubilant.Juju(model=model)
        yield juju
        show_debug_log(juju)
        return

    keep_models = typing.cast(bool, request.config.getoption("--keep-models"))
    with jubilant.temp_model(keep=keep_models) as juju:
        juju.wait_timeout = 10 * 60
        yield juju
        show_debug_log(juju)
        return
