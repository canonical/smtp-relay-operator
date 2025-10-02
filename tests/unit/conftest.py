# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests."""


from collections.abc import Iterator

import pytest
from ops.testing import Context

from charm import SMTPRelayCharm


@pytest.fixture(name="context")
def context_fixture() -> Iterator[Context[SMTPRelayCharm]]:
    """Context fixture.

    Yield: The charm context.
    """
    yield Context(SMTPRelayCharm)
