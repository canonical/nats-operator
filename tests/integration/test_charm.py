#
# Copyright 2024 Canonical Ltd.  All rights reserved.
#
import logging

import nats
import pytest
from nats.errors import Error
from pytest_operator.plugin import OpsTest

logging.basicConfig(level=logging.DEBUG)


@pytest.mark.skip_if_deployed
@pytest.mark.abort_on_fail
async def test_smoke(
    ops_test: OpsTest,
    constraints,
    charm_path,
):
    # Build and deploy charm from local source folder
    if not charm_path:
        charm_path = await ops_test.build_charm(".")
    if constraints:
        await ops_test.model.set_constraints(constraints)
    app = await ops_test.model.deploy(charm_path)
    await ops_test.model.block_until(lambda: app.status in ("active", "error"), timeout=300)
    assert app.status, "active"


@pytest.mark.asyncio
async def test_configured_with_token(ops_test: OpsTest, charm_name):
    ip = ops_test.model.applications[charm_name].units[0].public_address
    with pytest.raises(Error) as e:
        await nats.connect(f"nats://{ip}:4222", allow_reconnect=False)
    assert e.value.args[0] == "nats: 'Authorization Violation'"
