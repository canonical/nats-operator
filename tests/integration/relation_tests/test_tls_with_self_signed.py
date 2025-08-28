#
# Copyright 2025 Canonical Ltd.  All rights reserved.
#
import asyncio

import pytest
from helpers import APPLICATION_APP_NAME, TEST_APP_CHARM_PATH
from pytest_operator.plugin import OpsTest

TLS_CA_CHARM_NAME = "self-signed-certificates"


@pytest.mark.skip_if_deployed
@pytest.mark.abort_on_fail
@pytest.mark.skip_test_when_juju_2_is_in_use
async def test_deploy_tls(
    ops_test: OpsTest,
    constraints,
    charm_path,
    charm_name,
    charm_channel,
):
    if constraints:
        await ops_test.model.set_constraints(constraints)
    # Build and deploy charm from local source folder or charm store
    if not charm_path:
        if charm_channel:
            charm_path = charm_name
        else:
            charm_path = await ops_test.build_charm(".")
    tester_charm = await ops_test.build_charm(TEST_APP_CHARM_PATH)
    async with ops_test.fast_forward():
        await asyncio.gather(
            ops_test.model.deploy(
                tester_charm,
                application_name=APPLICATION_APP_NAME,
                num_units=1,
            ),
            ops_test.model.deploy(
                charm_path,
                application_name=charm_name,
                num_units=1,
                channel=charm_channel,
            ),
            ops_test.model.deploy(
                TLS_CA_CHARM_NAME,
                application_name=TLS_CA_CHARM_NAME,
                channel="latest/stable",
                num_units=1,
            ),
        )
        await asyncio.gather(
            ops_test.model.relate(f"{TLS_CA_CHARM_NAME}:certificates", f"{charm_name}:ca-client"),
            ops_test.model.relate(f"{APPLICATION_APP_NAME}:client", f"{charm_name}:client"),
        )
        await ops_test.model.wait_for_idle(
            apps=[charm_name, APPLICATION_APP_NAME, TLS_CA_CHARM_NAME],
            status="active",
            timeout=5000,
        )


@pytest.mark.skip_test_when_juju_2_is_in_use
async def test_adding_unit_works(ops_test: OpsTest, charm_name):
    async with ops_test.fast_forward():
        nats_app = ops_test.model.applications[charm_name]
        await nats_app.add_units(count=2)
        await ops_test.model.wait_for_idle(
            apps=[charm_name, APPLICATION_APP_NAME, TLS_CA_CHARM_NAME], status="active"
        )
