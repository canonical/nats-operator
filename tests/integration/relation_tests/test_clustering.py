#
# Copyright 2024 Canonical Ltd.  All rights reserved.
#
import asyncio

import pytest
from helpers import (
    APP_NAMES,
    APPLICATION_APP_NAME,
    TEST_APP_CHARM_PATH,
    check_relation_data_existence,
)
from pytest_operator.plugin import OpsTest


@pytest.mark.skip_if_deployed
@pytest.mark.abort_on_fail
async def test_deploy_cluster(ops_test: OpsTest, constraints, charm_path, charm_name):
    if constraints:
        await ops_test.model.set_constraints(constraints)
    # Build and deploy charm from local source folder
    if not charm_path:
        charm_path = await ops_test.build_charm(".")
    tester_charm = await ops_test.build_charm(TEST_APP_CHARM_PATH)
    async with ops_test.fast_forward():
        await asyncio.gather(
            ops_test.model.deploy(
                tester_charm,
                application_name=APPLICATION_APP_NAME,
                num_units=1,
                config={"check_clustering": "true"},
            ),
            ops_test.model.deploy(
                charm_path,
                application_name=charm_name,
                num_units=3,
            ),
        )
        await ops_test.model.wait_for_idle(apps=APP_NAMES, status="active", timeout=1000)


async def test_relation(ops_test: OpsTest, charm_name):
    async with ops_test.fast_forward():
        await ops_test.model.relate(f"{APPLICATION_APP_NAME}:client", f"{charm_name}:client")
        await ops_test.model.wait_for_idle(
            apps=[charm_name, APPLICATION_APP_NAME], status="active"
        )
        await check_relation_data_existence(
            ops_test,
            APPLICATION_APP_NAME,
            "client",
            "url",
        )
