import asyncio

import pytest
from helpers import (
    APP_NAMES,
    APPLICATION_APP_NAME,
    TEST_APP_CHARM_PATH,
    check_relation_data_existence,
)
from pytest_operator.plugin import OpsTest

from tests.integration.relation_tests.helpers import CHARM_NAME


@pytest.mark.skip_if_deployed
async def test_deploy_cluster(ops_test: OpsTest):
    charms = await ops_test.build_charms(".", TEST_APP_CHARM_PATH)
    async with ops_test.fast_forward():
        await asyncio.gather(
            ops_test.model.deploy(
                charms[APPLICATION_APP_NAME],
                application_name=APPLICATION_APP_NAME,
                config={"check_clustering": "true"},
                num_units=1,
            ),
            ops_test.model.deploy(
                charms[CHARM_NAME],
                application_name=CHARM_NAME,
                num_units=3,
            ),
        )
        await ops_test.model.wait_for_idle(apps=APP_NAMES, status="active", timeout=1000)


async def test_relation(ops_test: OpsTest):
    async with ops_test.fast_forward():
        await ops_test.model.relate(f"{APPLICATION_APP_NAME}:client", f"{CHARM_NAME}:client")
        await ops_test.model.wait_for_idle(apps=APP_NAMES, status="active")
        await check_relation_data_existence(
            ops_test,
            APPLICATION_APP_NAME,
            "client",
            "url",
        )
