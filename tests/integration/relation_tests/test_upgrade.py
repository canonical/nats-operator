import asyncio

import pytest
from helpers import APP_NAMES, APPLICATION_APP_NAME, TEST_APP_CHARM_PATH
from pytest_operator.plugin import OpsTest

from tests.integration.relation_tests.helpers import CHARM_NAME

TLS_CA_CHARM_NAME = "easyrsa"
OLD_CHARM_NAME = "nats-charmers-nats"


@pytest.mark.skip_if_deployed
@pytest.mark.abort_on_fail
async def test_deploy_old(ops_test: OpsTest):
    test_app = await ops_test.build_charm(TEST_APP_CHARM_PATH)
    async with ops_test.fast_forward():
        await asyncio.gather(
            ops_test.model.deploy(
                OLD_CHARM_NAME,
                application_name=CHARM_NAME,
                num_units=1,
                channel="stable",
                series="jammy",
            ),
            ops_test.model.deploy(
                test_app,
                application_name=APPLICATION_APP_NAME,
                num_units=1,
            ),
            ops_test.model.deploy(
                TLS_CA_CHARM_NAME,
                application_name=TLS_CA_CHARM_NAME,
                channel="stable",
                num_units=1,
            ),
        )
        await ops_test.model.relate(f"{TLS_CA_CHARM_NAME}:client", f"{CHARM_NAME}:ca-client")
        await ops_test.model.relate(f"{APPLICATION_APP_NAME}:client", f"{CHARM_NAME}:client")
        await ops_test.model.wait_for_idle(
            apps=[*APP_NAMES, TLS_CA_CHARM_NAME],
            status="active",
            timeout=5000,
            # Do not raise on error as the charms sometime transition from
            # an `error` state while forming relations
            raise_on_error=False,
        )


async def test_upgrade_switch(ops_test: OpsTest):
    charm = await ops_test.build_charm(".")
    await ops_test.model.applications[CHARM_NAME].refresh(path=charm)
    await ops_test.model.wait_for_idle(apps=[*APP_NAMES, TLS_CA_CHARM_NAME], status="active")
