import asyncio

from helpers import APP_NAMES, APPLICATION_APP_NAME, TEST_APP_CHARM_PATH
from pytest_operator.plugin import OpsTest

from tests.integration.relation_tests.helpers import CHARM_NAME

TLS_CA_CHARM_NAME = "easyrsa"

async def test_deploy_tls(ops_test: OpsTest):
    charms = await ops_test.build_charms(".", TEST_APP_CHARM_PATH)
    async with ops_test.fast_forward():
        await asyncio.gather(
            ops_test.model.deploy(
                charms[APPLICATION_APP_NAME],
                application_name=APPLICATION_APP_NAME,
                num_units=1,
            ),
            ops_test.model.deploy(
                charms[CHARM_NAME],
                application_name=CHARM_NAME,
                num_units=1,
            ),
            ops_test.model.deploy(
                TLS_CA_CHARM_NAME,
                application_name=TLS_CA_CHARM_NAME,
                channel="stable",
                num_units=1,
            ),
        )
        await ops_test.model.wait_for_idle(
            apps=[*APP_NAMES, TLS_CA_CHARM_NAME], status="active", timeout=1000
        )


async def test_tls_enabled(ops_test: OpsTest):
    async with ops_test.fast_forward():
        await ops_test.model.relate(f"{TLS_CA_CHARM_NAME}:client", f"{CHARM_NAME}:ca-client")
        await ops_test.model.relate(f"{APPLICATION_APP_NAME}:client", f"{CHARM_NAME}:client")
        await ops_test.model.wait_for_idle(apps=[*APP_NAMES, TLS_CA_CHARM_NAME], status="active")
