import asyncio

import pytest
from helpers import APP_NAMES, APPLICATION_APP_NAME, TEST_APP_CHARM_PATH
from nrpe.client import logging
from pytest_operator.plugin import OpsTest

from tests.integration.relation_tests.helpers import CHARM_NAME

TLS_CA_CHARM_NAME = "easyrsa"


@pytest.mark.skip_if_deployed
@pytest.mark.abort_on_fail
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
            apps=[*APP_NAMES, TLS_CA_CHARM_NAME], status="active", timeout=5000
        )


async def test_tls_enabled(ops_test: OpsTest):
    async with ops_test.fast_forward():
        await ops_test.model.relate(f"{TLS_CA_CHARM_NAME}:client", f"{CHARM_NAME}:ca-client")
        await ops_test.model.relate(f"{APPLICATION_APP_NAME}:client", f"{CHARM_NAME}:client")
        await ops_test.model.wait_for_idle(apps=[*APP_NAMES, TLS_CA_CHARM_NAME], status="active")


async def test_secrets(ops_test: OpsTest):
    # Check that on juju 3 we have secrets
    if hasattr(ops_test.model, "list_secrets"):
        logging.info("checking for secrets")
        secrets = await ops_test.model.list_secrets()
        assert len(secrets.results) > 0, "secrets not found"
    else:
        pytest.skip("secrets not supported for juju < 3.0")


async def test_adding_unit_works(ops_test: OpsTest):
    async with ops_test.fast_forward():
        nats_app = ops_test.model.applications[CHARM_NAME]
        await nats_app.add_units(count=2)
        await ops_test.model.wait_for_idle(apps=[*APP_NAMES, TLS_CA_CHARM_NAME], status="active")
