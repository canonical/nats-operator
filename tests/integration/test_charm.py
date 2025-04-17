#
# Copyright 2024 Canonical Ltd.  All rights reserved.
#
import asyncio
import logging

import nats
import pytest
from nats.errors import Error
from pytest_operator.plugin import OpsTest

STREAM_GATEWAY_NAME = "anbox-stream-gateway"
STREAM_AGENT_NAME = "anbox-stream-agent"
TLS_CHARM_NAME = "easyrsa"
AMS_CHARM_NAME = "ams"

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


async def test_relate_with_anbox_charms(
    ops_test: OpsTest,
    constraints,
    charm_name,
    charm_path,
    anbox_cloud_version,
):
    await asyncio.gather(
        ops_test.model.deploy(
            STREAM_GATEWAY_NAME,
            application_name=STREAM_GATEWAY_NAME,
            num_units=1,
            channel=f"{anbox_cloud_version}/stable",
        ),
        ops_test.model.deploy(
            STREAM_AGENT_NAME,
            application_name=STREAM_AGENT_NAME,
            num_units=1,
            channel=f"{anbox_cloud_version}/stable",
        ),
        ops_test.model.deploy(
            AMS_CHARM_NAME,  # Required by the stream agent
            application_name=AMS_CHARM_NAME,
            channel=f"{anbox_cloud_version}/stable",
            config={
                "use_embedded_etcd": True,
            },
        ),
        ops_test.model.deploy(
            TLS_CHARM_NAME,
            application_name=TLS_CHARM_NAME,
            channel="latest/stable",
            num_units=1,
        ),
    )

    await asyncio.gather(
        ops_test.model.relate(f"{TLS_CHARM_NAME}:client", f"{STREAM_GATEWAY_NAME}:certificates"),
        ops_test.model.relate(f"{TLS_CHARM_NAME}:client", f"{STREAM_AGENT_NAME}:certificates"),
        ops_test.model.relate(f"{TLS_CHARM_NAME}:client", f"{charm_name}:ca-client"),
        ops_test.model.relate(f"{charm_name}:client", f"{STREAM_GATEWAY_NAME}:nats"),
        ops_test.model.relate(f"{charm_name}:client", f"{STREAM_AGENT_NAME}:nats"),
        ops_test.model.relate(f"{STREAM_AGENT_NAME}:ams", f"{AMS_CHARM_NAME}:rest-api"),
        ops_test.model.relate(f"{STREAM_AGENT_NAME}:client", f"{AMS_CHARM_NAME}:agent"),
    )

    await ops_test.model.wait_for_idle(
        apps=[TLS_CHARM_NAME, STREAM_GATEWAY_NAME, STREAM_AGENT_NAME, charm_name],
        status="active",
        timeout=2400,
        # Do not raise on error as the charms sometime transition from
        # an `error` state while forming relations
        raise_on_error=False,
    )
