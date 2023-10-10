import logging
from pathlib import Path

import nats
import pytest
import yaml
from nats.errors import Error
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]


@pytest.mark.skip_if_deployed
async def test_smoke(ops_test: OpsTest):
    charm = await ops_test.build_charm(".", verbosity="debug")
    app = await ops_test.model.deploy(charm)
    await ops_test.model.block_until(lambda: app.status in ("active", "error"), timeout=300)
    assert app.status, "active"


@pytest.mark.asyncio
async def test_configured_with_token(ops_test: OpsTest):
    ip = ops_test.model.applications[APP_NAME].units[0].public_address
    with pytest.raises(Error) as e:
        await nats.connect(f"nats://{ip}:4222", allow_reconnect=False)
    assert e.value.args[0] == "nats: 'Authorization Violation'"
