import logging

from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)


async def test_smoke(ops_test: OpsTest):
    charm = await ops_test.build_charm(".", verbosity="debug")
    app = await ops_test.model.deploy(charm)
    await ops_test.model.block_until(lambda: app.status in ("active", "error"), timeout=300)
    assert app.status, "active"
