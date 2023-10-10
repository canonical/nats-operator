from pathlib import Path
from typing import Literal, Optional

import yaml
from pytest_operator.plugin import OpsTest
from tenacity import RetryError, Retrying, stop_after_attempt, wait_exponential

APPLICATION_APP_NAME = "nats-tester"
TEST_APP_CHARM_PATH = "tests/integration/relation_tests/application-charm"
CHARM_NAME = yaml.safe_load(Path("metadata.yaml").read_text())["name"]
APP_NAMES = [APPLICATION_APP_NAME, CHARM_NAME]


async def get_alias_from_relation_data(
    ops_test: OpsTest, unit_name: str, related_unit_name: str
) -> Optional[str]:
    """Get the alias that the unit assigned to the related unit application/cluster.

    Args:
        ops_test: The ops test framework instance
        unit_name: The name of the unit
        related_unit_name: name of the related unit

    Returns:
        the alias for the application/cluster of
            the related unit

    Raises:
        ValueError if it's not possible to get unit data
            or if there is no alias on that.
    """
    raw_data = (await ops_test.juju("show-unit", related_unit_name))[1]
    if not raw_data:
        raise ValueError(f"no unit info could be grabbed for {related_unit_name}")
    data = yaml.safe_load(raw_data)

    # Retrieve the relation data from the unit.
    relation_data = {}
    for relation in data[related_unit_name]["relation-info"]:
        for name, unit in relation["related-units"].items():
            if name == unit_name:
                relation_data = unit["data"]
                break

    # Check whether the unit has set an alias for the related unit application/cluster.
    if "alias" not in relation_data:
        raise ValueError(f"no alias could be grabbed for {related_unit_name} application/cluster")

    return relation_data["alias"]


async def get_relation_data(
    ops_test: OpsTest,
    application_name: str,
    relation_name: str,
    key: str,
    databag: Literal["application", "unit"],
    relation_id: str | None = None,
    relation_alias: str | None = None,
) -> Optional[str]:
    """Get relation data for an application.

    Args:
        ops_test: The ops test framework instance
        application_name: The name of the application
        relation_name: name of the relation to get connection data from
        key: key of data to be retrieved
        databag: Type of data bag i.e application or unit, to check the key in. Defaults to "unit".
        relation_id: id of the relation to get connection data from
        relation_alias: alias of the relation (like a connection name)
            to get connection data from

    Returns:
        the data that was requested or None
            if no data in the relation

    Raises:
        ValueError if it's not possible to get application data
            or if there is no data for the particular relation endpoint
            and/or alias.
    """
    unit_name = ops_test.model.applications[application_name].units[0].name
    raw_data = (await ops_test.juju("show-unit", unit_name))[1]
    if not raw_data:
        raise ValueError(f"no unit info could be grabbed for {unit_name}")
    data = yaml.safe_load(raw_data)
    # Filter the data based on the relation name.
    relation_data = [v for v in data[unit_name]["relation-info"] if v["endpoint"] == relation_name]
    if relation_id:
        # Filter the data based on the relation id.
        relation_data = [v for v in relation_data if v["relation-id"] == relation_id]
    if relation_alias:
        # Filter the data based on the cluster/relation alias.
        relation_data = [
            v
            for v in relation_data
            if await get_alias_from_relation_data(
                ops_test, unit_name, next(iter(v["related-units"]))
            )
            == relation_alias
        ]
    if len(relation_data) == 0:
        raise ValueError(
            f"no relation data could be grabbed on relation with endpoint {relation_name} and alias {relation_alias}"
        )
    if databag == "application":
        return relation_data[0]["application-data"].get(key)
    elif databag == "unit":
        related_unit = relation_data[0]["related-units"].popitem()
        return related_unit[1]["data"].get(key)
    else:
        raise ValueError("databag can only be of type 'unit' or 'application'")


async def check_relation_data_existence(
    ops_test: OpsTest,
    application_name: str,
    relation_name: str,
    key: str,
    exists: bool = True,
    databag: Literal["unit", "application"] = "unit",
) -> bool:
    """Check for the existence of a key in the relation data.

    Args:
        ops_test: The ops test framework instance
        application_name: The name of the application
        relation_name: Name of the relation to get relation data from
        key: Key of data to be checked
        exists: Whether to check for the existence or non-existence
        databag: Type of data bag i.e application or unit, to check the key in. Defaults to "unit".

    Returns:
        whether the key exists in the relation data
    """
    try:
        # Retry mechanism used to wait for some events to be triggered,
        # like the relation departed event.
        for attempt in Retrying(
            stop=stop_after_attempt(10), wait=wait_exponential(multiplier=1, min=2, max=30)
        ):
            with attempt:
                data = await get_relation_data(
                    ops_test,
                    application_name,
                    relation_name,
                    key,
                    databag,
                )
                if exists:
                    assert data is not None
                else:
                    assert data is None
        return True
    except RetryError:
        return False
