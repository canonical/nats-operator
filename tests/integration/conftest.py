#
# Copyright 2024 Canonical Ltd.  All rights reserved.
#
import zipfile
from pathlib import Path

import pytest
import yaml

OLD_CHARM_NAME = "nats-charmers-nats"


UBUNTU_SERIES_MAP = {
    "22.04": "jammy",
    "24.04": "noble",
}


def extract_series(charm_path):
    with zipfile.ZipFile(charm_path, "r") as f:
        metadata_file = next((m for m in f.namelist() if m.endswith("manifest.yaml")), None)
        if metadata_file:
            metadata_content = f.read(metadata_file).decode("utf-8")
            metadata = yaml.safe_load(metadata_content)
            bases = metadata.get("bases", [])
            if bases:
                channel = bases[0].get("channel")
                if channel in UBUNTU_SERIES_MAP:
                    return UBUNTU_SERIES_MAP[channel]
                raise ValueError("Invalid or unsupported Ubuntu series")

    raise ValueError("Failed to extract series from charm metadata")


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        f"skip_upgrade_on_noble: Skip upgrade test as {OLD_CHARM_NAME} is not available on Noble.",
    )


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    if "skip_upgrade_on_noble" in item.keywords:
        charm_path = item.config.getoption("--charm")
        series = extract_series(charm_path)
        if series == "noble":
            pytest.skip(
                f"{OLD_CHARM_NAME} is unavailable on Noble. Skipping the upgrade test on Noble."
            )


def pytest_addoption(parser):
    parser.addoption("--constraints", default="", action="store", help="Model constraints")
    parser.addoption("--charm", default="", action="store", help="Path to a built charm")


@pytest.fixture
def charm_name():
    metadata = yaml.safe_load(Path("./charmcraft.yaml").read_text())
    return metadata["name"]


@pytest.fixture
def constraints(request) -> dict:
    constraints = request.config.getoption("--constraints")
    cts = {}
    for constraint in constraints.split(" "):
        if not constraint:
            continue
        k, v = constraint.split("=")
        cts[k] = v
    return cts


@pytest.fixture
def charm_path(request):
    return request.config.getoption("--charm")
