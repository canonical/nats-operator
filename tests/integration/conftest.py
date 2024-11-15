#
# Copyright 2024 Canonical Ltd.  All rights reserved.
#
from pathlib import Path

import pytest
import yaml


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
