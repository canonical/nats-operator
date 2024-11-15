#!/usr/bin/env python3
#
# Copyright 2024 Canonical Ltd.  All rights reserved.
#

import os
import yaml
import json
import logging

SUPPORTED_ARCHITECTURES = ("arm64", "amd64")

logging.basicConfig(level=logging.INFO)


def main() -> int:
    charm_root_dir = os.environ.get("CHARM_ROOT_DIR")
    if charm_root_dir:
        os.chdir(charm_root_dir)
    charm_name = os.getcwd().split("/")[-1]
    with open("charmcraft.yaml", "r") as f:
        charmcraft_cfg = yaml.safe_load(f)
    data = []
    for arch in SUPPORTED_ARCHITECTURES:
        data.append(
            {
                "bases": [],
                "arch": arch,
                "name": charm_name,
            }
        )

    for base_idx, base in enumerate(charmcraft_cfg["bases"]):
        for arch in base["architectures"]:
            if arch not in SUPPORTED_ARCHITECTURES:
                raise ValueError(f"Base {base_idx} architecture: {arch} is not supported")
            for runner in data:
                if runner["arch"] == arch:
                    runner["bases"].append(base_idx)

    logging.info(f"bases: {data}")
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        f.write(f"bases={json.dumps(data)}")
    return 0


if __name__ == "__main__":
    SystemExit(main())
