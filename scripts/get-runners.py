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
    for platform in charmcraft_cfg.get("platforms", {}):
        distro, arch = platform.split(":")
        version = distro.split("@")[-1]
        if arch not in SUPPORTED_ARCHITECTURES:
            raise ValueError(f"Unsupported architecture: {arch}")
        data.append(
            {
                "version": version,
                "arch": arch,
                "charm_name": charm_name,
            }
        )

    logging.info(f"platforms: {data}")
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        f.write(f"platforms={json.dumps(data)}")
    return 0


if __name__ == "__main__":
    SystemExit(main())
