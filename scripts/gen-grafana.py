#!/usr/bin/env python3

import subprocess
import os

DOCKER_IPS = [
    "172.20.0.2",
    "172.20.0.3",
    "172.20.0.4",
    "172.20.0.5",
    "172.20.0.6",
]

PROM_PATH = os.path.join("prometheus", "prometheus.yml")


def get_ips() -> list[str]:
    try:
        ret = subprocess.run(
            "./scripts/get-task-ips timeboost timeboost".split(),
            shell=True,
            check=True,
            capture_output=True,
        )
        print(ret.stdout)
        print(ret.stderr)
    except Exception as e:
        print("process failed", e)


if __name__ == "__main__":
    if "scripts" in os.getcwd():
        print("don't run this from the scripts folder, run from the timeboost folder")
        exit(1)
