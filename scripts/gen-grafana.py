#!/usr/bin/env python3

import subprocess
import logging
import json
import os
from typing import Dict, Any

logger = logging.getLogger("gen-grafana")
logging.basicConfig(level=logging.DEBUG)

DOCKER_IPS = [
    "172.20.0.2",
    "172.20.0.3",
    "172.20.0.4",
    "172.20.0.5",
    "172.20.0.6",
]

PROM_PATH = os.path.join("prometheus", "prometheus.yml")
GRAF_PATH = os.path.join("grafana", "dashboards")
ENTRY_TEMPLATE = r"""
        {{
          "datasource": "prom1",
          "disableTextWrap": false,
          "editorMode": "builder",
          "expr": "committed_round{{instance=\"{}:{}\"}}",
          "fullMetaSearch": false,
          "includeNullMetadata": true,
          "legendFormat": "__auto",
          "range": true,
          "refId": "A",
          "useBackend": false
        }}
"""
PROM_FILE = r"""
global:
  scrape_interval: 5s

scrape_configs:
- job_name: status
  static_configs:
    - targets:
      - 172.20.0.2:9000
      - 172.20.0.3:9001
      - 172.20.0.4:9002
      - 172.20.0.5:9003
      - 172.20.0.6:9004
  metrics_path: /v0/status/metrics

global:
  scrape_interval: 5s

scrape_configs:
- job_name: cloud_status
  static_configs:
    - targets:
      {}
  metrics_path: /v0/status/metrics
"""


def make_entry(ip: str, port: int) -> str:
    return ENTRY_TEMPLATE.format(ip, port)


def get_ips() -> list[str]:
    logger.info("attempting to fetch ips from aws")
    try:
        ret = subprocess.run(
            "./scripts/get-task-ips timeboost timeboost",
            shell=True,
            check=True,
            capture_output=True,
        )
        logger.info("successfully fetched ips")
        return ret.stdout.decode().strip().split("\n")
    except Exception as e:
        print("process failed", e)
        return DOCKER_IPS


def make_grafana(ips: list[Dict[str, Any]]):
    # Read the grafana file
    filename = os.path.join(GRAF_PATH, "cloud.json")
    with open(filename) as f:
        j = json.load(f)

    # Find the committed round entry
    for panel in j["panels"]:
        if panel["title"].lower() == "committed round":
            # Get the targets
            panel["targets"] = ips

    # Write it back to the file
    with open(filename, "w") as f:
        json.dump(j, f, indent=2)


def make_prom(ips: list[str]) -> str:
    targets_yaml = "\n      - ".join(ips)
    formatted = PROM_FILE.format(f"\n      - {targets_yaml}")

    with open(PROM_PATH, "w") as f:
        f.write(formatted)


if __name__ == "__main__":
    if "scripts" in os.getcwd():
        print("don't run this from the scripts folder, run from the timeboost folder")
        exit(1)

    ip_addrs = get_ips()
    ips = [json.loads(make_entry(ip, 9000)) for ip in ip_addrs]

    make_grafana(ips)
    make_prom([f"{ip}:9000" for ip in ip_addrs])
