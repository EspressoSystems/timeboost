import json
import os
import subprocess

REGIONS = ["us-east-2", "us-west-2", "eu-north-1", "ap-northeast-1", "ap-southeast-2"]
PROFILE = "hotshot"
TEST_CONFIGS_DIR = os.path.join(os.path.dirname(__file__), "..", "test-configs")
CLOUD_SINGLE_PATH = os.path.join(TEST_CONFIGS_DIR, "cloud_single.json")
CLOUD_MULTI_PATH = os.path.join(TEST_CONFIGS_DIR, "cloud_multi.json")


def get_lb_dns_name(region: str):
    cmd = [
        "aws",
        "elbv2",
        "describe-load-balancers",
        "--profile",
        PROFILE,
        "--region",
        region,
        "--query",
        "LoadBalancers[*].DNSName",
        "--output",
        "text",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout.strip()


if __name__ == "__main__":
    print("[*] Fetching DNS names")
    dns_names = {region: get_lb_dns_name(region) for region in REGIONS}

    cloud_single = json.loads(open(CLOUD_SINGLE_PATH).read())

    print(f"[*] Editing {CLOUD_MULTI_PATH}")
    # Now, map the entries to the new DNS
    for i in range(len(cloud_single["keyset"])):
        region = REGIONS[i // 4]
        cloud_single["keyset"][i]["url"] = f"{dns_names[region]}:{8000 + i % 4}"

    with open(CLOUD_MULTI_PATH, "w") as f:
        json.dump(cloud_single, f, indent=4)

    print("[+] Done")
