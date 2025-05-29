# Test/Demo network configuration

To generate a new set of keys (optionally, you can seed it like `--seed 42`):

``` sh
just mkconfig_local 5 --seed 42 > test-configs/local-5.json
just mkconfig_local 13 --seed 42 > test-configs/local-13.json
just mkconfig_docker 5 --seed 42 > test-configs/docker.json
just mkconfig_cloud_single > test-configs/cloud_single.json
# run with whatever python runner you use
uv run scripts/gen-multi.py
```
