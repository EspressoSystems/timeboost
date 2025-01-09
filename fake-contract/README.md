# Fake Contract
A fake contract that orchestrates the keys. This allows for network deployments to not rely on hard-coded data like we do normally.

## Getting Started
First, cd into the `fake-contract` directory, then:
1. Grab [uv](https://docs.astral.sh/uv/)
2. Run `uv sync`

Now, `cd ..` and just do `just run_fake_contract` when you need the contract server. It should boot on`localhost:7200` by default. If you need help, `just run_fake_contract --help`. Note that to target the contract server you need to use the new base option for the builder. Here's an example startup command:

```bash
RUST_LOG=timeboost=debug just run --bin timeboost -- --id 0 --port 8000 --rpc-port 8800 --metrics-port 9000 --committee-size 5 --base network --startup-url http://localhost:7200/
```
