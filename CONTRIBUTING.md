# Contributing

## Requirements

- [Python 3.14+](https://python.org)
- [uv](https://docs.astral.sh/uv/) — Python package manager
- [mise](https://mise.jdx.dev/) — manages tool versions (Python, Node, uv, ruff, etc.)

## Setup

```shell
make setup        # install tool versions, dev dependencies, and pre-commit hooks
```

## Local Development

Start the worker locally with `pywrangler`:

```shell
make dev
```

This runs the Python worker at `http://localhost:8787`. Secrets referenced in `src/config.py` need to be present in a `.dev.vars` file at the project root (key=value format, one per line).

## Testing

Tests are written with pytest and exercise the worker's HTTP endpoints (JSON and wire-format queries, error handling, blocklist/allowlist, ECS truncation, rebind protection, config endpoint, etc.).

### Run tests locally

```shell
make test
```

By default, tests target `http://localhost:8787` (the `make dev` pywrangler server; see `BASE_URL` in `tests/conftest.py`).
To target a different URL:

```shell
BASE_URL=https://localhost make test
```

### Run tests in Kubernetes (CI)

The project includes a full CI pipeline using [Tilt](https://tilt.dev/) and [k3d](https://k3d.io/):

```shell
make k3d-create   # create a local k3d cluster with a registry
make ci           # build, deploy, and run tests in the cluster
```

The `make ci` target runs `tilt ci` which:

1. Builds the Docker image and pushes it to the local k3d registry.
2. Deploys the worker and nginx (with TLS) into the cluster.
3. Runs the pytest suite as a Kubernetes Job against the in-cluster nginx endpoint.
4. Tears down and re-runs with `--config-file=tests/configs/no_ecs_no_rebind.py` to validate disabled ECS truncation and rebind protection.
5. Tears down and re-runs with `--dev-vars=tests/configs/dev-vars-no-token` to validate behavior when `ADMIN_TOKEN` is absent.

In Kubernetes CI, `BASE_URL` is explicitly overridden to `https://nginx` in `k8s/tests.yaml`.
