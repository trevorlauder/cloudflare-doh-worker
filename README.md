# Cloudflare DoH Worker

[![CI](https://github.com/trevorlauder/cloudflare-doh-worker/actions/workflows/ci.yml/badge.svg)](https://github.com/trevorlauder/cloudflare-doh-worker/actions/workflows/ci.yml)

> [!IMPORTANT]
> This is a complete rewrite in Python. If you want the previous JavaScript version, use the [0.9.0 release](https://github.com/trevorlauder/cloudflare-doh-worker/tree/0.9.0). The JavaScript version will no longer receive updates.

> [!IMPORTANT]
> This document may not reflect the latest release. For current documentation, visit the [2.0.1 README](https://github.com/trevorlauder/cloudflare-doh-worker/tree/2.0.1).

A Cloudflare Worker that proxies DNS-over-HTTPS queries to multiple upstream providers in parallel and returns the most restrictive result. If **any** provider blocks a domain, it's blocked.

This started as [a workaround](https://www.lauder.family/blog/2021/09/25/Avoiding-DoH-Detection-and-Blocking/) when our school division blocked DoH on my kids' devices. It was a simple Cloudflare Worker proxying to NextDNS on a custom domain. This version takes that further, letting you proxy to as many DoH providers as you want and combine their filtering.

## Features

- Fan-out to multiple DoH providers, pick the most restrictive answer
- Domain blocklist and allowlist in [`src/config.py`](src/config.py) to ensure specific domains are always blocked or never blocked, regardless of upstream provider responses (not meant for huge community lists)
- Community block lists configured in [`blocklist_sources.yaml`](blocklist_sources.yaml), bundled as Workers Assets, with an optional GitHub Action to keep them updated automatically
- Allowed domains skip fan-out and go straight to a non-filtering bypass provider (default: Cloudflare)
- EDNS Client Subnet prefix truncation for privacy
- DNS rebind protection (blocks responses resolving to private IPs)
- `${SECRET_NAME}` placeholders in config, resolved from Cloudflare Worker secrets at request time
- Health check and live config inspection endpoints (config endpoint requires `ADMIN_TOKEN`)
- Debug mode adds diagnostic response headers
- Automatic retry on 5xx responses from upstream providers
- Optional Grafana Loki logging
- Supports both `dns-message` and `dns-json` content types

## Requirements

- A Cloudflare account (free tier should be fine for personal use)
- [mise](https://mise.jdx.dev) for installing dependencies (`uv`, `node`, `python`, `rust`)
- Grafana Loki (optional, for request logging)

## Deploy

> [!NOTE]
> You do not deploy from the `main` branch. The `main` branch is the development branch and contains source code, tests, and CI tooling that are not needed to run it. Instead, each release has a corresponding `deploy-x.y.z` tag that contains only the files needed to run the worker. Both deploy methods below use these deploy tags as the starting point for your repo.

### Quickstart Deploy

Use this button to deploy this worker to your Cloudflare account.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/trevorlauder/cloudflare-doh-worker/tree/deploy-2.0.1)

- When prompted during setup, set **Deploy command** to `npm run deploy` and leave **Build command** empty.

- Update [`wrangler.toml`](wrangler.toml) and [`src/config.py`](src/config.py) **in your new repo** created by Cloudflare, based on your needs. See [Configuration](#configuration) for details.

- Add any secrets referenced in your config via `${SECRET_NAME}` placeholders:

  ```shell
  # Add each secret referenced in your config, for example:
  uv run pywrangler secret put LOKI_PASSWORD
  ```

  Common optional secrets:

  | Secret          | Required when              |
  | --------------- | -------------------------- |
  | `ADMIN_TOKEN`   | Using the config endpoint  |
  | `LOKI_URL`      | Using Grafana Loki logging |
  | `LOKI_USERNAME` | Using Grafana Loki logging |
  | `LOKI_PASSWORD` | Using Grafana Loki logging |

### Manual Deploy

- Fork this repo on GitHub, then clone your fork and reset `main` to the latest deploy tag:

  ```shell
  git clone https://github.com/your-username/cloudflare-doh-worker.git
  cd cloudflare-doh-worker
  git checkout -B main deploy-2.0.1
  git push --force-with-lease origin main
  ```

- Update [`wrangler.toml`](wrangler.toml) with your routes/domains.

- Update [`src/config.py`](src/config.py) with your endpoint paths and provider details. See [Configuration](#configuration).

- Add your secrets as shown in [Quickstart Deploy](#quickstart-deploy).

- Install [mise](https://mise.jdx.dev), then install dependencies:

  ```shell
  mise install
  uv sync
  ```

- Deploy:

  ```shell
  uv run pywrangler deploy
  ```

  The first time you run this, it will need to log into your Cloudflare account and provide permission for Wrangler.

## Configuration

All config lives in [`src/config.py`](src/config.py). You can define as many endpoint paths as you need. Each one proxies to its own set of upstream DoH providers.

Each endpoint has one `main_provider` (whose answer is used when nothing is blocked) and optional `additional_providers`.

Each provider dict accepts `url`, and optionally `headers` and `dns_json`. Add `"dns_json": True` to providers that support `application/dns-json` so they aren't skipped for those requests.

If your repo is public, use `${SECRET_NAME}` placeholders for sensitive values like endpoint paths and provider paths. Placeholders are resolved from Cloudflare Worker secrets on the first request and cached for the lifetime of the Worker instance. Changes to secrets take effect when the Worker is redeployed or replaced. Setting your endpoint paths to include random strings keeps them from being discovered.

`ENDPOINTS` is the only required option. Everything else has a default and can be omitted. See [`examples/config.py`](examples/config.py) for a real-world example.

<details>
<summary>All configuration options</summary>

| Option               | Default                                                             | Description                                                                                                                                             |
| -------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ALLOWED_DOMAINS`    | `[]`                                                                | Domains to bypass fan-out and send to `BYPASS_PROVIDER` only                                                                                            |
| `BLOCKED_DOMAINS`    | `[]`                                                                | Domains to block with synthetic `NXDOMAIN` (supports `*.example.com` wildcards)                                                                         |
| `BLOCKLIST_ENABLED`  | `True`                                                              | Enable the community block list. Set to `False` to disable all filter checks                                                                            |
| `BYPASS_PROVIDER`    | `{"url": "https://cloudflare-dns.com/dns-query", "dns_json": True}` | Non-filtering provider used for allowed domains                                                                                                         |
| `CACHE_DNS`          | `True`                                                              | Cache DNS responses in the Cloudflare Cache API using the response TTL                                                                                  |
| `DEBUG`              | `False`                                                             | Enable verbose logging and diagnostic response headers                                                                                                  |
| `ECS_TRUNCATION`     | `{"enabled": False}`                                                | Truncate EDNS Client Subnet prefixes for privacy. Optional `ipv4_prefix` (default `24`) and `ipv6_prefix` (default `64`) control the truncation lengths |
| `PATH_PREFIX`        | `"/"`                                                               | Prefix prepended to all routes, including `/health` and `/config`. Supports `${SECRET}` placeholders                                                    |
| `ENDPOINTS`          | **required**                                                        | Map of URL paths to endpoint configs. Each entry requires a `main_provider` and optionally `additional_providers`                                       |
| `LOKI_TIMEOUT_MS`    | `5000`                                                              | Loki push timeout in milliseconds                                                                                                                       |
| `LOKI_URL`           | `""`                                                                | Grafana Loki push endpoint (also requires `LOKI_USERNAME` and `LOKI_PASSWORD` secrets)                                                                  |
| `REBIND_PROTECTION`  | `True`                                                              | Block responses that resolve to private/internal IPs                                                                                                    |
| `RETRY_MAX_ATTEMPTS` | `2`                                                                 | Number of times to retry a provider on 5xx responses before giving up. Set to `0` to disable retries                                                    |
| `TIMEOUT_MS`         | `5000`                                                              | Upstream provider timeout in milliseconds                                                                                                               |

</details>

## Blocking Methods

| Method                                                                     | How it works                                                                                                                                                                                      | When to use it                                                                |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Upstream provider filtering                                                | Providers like NextDNS and Quad9 apply their own lists and return blocked responses                                                                                                               | Zero config, no maintenance                                                   |
| `BLOCKED_DOMAINS` in config                                                | Checked before any upstream query                                                                                                                                                                 | Personal overrides or domains upstream providers don't cover. Keep this small |
| Community block lists ([`blocklist_sources.yaml`](blocklist_sources.yaml)) | Lists are fetched, merged, and bundled as Workers Assets as ~512 KB BinaryFuse32 filter shards. Only the shard matching the queried domain is fetched per request and cached in a 50 MB LRU cache | Large curated lists that are too big to put in config                         |

Both block lists are checked on every request. `ALLOWED_DOMAINS` takes precedence over both.

## Community Block List

Add URLs to [`blocklist_sources.yaml`](blocklist_sources.yaml):

```yaml
---
urls:
  - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
```

Each URL should point to a hosts-file format or plain domain-per-line list.

Then run:

```shell
uv run python scripts/build_blocklist.py
```

Commit the generated filter shards and metadata. The raw download files are gitignored.

The filter uses [BinaryFuse32](https://crates.io/crates/xorf), a compact probabilistic data structure with a fixed false-positive rate of ~1/2^32. At ~4.5 bytes per domain, ~**4.2 million** unique domains produce a filter of roughly **18 MB**. The filter is split into ~512 KB shards so that only the shard matching the queried domain is fetched per request and cached in a 50 MB LRU cache, keeping memory use low.

#### Options

| Flag              | Default | Description                                                            |
| ----------------- | ------- | ---------------------------------------------------------------------- |
| `--verify`        |         | After building, re-check every domain to confirm zero false negatives. |
| `--fp-check N`    | `0`     | Probe N absent domains and report the empirical false-positive rate.   |
| `--skip-download` |         | Skip fetching URLs. Re-use existing `blocklist/<i>.txt` files instead. |

### False-positive rate

The community blocklist uses a [BinaryFuse32 filter](https://crates.io/crates/xorf), a probabilistic data structure that can say "definitely not blocked" or "probably blocked." It has **no false negatives** (a domain in the list is always detected), but it does have a small **false-positive rate** of ~1/2^32 (~2.3e-10): an unlisted domain may very occasionally be matched and blocked. This rate is fixed by the data structure and is not configurable.

**What if a legitimate domain is blocked by mistake?**
If you notice a legitimate domain being blocked due to a false positive, add it to your `ALLOWED_DOMAINS` list in `src/config.py`. This will ensure it is always allowed, even if the filter matches it. After updating the allowlist, redeploy the worker to apply the change.

**What happens if you add a very large source?**

The filter automatically resizes as you add more domains while maintaining the same fixed false-positive rate. At ~4.5 bytes per domain, even millions of domains produce a compact filter.

### GitHub Actions (automatic)

Enable the included `.github/workflows/update-blocklist.yml` workflow (commented out by default). It runs weekly, re-fetches each source, rebuilds the filter shards, and opens a PR if anything changed.

This file is included in the deploy branch and will be present in your repo after following the [deploy instructions](#quickstart-deploy).

To enable it, uncomment the entire contents of `.github/workflows/update-blocklist.yml`.

### Manual

```shell
uv run python scripts/build_blocklist.py
git add blocklist/shard_*.bin src/filter_meta.py
git commit -m "Update blocklist"
uv run pywrangler deploy
```

`build_blocklist.py` downloads the sources, builds the filter shards, and writes them to `blocklist/`. The raw download files are not committed.

## Updating

Check [CHANGELOG.md](CHANGELOG.md) and the [release notes](https://github.com/trevorlauder/cloudflare-doh-worker/releases) before updating to see if any config changes are required.

Add this repo as an upstream remote (only needed once), then merge the new deploy tag:

```shell
git remote add upstream https://github.com/trevorlauder/cloudflare-doh-worker.git
git fetch upstream
git merge --allow-unrelated-histories deploy-2.0.1  # replace with the new version tag
```

### Avoiding merge conflicts

Since the deploy branch is force-pushed as an orphan, merges can produce conflicts on every file. A `.gitattributes` file is included that auto-accepts upstream changes for all files and keeps your local versions of `src/config.py`, `blocklist_sources.yaml`, and `wrangler.toml`. To enable it, set up the custom merge drivers it references:

```shell
git config merge.theirs.driver 'cp %B %A'
git config merge.ours.driver true
```

With this in place, all files will silently accept the upstream version except `src/config.py`, `blocklist_sources.yaml`, and `wrangler.toml`, which will keep your local versions unchanged. Check the release notes for any required changes to those files and apply them manually.

After applying any changes, redeploy.

## Latency

Measured with [k6](https://k6.io/) from a residential connection in Alberta, Canada using [`tests/latency.js`](tests/latency.js). Your numbers will differ depending on how close you are to each provider's PoPs.

Queries for domains on the worker's own blocklist never leave the worker. They hit the blocklist, return a synthetic NXDOMAIN, and take ~36-38ms regardless of provider config, even with a ~4.2 million domain filter loaded. That's the worker's base overhead. Everything above that on a normal query is time spent waiting for upstream providers.

### Single provider through worker

| Provider   | Wire GET | Wire POST | Overhead vs direct |
| ---------- | -------- | --------- | ------------------ |
| Cloudflare | 49ms     | 48ms      | ~13ms              |
| NextDNS    | 62ms     | 75ms      | ~29ms              |
| Quad9      | 88ms     | 78ms      | ~43ms              |

### All providers combined

~106ms GET, ~97ms POST. Fans out to all three in parallel, so latency is bounded by the slowest provider (Quad9 at ~88ms) plus ~18ms of fan-out coordination overhead.

## Design

![Cloudflare DoH Worker Sequence Diagram](docs/Cloudflare-DoH-Worker.svg)

### How it works

- **Blocklist**: matched domains return a synthetic `NXDOMAIN` without querying any upstream providers.

- **Allowlist**: uses the same matching rules. Matched domains skip fan-out and go to `BYPASS_PROVIDER` (which should be non-filtering). If a domain is in both lists, the allowlist takes precedence and the domain will be resolved, not blocked.

- **Response classification**:
  - `0.0.0.0` or `::` = blocked
  - `NXDOMAIN` = possibly blocked
  - No response within `TIMEOUT_MS` = timed out

- **Response priority**
  1. Blocked response (any provider)
  2. Possibly blocked response
  3. Main provider's response
  4. Any additional provider's response
  5. Error (all providers failed)

- **Rebind protection**: if enabled and every successful answer points to a private IP, the worker returns `NXDOMAIN`. If at least one provider returns a non-private answer, that one wins.

- **ECS truncation**: strips EDNS Client Subnet prefixes down when enabled.

- **Debug mode** (`DEBUG = True`) sets log level to `DEBUG` and adds diagnostic headers to every DNS response.

  Always-present headers (when applicable):

  | Header                                               | Value                                                                        |
  | ---------------------------------------------------- | ---------------------------------------------------------------------------- |
  | `CLOUDFLARE-DOH-WORKER-CONFIG-ALLOWED`               | `1` when domain matched the allowlist                                        |
  | `CLOUDFLARE-DOH-WORKER-CONFIG-BLOCKED`               | `1` when domain matched the blocklist                                        |
  | `CLOUDFLARE-DOH-WORKER-ECS-TRUNCATED`                | ECS prefix rewrite description when truncation occurred                      |
  | `CLOUDFLARE-DOH-WORKER-PROVIDERS-CONNECTION-ERROR`   | Number of providers that failed with a connection error                      |
  | `CLOUDFLARE-DOH-WORKER-PROVIDERS-FAILED-STATUS-CODE` | Number of providers that failed with a 5xx response after exhausting retries |
  | `CLOUDFLARE-DOH-WORKER-PROVIDERS-FAILED`             | Number of providers that failed (all causes)                                 |
  | `CLOUDFLARE-DOH-WORKER-PROVIDERS-QUERIED`            | Number of providers contacted                                                |
  | `CLOUDFLARE-DOH-WORKER-PROVIDERS-RETRIED`            | Number of providers that were retried at least once                          |
  | `CLOUDFLARE-DOH-WORKER-PROVIDERS-TIMED-OUT`          | Number of providers that timed out                                           |
  | `CLOUDFLARE-DOH-WORKER-REBIND-PROTECTED`             | `1` when rebind protection triggered                                         |

  Additional headers only present in debug mode:

  | Header                                             | Value                                         |
  | -------------------------------------------------- | --------------------------------------------- |
  | `CLOUDFLARE-DOH-WORKER-BLOCKED-PROVIDERS`          | Providers that returned a blocked response    |
  | `CLOUDFLARE-DOH-WORKER-CONNECTION-ERROR-PROVIDERS` | Providers that failed with a connection error |
  | `CLOUDFLARE-DOH-WORKER-POSSIBLY-BLOCKED-PROVIDERS` | Providers that returned `NXDOMAIN`            |
  | `CLOUDFLARE-DOH-WORKER-RESPONSE-CODES`             | Per-provider status codes                     |
  | `CLOUDFLARE-DOH-WORKER-RESPONSE-FROM`              | Provider ID that won                          |
  | `CLOUDFLARE-DOH-WORKER-TIMED-OUT-PROVIDERS`        | Providers that timed out                      |

- **Retry logic**: retries upstream providers on both 5xx responses and connection errors up to `RETRY_MAX_ATTEMPTS` times before marking them failed.

- **Loki logging** is async and only active when `LOKI_URL`, `LOKI_USERNAME`, and `LOKI_PASSWORD` are all set.

## Grafana

A sample dashboard is included in [`dashboard/grafana.json`](dashboard/grafana.json). Import it into Grafana, select your Loki datasource, and save.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, design details, and testing instructions.
