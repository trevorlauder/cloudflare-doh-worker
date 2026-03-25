# cloudflare-doh-worker

This is a deploy branch. For documentation, see the [README](https://github.com/trevorlauder/cloudflare-doh-worker/blob/2.0.0/README.md) for this release.

[Grafana dashboard](https://github.com/trevorlauder/cloudflare-doh-worker/blob/2.0.0/dashboard/grafana.json) for this release.

[Additional example configs](https://github.com/trevorlauder/cloudflare-doh-worker/blob/2.0.0/examples/).

## Community Block List

Add URLs to `blocklist_sources.yaml` to enable community block lists:

```yaml
urls:
  - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
```

Then download and commit the per-source files:

```shell
uv run python scripts/build_blocklist.py
git add blocklist_sources.yaml blocklist/ src/bloom_meta.py
git commit -m "update blocklist"
git push
```

The bloom filter is rebuilt and bundled as Workers Assets automatically on deploy.

To keep lists updated automatically, you can use the [sample workflow](https://github.com/trevorlauder/cloudflare-doh-worker/blob/2.0.0/workflows/update-blocklist.yml).

See the [full docs](https://github.com/trevorlauder/cloudflare-doh-worker/blob/2.0.0/README.md#community-block-list) for details.
