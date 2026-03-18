# cloudflare-doh-worker

This is a deploy branch. For documentation, see the README for this release:
https://github.com/trevorlauder/cloudflare-doh-worker/blob/1.1.0-rc3/README.md

Grafana dashboard for this release:
https://github.com/trevorlauder/cloudflare-doh-worker/blob/1.1.0-rc3/dashboard/grafana.json

Additional example configs:
https://github.com/trevorlauder/cloudflare-doh-worker/blob/1.1.0-rc3/examples/

## Community Block List

Add URLs to `blocklist_sources.yaml` to enable community block lists:

```yaml
urls:
  - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
```

Then download and commit the per-source files:

```shell
uv run python scripts/build_blocklist.py
git add blocklist/
git commit -m "update blocklist"
git push
```

The bloom filter is rebuilt and uploaded to KV automatically on deploy.

To keep lists updated automatically, you can use the sample workflow here:
https://github.com/trevorlauder/cloudflare-doh-worker/blob/1.1.0-rc3/workflows/update-blocklist.yml

See the full docs for details:
https://github.com/trevorlauder/cloudflare-doh-worker/blob/1.1.0-rc3/README.md#community-block-list
