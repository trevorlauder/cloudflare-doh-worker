# Changelog

## [1.0.1] - 2026-03-13

### Dependencies

- **deps**: Update dependency workers-runtime-sdk to v1 ([#82](https://github.com/trevorlauder/cloudflare-doh-worker/pull/82))
- **deps**: Update dependency ruff to v0.15.6 ([#80](https://github.com/trevorlauder/cloudflare-doh-worker/pull/80))
- **deps**: Update dependency jdx/mise to v2026.3.8 ([#79](https://github.com/trevorlauder/cloudflare-doh-worker/pull/79))
- **deps**: Update dependency workers-py to ~=1.9.0 ([#81](https://github.com/trevorlauder/cloudflare-doh-worker/pull/81))

## [1.0.0] - 2026-03-13

### Bug Fixes

- Improve error handling, logging, and failed provider tracking ([#46](https://github.com/trevorlauder/cloudflare-doh-worker/pull/46))
- Harden error handling and add POST body size guard ([#48](https://github.com/trevorlauder/cloudflare-doh-worker/pull/48))
- Sanitize get/post request parameters ([#60](https://github.com/trevorlauder/cloudflare-doh-worker/pull/60))
- Harden config endpoint ([#61](https://github.com/trevorlauder/cloudflare-doh-worker/pull/61))
- Sanitize response content-type ([#63](https://github.com/trevorlauder/cloudflare-doh-worker/pull/63))
- Validate config and secrets ([#64](https://github.com/trevorlauder/cloudflare-doh-worker/pull/64))
- Flatten loki json structure and cleanup dashboard ([#68](https://github.com/trevorlauder/cloudflare-doh-worker/pull/68))
- Mitigate Pyodide task re-entrancy under concurrent load ([#73](https://github.com/trevorlauder/cloudflare-doh-worker/pull/73))
- Add safety timeout to prevent hung requests from Pyodide re-entrancy ([#75](https://github.com/trevorlauder/cloudflare-doh-worker/pull/75))

### Changes

- Refactor in python ([#33](https://github.com/trevorlauder/cloudflare-doh-worker/pull/33))
- Improved exception handling and cache logic ([#34](https://github.com/trevorlauder/cloudflare-doh-worker/pull/34))
- Update jdx/mise-action action to v3.6.2 ([#36](https://github.com/trevorlauder/cloudflare-doh-worker/pull/36))
- Update mise ([#38](https://github.com/trevorlauder/cloudflare-doh-worker/pull/38))
- Update dependency jdx/mise to v2026.3.0 ([#37](https://github.com/trevorlauder/cloudflare-doh-worker/pull/37))
- Migrate Renovate config ([#39](https://github.com/trevorlauder/cloudflare-doh-worker/pull/39))
- Update python version in CONTRIBUTING.md ([#40](https://github.com/trevorlauder/cloudflare-doh-worker/pull/40))
- Add release notes link to Updating section in README ([#41](https://github.com/trevorlauder/cloudflare-doh-worker/pull/41))
- Remove hardcoded grafana datasource ([#42](https://github.com/trevorlauder/cloudflare-doh-worker/pull/42))
- Rename secret template syntax to avoid confusion with variables ([#43](https://github.com/trevorlauder/cloudflare-doh-worker/pull/43))
- 1.0.0-rc3 prep ([#44](https://github.com/trevorlauder/cloudflare-doh-worker/pull/44))
- Move js & pyodide.ffi imports inside functions ([#45](https://github.com/trevorlauder/cloudflare-doh-worker/pull/45))

### Dependencies

- **deps**: Update mise ([#71](https://github.com/trevorlauder/cloudflare-doh-worker/pull/71))
- **deps**: Update jdx/mise-action action to v3.6.3 ([#70](https://github.com/trevorlauder/cloudflare-doh-worker/pull/70))
- **deps**: Update dependency jdx/mise to v2026.3.4 ([#69](https://github.com/trevorlauder/cloudflare-doh-worker/pull/69))
- **deps**: Update dependency jdx/mise to v2026.3.5 ([#72](https://github.com/trevorlauder/cloudflare-doh-worker/pull/72))

### Documentation

- Update design diagram

### Features

- Include provider response code in message sent to grafana ([#49](https://github.com/trevorlauder/cloudflare-doh-worker/pull/49))
- Add retry logic for providers ([#54](https://github.com/trevorlauder/cloudflare-doh-worker/pull/54))
- Add retry logic for connection errors ([#55](https://github.com/trevorlauder/cloudflare-doh-worker/pull/55))
- Make dns-json configurable instead of hardcoded ([#65](https://github.com/trevorlauder/cloudflare-doh-worker/pull/65))
- Add JSON health endpoint ([#76](https://github.com/trevorlauder/cloudflare-doh-worker/pull/76))

### Performance

- Improvements to reduce cpu time ([#50](https://github.com/trevorlauder/cloudflare-doh-worker/pull/50))
- Reduce Python/JS FFI boundary crossings ([#52](https://github.com/trevorlauder/cloudflare-doh-worker/pull/52))
- Reduce FFI crossings even more using urllib ([#53](https://github.com/trevorlauder/cloudflare-doh-worker/pull/53))

### Refactoring

- Use workers.fetch and Promise.allSettled for upstream requests ([#74](https://github.com/trevorlauder/cloudflare-doh-worker/pull/74))

### Style

- Code cleanup
- Cleanup

### Testing

- Consolidate all tests into a single tilt run ([#58](https://github.com/trevorlauder/cloudflare-doh-worker/pull/58))
- Simplify and add eco integration tests and some unit tests ([#66](https://github.com/trevorlauder/cloudflare-doh-worker/pull/66))
- Prevent tilt config-restart resources from firing on first startup ([#77](https://github.com/trevorlauder/cloudflare-doh-worker/pull/77))

## [0.9.0] - 2026-02-18

### Changes

- Initial commit
- Add NGINX support for docker compose ([#1](https://github.com/trevorlauder/cloudflare-doh-worker/pull/1))
- Add NGINX support for docker compose ([#2](https://github.com/trevorlauder/cloudflare-doh-worker/pull/2))
- Cleanup
- Dependency updates
- Dependency updates
- Upgrade packages and migrate to ES Modules ([#5](https://github.com/trevorlauder/cloudflare-doh-worker/pull/5))
- Remove version in docker-compose.yaml
- Fix link in README
- Update README
- Add config and wrangler.toml ([#6](https://github.com/trevorlauder/cloudflare-doh-worker/pull/6))
- Support cloudflare deploy button ([#7](https://github.com/trevorlauder/cloudflare-doh-worker/pull/7))
- Fix link in README ([#8](https://github.com/trevorlauder/cloudflare-doh-worker/pull/8))
- Add CI ([#11](https://github.com/trevorlauder/cloudflare-doh-worker/pull/11))
- Add Dependabot configuration for GitHub Actions and npm ([#10](https://github.com/trevorlauder/cloudflare-doh-worker/pull/10))
- Fix formatting issues in dependabot.yml
- Update CI ([#27](https://github.com/trevorlauder/cloudflare-doh-worker/pull/27))

### Dependencies

- Bump actions/checkout from 5 to 6 ([#17](https://github.com/trevorlauder/cloudflare-doh-worker/pull/17))
- Bump the npm-dependencies group with 5 updates ([#18](https://github.com/trevorlauder/cloudflare-doh-worker/pull/18))
- Bump actions/cache from 4 to 5 ([#21](https://github.com/trevorlauder/cloudflare-doh-worker/pull/21))
- Bump the npm-dependencies group across 1 directory with 4 updates ([#20](https://github.com/trevorlauder/cloudflare-doh-worker/pull/20))
- Bump workerd from 1.20251221.0 to 1.20251229.0 in the npm-dependencies group ([#22](https://github.com/trevorlauder/cloudflare-doh-worker/pull/22))
- Bump the npm-dependencies group across 1 directory with 3 updates ([#24](https://github.com/trevorlauder/cloudflare-doh-worker/pull/24))
- Bump the npm-dependencies group across 1 directory with 4 updates ([#26](https://github.com/trevorlauder/cloudflare-doh-worker/pull/26))
- Bump the npm-dependencies group with 2 updates ([#28](https://github.com/trevorlauder/cloudflare-doh-worker/pull/28))
- Bump the npm-dependencies group with 2 updates ([#30](https://github.com/trevorlauder/cloudflare-doh-worker/pull/30))
- Bump the npm-dependencies group with 2 updates ([#31](https://github.com/trevorlauder/cloudflare-doh-worker/pull/31))
