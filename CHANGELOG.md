## [1.1.0] - 2026-03-21

### 🚀 Features

- Add support for large community blocklists ([#100](https://github.com/trevorlauder/cloudflare-doh-worker/pull/100))
- Add config flag for kv blocklist ([#110](https://github.com/trevorlauder/cloudflare-doh-worker/pull/110))
- Add gitattributes ([#114](https://github.com/trevorlauder/cloudflare-doh-worker/pull/114))
- Auto-accept our versions for customized files during merge ([#116](https://github.com/trevorlauder/cloudflare-doh-worker/pull/116))
- Split latency panels by worker blocked/allowed vs upstream ([#120](https://github.com/trevorlauder/cloudflare-doh-worker/pull/120))

### 🐛 Bug Fixes

- Delete all blocklist files and from KV when sources are empty ([#108](https://github.com/trevorlauder/cloudflare-doh-worker/pull/108))
- Only delete *.txt from blocklist/ ([#112](https://github.com/trevorlauder/cloudflare-doh-worker/pull/112))
- Misc fixes ([#117](https://github.com/trevorlauder/cloudflare-doh-worker/pull/117))

### 💼 Other

- Remove workflow from build branch ([#105](https://github.com/trevorlauder/cloudflare-doh-worker/pull/105))

### 📚 Documentation

- Add missing config options to README ([#98](https://github.com/trevorlauder/cloudflare-doh-worker/pull/98))
- Clarify deploy tag usage ([#121](https://github.com/trevorlauder/cloudflare-doh-worker/pull/121))

### ⚡ Performance

- Implement provider response caching ([#99](https://github.com/trevorlauder/cloudflare-doh-worker/pull/99))
- Use single kv key with metadata and remove community wildcard support ([#122](https://github.com/trevorlauder/cloudflare-doh-worker/pull/122))

### 🧪 Testing

- Add new KV_ENABLED flag to test configs ([#113](https://github.com/trevorlauder/cloudflare-doh-worker/pull/113))

### ⚙️ Miscellaneous Tasks

- Add actions permission to release workflow ([#101](https://github.com/trevorlauder/cloudflare-doh-worker/pull/101))
- Update cliff config ([#102](https://github.com/trevorlauder/cloudflare-doh-worker/pull/102))
- Add pre-release support to release workflow ([#106](https://github.com/trevorlauder/cloudflare-doh-worker/pull/106))
- Anchor tag in git-cliff ([#107](https://github.com/trevorlauder/cloudflare-doh-worker/pull/107))
- Cleanup deploy branch readme ([#109](https://github.com/trevorlauder/cloudflare-doh-worker/pull/109))
- Fix build branch copy ([#111](https://github.com/trevorlauder/cloudflare-doh-worker/pull/111))

## [1.0.3] - 2026-03-14

### 💼 Other

- Fix release notes generation ([#95](https://github.com/trevorlauder/cloudflare-doh-worker/pull/95))
- Comment routes so first deploy doesn't throw an error ([#96](https://github.com/trevorlauder/cloudflare-doh-worker/pull/96))

### ⚙️ Miscellaneous Tasks

- Bump for 1.0.3 release ([#97](https://github.com/trevorlauder/cloudflare-doh-worker/pull/97))

## [1.0.2] - 2026-03-14

### 💼 Other

- Add release to CI ([#92](https://github.com/trevorlauder/cloudflare-doh-worker/pull/92))
- Update mise sha ([#93](https://github.com/trevorlauder/cloudflare-doh-worker/pull/93))

### 📚 Documentation

- Update README feature wording ([#86](https://github.com/trevorlauder/cloudflare-doh-worker/pull/86))
- README fixes ([#87](https://github.com/trevorlauder/cloudflare-doh-worker/pull/87))
- Add example config ([#90](https://github.com/trevorlauder/cloudflare-doh-worker/pull/90))

### ⚙️ Miscellaneous Tasks

- Update README for official release ([#84](https://github.com/trevorlauder/cloudflare-doh-worker/pull/84))
- Update README description ([#85](https://github.com/trevorlauder/cloudflare-doh-worker/pull/85))
- Bump for 1.0.2 release ([#94](https://github.com/trevorlauder/cloudflare-doh-worker/pull/94))

## [1.0.1] - 2026-03-13

### ⚙️ Miscellaneous Tasks

- Bump for 1.0.1 release ([#83](https://github.com/trevorlauder/cloudflare-doh-worker/pull/83))

## [1.0.0] - 2026-03-13

### 🚀 Features

- Include provider response code in message sent to grafana ([#49](https://github.com/trevorlauder/cloudflare-doh-worker/pull/49))
- Add retry logic for providers ([#54](https://github.com/trevorlauder/cloudflare-doh-worker/pull/54))
- Add retry logic for connection errors ([#55](https://github.com/trevorlauder/cloudflare-doh-worker/pull/55))
- Make dns-json configurable instead of hardcoded ([#65](https://github.com/trevorlauder/cloudflare-doh-worker/pull/65))
- Add JSON health endpoint ([#76](https://github.com/trevorlauder/cloudflare-doh-worker/pull/76))

### 🐛 Bug Fixes

- Improve error handling, logging, and failed provider tracking ([#46](https://github.com/trevorlauder/cloudflare-doh-worker/pull/46))
- Harden error handling and add POST body size guard ([#48](https://github.com/trevorlauder/cloudflare-doh-worker/pull/48))
- Sanitize get/post request parameters ([#60](https://github.com/trevorlauder/cloudflare-doh-worker/pull/60))
- Harden config endpoint ([#61](https://github.com/trevorlauder/cloudflare-doh-worker/pull/61))
- Sanitize response content-type ([#63](https://github.com/trevorlauder/cloudflare-doh-worker/pull/63))
- Validate config and secrets ([#64](https://github.com/trevorlauder/cloudflare-doh-worker/pull/64))
- Flatten loki json structure and cleanup dashboard ([#68](https://github.com/trevorlauder/cloudflare-doh-worker/pull/68))
- Mitigate Pyodide task re-entrancy under concurrent load ([#73](https://github.com/trevorlauder/cloudflare-doh-worker/pull/73))
- Add safety timeout to prevent hung requests from Pyodide re-entrancy ([#75](https://github.com/trevorlauder/cloudflare-doh-worker/pull/75))

### 🚜 Refactor

- Use workers.fetch and Promise.allSettled for upstream requests ([#74](https://github.com/trevorlauder/cloudflare-doh-worker/pull/74))

### 📚 Documentation

- Update design diagram

### ⚡ Performance

- Improvements to reduce cpu time ([#50](https://github.com/trevorlauder/cloudflare-doh-worker/pull/50))
- Reduce Python/JS FFI boundary crossings ([#52](https://github.com/trevorlauder/cloudflare-doh-worker/pull/52))
- Reduce FFI crossings even more using urllib ([#53](https://github.com/trevorlauder/cloudflare-doh-worker/pull/53))

### 🎨 Styling

- Code cleanup
- Cleanup

### 🧪 Testing

- Consolidate all tests into a single tilt run ([#58](https://github.com/trevorlauder/cloudflare-doh-worker/pull/58))
- Simplify and add eco integration tests and some unit tests ([#66](https://github.com/trevorlauder/cloudflare-doh-worker/pull/66))
- Prevent tilt config-restart resources from firing on first startup ([#77](https://github.com/trevorlauder/cloudflare-doh-worker/pull/77))

### ⚙️ Miscellaneous Tasks

- Update CHANGELOG ([#47](https://github.com/trevorlauder/cloudflare-doh-worker/pull/47))
- Update CHANGELOG ([#51](https://github.com/trevorlauder/cloudflare-doh-worker/pull/51))
- Update CHANGELOG
- Update CHANGELOG ([#56](https://github.com/trevorlauder/cloudflare-doh-worker/pull/56))
- Include dashboard in deploy branch ([#57](https://github.com/trevorlauder/cloudflare-doh-worker/pull/57))
- Only log provider retries in debug ([#59](https://github.com/trevorlauder/cloudflare-doh-worker/pull/59))
- Retry tilt ci jobs on failures ([#62](https://github.com/trevorlauder/cloudflare-doh-worker/pull/62))
- Bump for 1.0.0-rc7 ([#67](https://github.com/trevorlauder/cloudflare-doh-worker/pull/67))
- Bump for 1.0.0-rc8
- Update mise checksums
- Bump for 1.0.0-rc9
- Bump for 1.0.0-rc10
- Bump for 1.0.0-rc11
- Bump for 1.0.0 release ([#78](https://github.com/trevorlauder/cloudflare-doh-worker/pull/78))

## [0.9.0] - 2026-02-18
