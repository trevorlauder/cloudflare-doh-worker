## [unreleased]

### 🚀 Features

- Add support for large community blocklists ([#100](https://github.com/trevorlauder/cloudflare-doh-worker/pull/100))

### 💼 Other

- Remove workflow from build branch ([#105](https://github.com/trevorlauder/cloudflare-doh-worker/pull/105))

### 📚 Documentation

- Add missing config options to README ([#98](https://github.com/trevorlauder/cloudflare-doh-worker/pull/98))

### ⚡ Performance

- Implement provider response caching ([#99](https://github.com/trevorlauder/cloudflare-doh-worker/pull/99))

### ⚙️ Miscellaneous Tasks

- Add actions permission to release workflow ([#101](https://github.com/trevorlauder/cloudflare-doh-worker/pull/101))
- Update cliff config ([#102](https://github.com/trevorlauder/cloudflare-doh-worker/pull/102))

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

### ⚙️ Miscellaneous Tasks

- Bump for 1.0.0 release ([#78](https://github.com/trevorlauder/cloudflare-doh-worker/pull/78))

## [1.0.0-rc11] - 2026-03-13

### 🚀 Features

- Add JSON health endpoint ([#76](https://github.com/trevorlauder/cloudflare-doh-worker/pull/76))

### 🐛 Bug Fixes

- Add safety timeout to prevent hung requests from Pyodide re-entrancy ([#75](https://github.com/trevorlauder/cloudflare-doh-worker/pull/75))

### 📚 Documentation

- Update design diagram

### 🎨 Styling

- Cleanup

### 🧪 Testing

- Prevent tilt config-restart resources from firing on first startup ([#77](https://github.com/trevorlauder/cloudflare-doh-worker/pull/77))

### ⚙️ Miscellaneous Tasks

- Bump for 1.0.0-rc11

## [1.0.0-rc10] - 2026-03-11

### 🚜 Refactor

- Use workers.fetch and Promise.allSettled for upstream requests ([#74](https://github.com/trevorlauder/cloudflare-doh-worker/pull/74))

### ⚙️ Miscellaneous Tasks

- Bump for 1.0.0-rc10

## [1.0.0-rc9] - 2026-03-11

### 🐛 Bug Fixes

- Mitigate Pyodide task re-entrancy under concurrent load ([#73](https://github.com/trevorlauder/cloudflare-doh-worker/pull/73))

### ⚙️ Miscellaneous Tasks

- Update mise checksums
- Bump for 1.0.0-rc9

## [1.0.0-rc8] - 2026-03-06

### 🐛 Bug Fixes

- Flatten loki json structure and cleanup dashboard ([#68](https://github.com/trevorlauder/cloudflare-doh-worker/pull/68))

### 🎨 Styling

- Code cleanup

### ⚙️ Miscellaneous Tasks

- Bump for 1.0.0-rc8

## [1.0.0-rc7] - 2026-03-06

### 🚀 Features

- Make dns-json configurable instead of hardcoded ([#65](https://github.com/trevorlauder/cloudflare-doh-worker/pull/65))

### 🐛 Bug Fixes

- Sanitize get/post request parameters ([#60](https://github.com/trevorlauder/cloudflare-doh-worker/pull/60))
- Harden config endpoint ([#61](https://github.com/trevorlauder/cloudflare-doh-worker/pull/61))
- Sanitize response content-type ([#63](https://github.com/trevorlauder/cloudflare-doh-worker/pull/63))
- Validate config and secrets ([#64](https://github.com/trevorlauder/cloudflare-doh-worker/pull/64))

### 🧪 Testing

- Consolidate all tests into a single tilt run ([#58](https://github.com/trevorlauder/cloudflare-doh-worker/pull/58))
- Simplify and add eco integration tests and some unit tests ([#66](https://github.com/trevorlauder/cloudflare-doh-worker/pull/66))

### ⚙️ Miscellaneous Tasks

- Include dashboard in deploy branch ([#57](https://github.com/trevorlauder/cloudflare-doh-worker/pull/57))
- Only log provider retries in debug ([#59](https://github.com/trevorlauder/cloudflare-doh-worker/pull/59))
- Retry tilt ci jobs on failures ([#62](https://github.com/trevorlauder/cloudflare-doh-worker/pull/62))
- Bump for 1.0.0-rc7 ([#67](https://github.com/trevorlauder/cloudflare-doh-worker/pull/67))

## [1.0.0-rc6] - 2026-03-05

### 🚀 Features

- Add retry logic for providers ([#54](https://github.com/trevorlauder/cloudflare-doh-worker/pull/54))
- Add retry logic for connection errors ([#55](https://github.com/trevorlauder/cloudflare-doh-worker/pull/55))

### ⚡ Performance

- Reduce FFI crossings even more using urllib ([#53](https://github.com/trevorlauder/cloudflare-doh-worker/pull/53))

### ⚙️ Miscellaneous Tasks

- Update CHANGELOG ([#56](https://github.com/trevorlauder/cloudflare-doh-worker/pull/56))

## [1.0.0-rc5] - 2026-03-04

### 🚀 Features

- Include provider response code in message sent to grafana ([#49](https://github.com/trevorlauder/cloudflare-doh-worker/pull/49))

### 🐛 Bug Fixes

- Harden error handling and add POST body size guard ([#48](https://github.com/trevorlauder/cloudflare-doh-worker/pull/48))

### ⚡ Performance

- Improvements to reduce cpu time ([#50](https://github.com/trevorlauder/cloudflare-doh-worker/pull/50))
- Reduce Python/JS FFI boundary crossings ([#52](https://github.com/trevorlauder/cloudflare-doh-worker/pull/52))

### ⚙️ Miscellaneous Tasks

- Update CHANGELOG ([#51](https://github.com/trevorlauder/cloudflare-doh-worker/pull/51))
- Update CHANGELOG

## [1.0.0-rc4] - 2026-03-04

### 🐛 Bug Fixes

- Improve error handling, logging, and failed provider tracking ([#46](https://github.com/trevorlauder/cloudflare-doh-worker/pull/46))

### ⚙️ Miscellaneous Tasks

- Update CHANGELOG ([#47](https://github.com/trevorlauder/cloudflare-doh-worker/pull/47))

## [0.9.0] - 2026-02-18
