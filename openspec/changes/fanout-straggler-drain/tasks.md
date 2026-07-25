## 1. Core Implementation

- [x] 1.1 Add `FANOUT_DRAIN_TIMEOUT_MS` config read, defaulting to 10000, to `src/dns_utils.py`
- [x] 1.2 Add optional `ctx` parameter to `send_doh_requests_fanout` and update its docstring
- [x] 1.3 Add `_schedule_fanout_drain` helper that passes a bounded drain task to `ctx.waitUntil` via `js.Promise.resolve`, with failures logged at debug level
- [x] 1.4 Schedule the drain when stragglers exist and the caller provides `ctx`
- [x] 1.5 Pass `ctx` at the fan-out call site in `src/worker.py`

## 2. Tests

- [x] 2.1 Unit test: the fan-out reports stragglers as timed out and calls `ctx.waitUntil` exactly once
- [x] 2.2 Unit test: the fan-out schedules no drain when all providers finish before the deadline
- [x] 2.3 Run the integration suite under real workerd, via local `pywrangler dev` since docker/k3d is unavailable in this container, plus a forced-straggler smoke test of the drain path

## 3. Documentation

- [x] 3.1 Document `FANOUT_DRAIN_TIMEOUT_MS` in the README configuration table

## 4. Verification

- [x] 4.1 Unit suite passes: `uv run pytest tests/test_unit.py -n auto`
- [x] 4.2 Lint and formatting pass: ruff, dprint
- [ ] 4.3 Soak in production past isolate eviction and confirm no `Cannot enter into task` / `NoGilError` wedge recurs
