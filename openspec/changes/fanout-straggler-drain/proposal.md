## Why

Provider fetch tasks that miss the fan-out deadline are currently abandoned once the fan-out returns a response. Their fetch continuations then fire after the request context tears down, which can leave the Pyodide event loop with a stuck current task and wedge the isolate until Cloudflare kills it, per cloudflare/workerd#6624. Affected isolates fail every subsequent request with `RuntimeError: Cannot enter into task` followed by `exceededCpu` and `NoGilError`.

## What Changes

- `send_doh_requests_fanout` accepts the Worker execution context and schedules a background drain via `ctx.waitUntil` when providers are still in flight at the deadline.
- Straggler tasks settle naturally in a live request context. No cancellation and no AbortSignal, since delivering it mid-task is a suspected corruption trigger.
- A new `FANOUT_DRAIN_TIMEOUT_MS` config option, defaulting to `10000`, bounds the drain, keeping worst-case context lifetime well under the platform's 30 second `waitUntil` cap.
- Client-facing behavior stays the same: the fan-out still returns at `safety_timeout_ms` and stragglers are still reported as timed out.

## Capabilities

### New Capabilities

- `upstream-fanout`: Fan-out of DNS queries to upstream DoH providers, including the overall deadline, timed-out provider reporting, and background draining of straggler requests.

### Modified Capabilities

<!-- None. No existing specs in openspec/specs/. -->

## Impact

- `src/dns_utils.py`: new `ctx` parameter, `_schedule_fanout_drain` helper, `_FANOUT_DRAIN_TIMEOUT_MS` config read.
- `src/worker.py`: passes `ctx` at the fan-out call site.
- `README.md`: documents `FANOUT_DRAIN_TIMEOUT_MS`.
- `tests/test_unit.py`: covers drain scheduling and the no-straggler case.
- No breaking changes. The `ctx` parameter defaults to `None`, and behavior without it matches the previous release.
