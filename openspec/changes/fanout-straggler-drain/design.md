## Context

`send_doh_requests_fanout` runs one fetch and retry coroutine per provider and bounds the whole fan-out with `asyncio.wait(timeout=...)`. `asyncio.wait` doesn't cancel tasks that miss the deadline, so straggler tasks kept running after the handler returned. workerd tears down pending I/O when the request context ends, and a Python task that's actively awaiting mid-loop during teardown can leave the Pyodide event loop with a stuck current task, per cloudflare/workerd#6624. An earlier design used a shared `AbortSignal.timeout` per fan-out. This branch removed it because AbortSignal rejections delivered at arbitrary moments are a suspected corruption trigger.

## Goals / Non-Goals

**Goals:**

- No fan-out task is actively running when its request context tears down.
- Client-visible latency and results stay the same.
- Worst-case context lifetime stays well under the 30 second `waitUntil` cap.

**Non-Goals:**

- Fixing the underlying workerd or Pyodide bug. This is a hardening measure in app code.
- Bounding individual upstream fetches. Cloudflare documents no time limit on subrequests and this design doesn't add one.

## Decisions

- **Drain stragglers under `ctx.waitUntil` instead of abandoning them.** The drain keeps the request context alive so straggler continuations fire into a live context. This design considered and rejected three alternatives:
  - Abandoning tasks, the previous behavior that causes the wedge.
  - Cancelling tasks at the deadline, which injects `CancelledError` into tasks awaiting Pyodide futures, another suspect delivery path.
  - Aborting fetches from inside the drain, which reintroduces the same AbortSignal delivery this branch already ruled out.
- **No cancellation and no AbortSignal anywhere in the fan-out.** Tasks settle naturally. This is the most conservative option given that upstream hasn't root-caused the corruption trigger yet.
- **Bound the drain with `FANOUT_DRAIN_TIMEOUT_MS`, default 10000.** Stragglers have already been in flight for `safety_timeout_ms`, about 7 seconds, when the drain starts. Ten more seconds covers one full retry attempt at `TIMEOUT_MS` with margin, and keeps worst-case context lifetime near 17 seconds. Anything still pending at the cap tears down at context close with no Python task actively awaiting it, the same teardown path the platform cap would take.
- **Wrap the drain task in `js.Promise.resolve` before passing to `waitUntil`.** A Pyodide future proxy is thenable and `Promise.resolve` assimilates it into a native promise, matching the native-promise pattern used by the cache and Loki `waitUntil` calls.
- **`ctx` is optional and defaults to `None`.** Unit tests and any caller without a context get the previous behavior.

## Risks / Trade-offs

- [Straggler still pending at the drain cap] → Its context teardown happens with no attached Python task, landing on an already settled or unobserved future. Same exposure as the platform 30 second cap, just earlier.
- [Drain keeps the isolate context alive longer] → Costs no CPU billing, since awaiting a fetch burns no CPU, and is invisible to clients.
- [`Promise.resolve` assimilation of a Pyodide task proxy fails in some runtime version] → A try/except wraps the call, and failure only logs at debug level, restoring the previous abandon behavior rather than breaking responses.
