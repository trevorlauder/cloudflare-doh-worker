## ADDED Requirements

### Requirement: Fan-out returns by the overall deadline

The fan-out SHALL return one result per queried provider within the overall deadline: `safety_timeout_ms` when positive, otherwise `TIMEOUT_MS`. The fan-out SHALL report providers still in flight at the deadline as failed with `timed_out` set and status 504.

#### Scenario: Provider misses the deadline

- **WHEN** a provider request hasn't completed by the overall deadline
- **THEN** the fan-out returns without waiting further
- **THEN** that provider's result has `failed` and `timed_out` set

#### Scenario: All providers finish in time

- **WHEN** every provider request completes before the overall deadline
- **THEN** each result reflects the provider's actual response

### Requirement: Fan-out drains straggler requests in a live request context

When providers are still in flight at the deadline and an execution context is available, the fan-out SHALL schedule a background drain via `ctx.waitUntil` so straggler tasks settle before the request context tears down. The drain SHALL NOT cancel tasks or stop fetches.

#### Scenario: Stragglers exist and the caller provides context

- **WHEN** the fan-out returns with at least one provider still in flight and the caller provides `ctx`
- **THEN** the fan-out passes a drain awaiting the straggler tasks to `ctx.waitUntil` exactly once

#### Scenario: No stragglers

- **WHEN** every provider finishes before the deadline
- **THEN** the fan-out schedules no drain

#### Scenario: No execution context

- **WHEN** stragglers exist but `ctx` is `None`
- **THEN** the fan-out returns normally without scheduling a drain

### Requirement: Configuration bounds the drain duration

The drain SHALL wait at most `FANOUT_DRAIN_TIMEOUT_MS` milliseconds, default 10000, for straggler tasks to settle. Failure to schedule the drain SHALL NOT affect the response.

#### Scenario: Straggler never settles

- **WHEN** a straggler task is still pending after `FANOUT_DRAIN_TIMEOUT_MS`
- **THEN** the drain completes and releases the request context

#### Scenario: Drain scheduling fails

- **WHEN** scheduling the drain raises an exception
- **THEN** the fan-out logs the failure at debug level and returns its results unchanged
