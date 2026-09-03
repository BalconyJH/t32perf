# T32Perf C99 target event SDK

This SDK provides fixed-cost custom-event encoding for firmware. It allocates no heap memory, waits for no transport, and reads no clock; callers provide the integer tick, context ID, and event ID. The default payload limit is 256 bytes and can be changed consistently across every translation unit with `T32PERF_MAX_PAYLOAD_SIZE`.

## Wire v1

Each record is a 32-byte header followed by its payload. All multi-byte integers are manually encoded little-endian; the implementation never sends a packed C struct.

| Offset | Size | Field | Value |
|---:|---:|---|---|
| 0 | 4 | `magic` | ASCII `T3PF` |
| 4 | 1 | `version` | `1` |
| 5 | 1 | `kind` | See below |
| 6 | 2 | `flags` | v1 writes `0`; bit 0 is reserved for `dropped_since_last` |
| 8 | 2 | `payload_len` | Payload byte count |
| 10 | 2 | `reserved` | Must be `0` |
| 12 | 4 | `seq` | Increments for every actual transport attempt; natural `u32` wrap is allowed |
| 16 | 8 | `timestamp_ticks` | Caller timestamp; no conversion is performed |
| 24 | 4 | `context_id` | Task, ISR, Core, or other caller context |
| 28 | 4 | `event_id` | Caller event-dictionary ID; drop reports use `0` |

| Kind | Value | Payload |
|---|---:|---|
| `instant` | 1 | UTF-8 name bytes; may be empty and contain no NUL |
| `begin` | 2 | UTF-8 name bytes; may be empty and contain no NUL |
| `end` | 3 | UTF-8 name bytes; may be empty and contain no NUL |
| `counter` | 4 | Little-endian `i64` |
| `async_begin` | 5 | Little-endian `u64 correlation_id`, followed by optional UTF-8 name bytes |
| `async_end` | 6 | Little-endian `u64 correlation_id` |
| `dropped` | 7 | Little-endian `u32 dropped_count` |

The SDK does not validate UTF-8. Firmware must pass valid UTF-8 or an empty name, and use `event_id` to connect to the host dictionary.

## Transport and loss semantics

A transport callback returns immediately with `ACCEPTED`, `FULL`, or `ERROR`; the SDK neither retries nor blocks.

- For a normal record returning `FULL`, its `seq` is consumed and `pending_dropped` saturating-increments.
- The next valid event first attempts a kind-7 drop report. Only an accepted report permits the current event to be sent.
- A `FULL` drop report retains the prior count, counts the current unsent event as dropped, and does not consume the current event's `seq` because no transport attempt occurred.
- An `ERROR` drop report retains the count, returns an error, and does not send the current event. `ERROR` is not counted in `pending_dropped`; the platform treats it as a transport fault.
- The drop report uses the timestamp and context ID of the event that triggered this retry.

These rules provide both an explicit drop count and receiver-side sequence-gap detection. A `t32perf_context_t` has exactly one producer.

## Use

```c
#include "t32perf/event.h"
#include "t32perf/transports.h"

static t32perf_ram_slot_t trace_slots[32];
static t32perf_ram_transport_t trace_ring;
static t32perf_context_t trace_context;

void trace_init(void)
{
    (void)t32perf_ram_transport_init(
        &trace_ring, trace_slots, 32u);
    (void)t32perf_context_init(
        &trace_context,
        t32perf_ram_transport_as_transport(&trace_ring),
        0u);
}

void work(uint64_t ticks)
{
    (void)t32perf_begin(&trace_context, ticks, 1u, 42u, "work", 4u);
}
```

Use `t32perf_null_transport()` to validate a call path or deliberately discard records. With `T32PERF_ENABLE=0`, the event API is a header-only `static inline` stub: it does not mutate context or call transport.

## SPSC RAM transport

The RAM transport uses a caller-provided fixed slot array and no dynamic allocation. The producer uses the event API; the consumer uses `peek`/`pop` or `read`. It supports exactly one producer and one consumer, never MPMC or multiple producers/consumers.

GCC/Clang uses `__sync_synchronize()` by default and MSVC uses a compiler barrier. Other embedded toolchains must supply architecture-appropriate definitions:

```c
#define T32PERF_RAM_ACQUIRE_BARRIER() platform_acquire_barrier()
#define T32PERF_RAM_RELEASE_BARRIER() platform_release_barrier()
```

If producer and consumer can preempt one another, the platform must also make reads/writes of both 32-bit positions atomic. Cross-core use must additionally handle cache coherence. Platforms that cannot meet these invariants must provide their own transport callback.

## Build and test

```text
cmake -S sdk/c -B build/sdk-c -G Ninja
cmake --build build/sdk-c
ctest --test-dir build/sdk-c --output-on-failure
```

Tests cover golden wire bytes, every event payload, maximum-length and `size_t`-overflow inputs, drop reports, saturating drop counters, sequence/ring-position wrap, null transport, full/empty RAM rings, and compile-time disable.
