#ifndef T32PERF_EVENT_H
#define T32PERF_EVENT_H

#include <stddef.h>
#include <stdint.h>

#ifndef T32PERF_ENABLE
#define T32PERF_ENABLE 1
#endif

#if (T32PERF_ENABLE != 0) && (T32PERF_ENABLE != 1)
#error "T32PERF_ENABLE must be 0 or 1"
#endif

#ifndef T32PERF_MAX_PAYLOAD_SIZE
#define T32PERF_MAX_PAYLOAD_SIZE 256u
#endif

#if T32PERF_MAX_PAYLOAD_SIZE < 8u
#error "T32PERF_MAX_PAYLOAD_SIZE must be at least 8"
#endif

#if T32PERF_MAX_PAYLOAD_SIZE > 65535u
#error "T32PERF_MAX_PAYLOAD_SIZE must fit in the wire payload_len field"
#endif

#define T32PERF_WIRE_MAGIC_SIZE 4u
#define T32PERF_WIRE_HEADER_SIZE 32u
#define T32PERF_WIRE_VERSION 1u
#define T32PERF_WIRE_MAX_RECORD_SIZE \
    (T32PERF_WIRE_HEADER_SIZE + T32PERF_MAX_PAYLOAD_SIZE)

#define T32PERF_WIRE_OFFSET_MAGIC 0u
#define T32PERF_WIRE_OFFSET_VERSION 4u
#define T32PERF_WIRE_OFFSET_KIND 5u
#define T32PERF_WIRE_OFFSET_FLAGS 6u
#define T32PERF_WIRE_OFFSET_PAYLOAD_LEN 8u
#define T32PERF_WIRE_OFFSET_RESERVED 10u
#define T32PERF_WIRE_OFFSET_SEQUENCE 12u
#define T32PERF_WIRE_OFFSET_TIMESTAMP 16u
#define T32PERF_WIRE_OFFSET_CONTEXT_ID 24u
#define T32PERF_WIRE_OFFSET_EVENT_ID 28u

#define T32PERF_WIRE_FLAG_DROPPED_SINCE_LAST UINT16_C(0x0001)

#ifdef __cplusplus
extern "C" {
#endif

typedef enum t32perf_event_kind {
    T32PERF_EVENT_INSTANT = 1,
    T32PERF_EVENT_BEGIN = 2,
    T32PERF_EVENT_END = 3,
    T32PERF_EVENT_COUNTER = 4,
    T32PERF_EVENT_ASYNC_BEGIN = 5,
    T32PERF_EVENT_ASYNC_END = 6,
    T32PERF_EVENT_DROPPED = 7
} t32perf_event_kind_t;

typedef enum t32perf_transport_result {
    T32PERF_TRANSPORT_ACCEPTED = 0,
    T32PERF_TRANSPORT_FULL = 1,
    T32PERF_TRANSPORT_ERROR = 2
} t32perf_transport_result_t;

typedef t32perf_transport_result_t (*t32perf_transport_write_fn)(
    void *user_data,
    const uint8_t *record,
    size_t record_len);

typedef struct t32perf_transport {
    t32perf_transport_write_fn write;
    void *user_data;
} t32perf_transport_t;

typedef struct t32perf_context {
    t32perf_transport_t transport;
    uint32_t next_sequence;
    uint32_t pending_dropped;
} t32perf_context_t;

typedef enum t32perf_emit_result {
    T32PERF_EMIT_ACCEPTED = 0,
    T32PERF_EMIT_DROPPED = 1,
    T32PERF_EMIT_TRANSPORT_ERROR = 2,
    T32PERF_EMIT_INVALID_ARGUMENT = 3,
    T32PERF_EMIT_PAYLOAD_TOO_LARGE = 4,
    T32PERF_EMIT_DISABLED = 5
} t32perf_emit_result_t;

#if T32PERF_ENABLE

t32perf_emit_result_t t32perf_context_init(
    t32perf_context_t *context,
    t32perf_transport_t transport,
    uint32_t initial_sequence);

uint32_t t32perf_context_next_sequence(const t32perf_context_t *context);
uint32_t t32perf_context_pending_dropped(const t32perf_context_t *context);

t32perf_emit_result_t t32perf_instant(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    const char *name,
    size_t name_len);

t32perf_emit_result_t t32perf_begin(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    const char *name,
    size_t name_len);

t32perf_emit_result_t t32perf_end(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    const char *name,
    size_t name_len);

t32perf_emit_result_t t32perf_counter(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    int64_t value);

t32perf_emit_result_t t32perf_async_begin(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    uint64_t correlation_id,
    const char *name,
    size_t name_len);

t32perf_emit_result_t t32perf_async_end(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    uint64_t correlation_id);

#else

static inline t32perf_emit_result_t t32perf_context_init(
    t32perf_context_t *context,
    t32perf_transport_t transport,
    uint32_t initial_sequence)
{
    (void)context;
    (void)transport;
    (void)initial_sequence;
    return T32PERF_EMIT_DISABLED;
}

static inline uint32_t t32perf_context_next_sequence(
    const t32perf_context_t *context)
{
    (void)context;
    return UINT32_C(0);
}

static inline uint32_t t32perf_context_pending_dropped(
    const t32perf_context_t *context)
{
    (void)context;
    return UINT32_C(0);
}

static inline t32perf_emit_result_t t32perf_instant(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    const char *name,
    size_t name_len)
{
    (void)context;
    (void)timestamp_ticks;
    (void)context_id;
    (void)event_id;
    (void)name;
    (void)name_len;
    return T32PERF_EMIT_DISABLED;
}

static inline t32perf_emit_result_t t32perf_begin(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    const char *name,
    size_t name_len)
{
    return t32perf_instant(
        context, timestamp_ticks, context_id, event_id, name, name_len);
}

static inline t32perf_emit_result_t t32perf_end(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    const char *name,
    size_t name_len)
{
    return t32perf_instant(
        context, timestamp_ticks, context_id, event_id, name, name_len);
}

static inline t32perf_emit_result_t t32perf_counter(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    int64_t value)
{
    (void)context;
    (void)timestamp_ticks;
    (void)context_id;
    (void)event_id;
    (void)value;
    return T32PERF_EMIT_DISABLED;
}

static inline t32perf_emit_result_t t32perf_async_begin(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    uint64_t correlation_id,
    const char *name,
    size_t name_len)
{
    (void)context;
    (void)timestamp_ticks;
    (void)context_id;
    (void)event_id;
    (void)correlation_id;
    (void)name;
    (void)name_len;
    return T32PERF_EMIT_DISABLED;
}

static inline t32perf_emit_result_t t32perf_async_end(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    uint64_t correlation_id)
{
    (void)context;
    (void)timestamp_ticks;
    (void)context_id;
    (void)event_id;
    (void)correlation_id;
    return T32PERF_EMIT_DISABLED;
}

#endif

#ifdef __cplusplus
}
#endif

#endif
