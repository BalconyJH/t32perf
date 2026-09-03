#include "t32perf/event.h"

#if T32PERF_ENABLE

#include <string.h>

static void t32perf_write_u16_le(uint8_t *output, uint16_t value)
{
    output[0] = (uint8_t)(value & UINT16_C(0x00ff));
    output[1] = (uint8_t)(value >> 8);
}

static void t32perf_write_u32_le(uint8_t *output, uint32_t value)
{
    output[0] = (uint8_t)(value & UINT32_C(0x000000ff));
    output[1] = (uint8_t)((value >> 8) & UINT32_C(0x000000ff));
    output[2] = (uint8_t)((value >> 16) & UINT32_C(0x000000ff));
    output[3] = (uint8_t)(value >> 24);
}

static void t32perf_write_u64_le(uint8_t *output, uint64_t value)
{
    output[0] = (uint8_t)(value & UINT64_C(0x00000000000000ff));
    output[1] = (uint8_t)((value >> 8) & UINT64_C(0x00000000000000ff));
    output[2] = (uint8_t)((value >> 16) & UINT64_C(0x00000000000000ff));
    output[3] = (uint8_t)((value >> 24) & UINT64_C(0x00000000000000ff));
    output[4] = (uint8_t)((value >> 32) & UINT64_C(0x00000000000000ff));
    output[5] = (uint8_t)((value >> 40) & UINT64_C(0x00000000000000ff));
    output[6] = (uint8_t)((value >> 48) & UINT64_C(0x00000000000000ff));
    output[7] = (uint8_t)(value >> 56);
}

static t32perf_emit_result_t t32perf_validate_context(
    const t32perf_context_t *context)
{
    if ((context == NULL) || (context->transport.write == NULL)) {
        return T32PERF_EMIT_INVALID_ARGUMENT;
    }
    return T32PERF_EMIT_ACCEPTED;
}

static t32perf_emit_result_t t32perf_validate_bytes(
    const void *bytes,
    size_t byte_count,
    size_t maximum)
{
    if (byte_count > maximum) {
        return T32PERF_EMIT_PAYLOAD_TOO_LARGE;
    }
    if ((byte_count != 0u) && (bytes == NULL)) {
        return T32PERF_EMIT_INVALID_ARGUMENT;
    }
    return T32PERF_EMIT_ACCEPTED;
}

static void t32perf_increment_dropped(t32perf_context_t *context)
{
    if (context->pending_dropped != UINT32_MAX) {
        context->pending_dropped += UINT32_C(1);
    }
}

static t32perf_emit_result_t t32perf_write_record(
    t32perf_context_t *context,
    t32perf_event_kind_t kind,
    uint16_t flags,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    const uint8_t *payload,
    size_t payload_len,
    int count_full_as_dropped)
{
    uint8_t record[T32PERF_WIRE_MAX_RECORD_SIZE];
    uint32_t sequence;
    t32perf_transport_result_t transport_result;

    sequence = context->next_sequence;
    context->next_sequence += UINT32_C(1);

    record[0] = (uint8_t)'T';
    record[1] = (uint8_t)'3';
    record[2] = (uint8_t)'P';
    record[3] = (uint8_t)'F';
    record[T32PERF_WIRE_OFFSET_VERSION] = (uint8_t)T32PERF_WIRE_VERSION;
    record[T32PERF_WIRE_OFFSET_KIND] = (uint8_t)kind;
    t32perf_write_u16_le(&record[T32PERF_WIRE_OFFSET_FLAGS], flags);
    t32perf_write_u16_le(
        &record[T32PERF_WIRE_OFFSET_PAYLOAD_LEN], (uint16_t)payload_len);
    t32perf_write_u16_le(&record[T32PERF_WIRE_OFFSET_RESERVED], UINT16_C(0));
    t32perf_write_u32_le(&record[T32PERF_WIRE_OFFSET_SEQUENCE], sequence);
    t32perf_write_u64_le(&record[T32PERF_WIRE_OFFSET_TIMESTAMP], timestamp_ticks);
    t32perf_write_u32_le(&record[T32PERF_WIRE_OFFSET_CONTEXT_ID], context_id);
    t32perf_write_u32_le(&record[T32PERF_WIRE_OFFSET_EVENT_ID], event_id);

    if (payload_len != 0u) {
        memcpy(&record[T32PERF_WIRE_HEADER_SIZE], payload, payload_len);
    }

    transport_result = context->transport.write(
        context->transport.user_data,
        record,
        T32PERF_WIRE_HEADER_SIZE + payload_len);
    if (transport_result == T32PERF_TRANSPORT_ACCEPTED) {
        return T32PERF_EMIT_ACCEPTED;
    }
    if (transport_result == T32PERF_TRANSPORT_FULL) {
        if (count_full_as_dropped != 0) {
            t32perf_increment_dropped(context);
        }
        return T32PERF_EMIT_DROPPED;
    }
    return T32PERF_EMIT_TRANSPORT_ERROR;
}

static t32perf_emit_result_t t32perf_report_dropped(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id)
{
    uint8_t payload[4];
    uint32_t count;
    t32perf_emit_result_t result;

    if (context->pending_dropped == UINT32_C(0)) {
        return T32PERF_EMIT_ACCEPTED;
    }

    count = context->pending_dropped;
    t32perf_write_u32_le(payload, count);
    result = t32perf_write_record(
        context,
        T32PERF_EVENT_DROPPED,
        UINT16_C(0),
        timestamp_ticks,
        context_id,
        UINT32_C(0),
        payload,
        sizeof(payload),
        0);
    if (result == T32PERF_EMIT_ACCEPTED) {
        context->pending_dropped = UINT32_C(0);
    }
    return result;
}

static t32perf_emit_result_t t32perf_emit(
    t32perf_context_t *context,
    t32perf_event_kind_t kind,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    const uint8_t *payload,
    size_t payload_len)
{
    t32perf_emit_result_t result;

    result = t32perf_report_dropped(context, timestamp_ticks, context_id);
    if (result == T32PERF_EMIT_DROPPED) {
        t32perf_increment_dropped(context);
        return result;
    }
    if (result != T32PERF_EMIT_ACCEPTED) {
        return result;
    }

    return t32perf_write_record(
        context,
        kind,
        UINT16_C(0),
        timestamp_ticks,
        context_id,
        event_id,
        payload,
        payload_len,
        1);
}

static t32perf_emit_result_t t32perf_named_event(
    t32perf_context_t *context,
    t32perf_event_kind_t kind,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    const char *name,
    size_t name_len)
{
    t32perf_emit_result_t result;

    result = t32perf_validate_context(context);
    if (result != T32PERF_EMIT_ACCEPTED) {
        return result;
    }
    result = t32perf_validate_bytes(name, name_len, T32PERF_MAX_PAYLOAD_SIZE);
    if (result != T32PERF_EMIT_ACCEPTED) {
        return result;
    }
    return t32perf_emit(
        context,
        kind,
        timestamp_ticks,
        context_id,
        event_id,
        (const uint8_t *)name,
        name_len);
}

t32perf_emit_result_t t32perf_context_init(
    t32perf_context_t *context,
    t32perf_transport_t transport,
    uint32_t initial_sequence)
{
    if ((context == NULL) || (transport.write == NULL)) {
        return T32PERF_EMIT_INVALID_ARGUMENT;
    }
    context->transport = transport;
    context->next_sequence = initial_sequence;
    context->pending_dropped = UINT32_C(0);
    return T32PERF_EMIT_ACCEPTED;
}

uint32_t t32perf_context_next_sequence(const t32perf_context_t *context)
{
    if (context == NULL) {
        return UINT32_C(0);
    }
    return context->next_sequence;
}

uint32_t t32perf_context_pending_dropped(const t32perf_context_t *context)
{
    if (context == NULL) {
        return UINT32_C(0);
    }
    return context->pending_dropped;
}

t32perf_emit_result_t t32perf_instant(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    const char *name,
    size_t name_len)
{
    return t32perf_named_event(
        context,
        T32PERF_EVENT_INSTANT,
        timestamp_ticks,
        context_id,
        event_id,
        name,
        name_len);
}

t32perf_emit_result_t t32perf_begin(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    const char *name,
    size_t name_len)
{
    return t32perf_named_event(
        context,
        T32PERF_EVENT_BEGIN,
        timestamp_ticks,
        context_id,
        event_id,
        name,
        name_len);
}

t32perf_emit_result_t t32perf_end(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    const char *name,
    size_t name_len)
{
    return t32perf_named_event(
        context,
        T32PERF_EVENT_END,
        timestamp_ticks,
        context_id,
        event_id,
        name,
        name_len);
}

t32perf_emit_result_t t32perf_counter(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    int64_t value)
{
    uint8_t payload[8];
    t32perf_emit_result_t result;

    result = t32perf_validate_context(context);
    if (result != T32PERF_EMIT_ACCEPTED) {
        return result;
    }
    t32perf_write_u64_le(payload, (uint64_t)value);
    return t32perf_emit(
        context,
        T32PERF_EVENT_COUNTER,
        timestamp_ticks,
        context_id,
        event_id,
        payload,
        sizeof(payload));
}

t32perf_emit_result_t t32perf_async_begin(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    uint64_t correlation_id,
    const char *name,
    size_t name_len)
{
    uint8_t payload[T32PERF_MAX_PAYLOAD_SIZE];
    t32perf_emit_result_t result;

    result = t32perf_validate_context(context);
    if (result != T32PERF_EMIT_ACCEPTED) {
        return result;
    }
    result = t32perf_validate_bytes(
        name, name_len, T32PERF_MAX_PAYLOAD_SIZE - 8u);
    if (result != T32PERF_EMIT_ACCEPTED) {
        return result;
    }

    t32perf_write_u64_le(payload, correlation_id);
#if T32PERF_MAX_PAYLOAD_SIZE > 8u
    if (name_len != 0u) {
        memcpy(&payload[8], name, name_len);
    }
#endif
    return t32perf_emit(
        context,
        T32PERF_EVENT_ASYNC_BEGIN,
        timestamp_ticks,
        context_id,
        event_id,
        payload,
        8u + name_len);
}

t32perf_emit_result_t t32perf_async_end(
    t32perf_context_t *context,
    uint64_t timestamp_ticks,
    uint32_t context_id,
    uint32_t event_id,
    uint64_t correlation_id)
{
    uint8_t payload[8];
    t32perf_emit_result_t result;

    result = t32perf_validate_context(context);
    if (result != T32PERF_EMIT_ACCEPTED) {
        return result;
    }
    t32perf_write_u64_le(payload, correlation_id);
    return t32perf_emit(
        context,
        T32PERF_EVENT_ASYNC_END,
        timestamp_ticks,
        context_id,
        event_id,
        payload,
        sizeof(payload));
}

#endif
