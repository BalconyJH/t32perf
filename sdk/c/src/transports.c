#include "t32perf/transports.h"

#include <string.h>

#ifndef T32PERF_RAM_ACQUIRE_BARRIER
#if defined(__GNUC__) || defined(__clang__)
#define T32PERF_RAM_ACQUIRE_BARRIER() __sync_synchronize()
#elif defined(_MSC_VER)
#include <intrin.h>
#define T32PERF_RAM_ACQUIRE_BARRIER() _ReadWriteBarrier()
#else
#define T32PERF_RAM_ACQUIRE_BARRIER() ((void)0)
#endif
#endif

#ifndef T32PERF_RAM_RELEASE_BARRIER
#if defined(__GNUC__) || defined(__clang__)
#define T32PERF_RAM_RELEASE_BARRIER() __sync_synchronize()
#elif defined(_MSC_VER)
#include <intrin.h>
#define T32PERF_RAM_RELEASE_BARRIER() _ReadWriteBarrier()
#else
#define T32PERF_RAM_RELEASE_BARRIER() ((void)0)
#endif
#endif

static int t32perf_ram_transport_is_valid(
    const t32perf_ram_transport_t *transport)
{
    return (transport != NULL) &&
           (transport->slots != NULL) &&
           (transport->slot_count != UINT32_C(0)) &&
           (transport->slot_count <= UINT32_C(0x7fffffff));
}

t32perf_transport_result_t t32perf_null_transport_write(
    void *user_data,
    const uint8_t *record,
    size_t record_len)
{
    (void)user_data;
    (void)record;
    (void)record_len;
    return T32PERF_TRANSPORT_ACCEPTED;
}

t32perf_transport_t t32perf_null_transport(void)
{
    t32perf_transport_t transport;
    transport.write = t32perf_null_transport_write;
    transport.user_data = NULL;
    return transport;
}

t32perf_ram_result_t t32perf_ram_transport_init(
    t32perf_ram_transport_t *transport,
    t32perf_ram_slot_t *slots,
    uint32_t slot_count)
{
    if ((transport == NULL) ||
        (slots == NULL) ||
        (slot_count == UINT32_C(0)) ||
        (slot_count > UINT32_C(0x7fffffff))) {
        return T32PERF_RAM_INVALID_ARGUMENT;
    }

    transport->slots = slots;
    transport->slot_count = slot_count;
    transport->write_position = UINT32_C(0);
    transport->read_position = UINT32_C(0);
    return T32PERF_RAM_READY;
}

t32perf_transport_t t32perf_ram_transport_as_transport(
    t32perf_ram_transport_t *transport)
{
    t32perf_transport_t result;
    result.write = t32perf_ram_transport_write;
    result.user_data = transport;
    return result;
}

t32perf_transport_result_t t32perf_ram_transport_write(
    void *user_data,
    const uint8_t *record,
    size_t record_len)
{
    t32perf_ram_transport_t *transport;
    uint32_t write_position;
    uint32_t read_position;
    t32perf_ram_slot_t *slot;

    transport = (t32perf_ram_transport_t *)user_data;
    if (!t32perf_ram_transport_is_valid(transport) ||
        (record == NULL) ||
        (record_len > T32PERF_WIRE_MAX_RECORD_SIZE)) {
        return T32PERF_TRANSPORT_ERROR;
    }

    write_position = transport->write_position;
    read_position = transport->read_position;
    T32PERF_RAM_ACQUIRE_BARRIER();
    if ((uint32_t)(write_position - read_position) >= transport->slot_count) {
        return T32PERF_TRANSPORT_FULL;
    }

    slot = &transport->slots[write_position % transport->slot_count];
    memcpy(slot->record, record, record_len);
    slot->record_len = record_len;
    T32PERF_RAM_RELEASE_BARRIER();
    transport->write_position = write_position + UINT32_C(1);
    return T32PERF_TRANSPORT_ACCEPTED;
}

t32perf_ram_result_t t32perf_ram_transport_peek(
    t32perf_ram_transport_t *transport,
    const uint8_t **record,
    size_t *record_len)
{
    uint32_t read_position;
    uint32_t write_position;
    t32perf_ram_slot_t *slot;

    if (!t32perf_ram_transport_is_valid(transport) ||
        (record == NULL) ||
        (record_len == NULL)) {
        return T32PERF_RAM_INVALID_ARGUMENT;
    }

    read_position = transport->read_position;
    write_position = transport->write_position;
    T32PERF_RAM_ACQUIRE_BARRIER();
    if (read_position == write_position) {
        return T32PERF_RAM_EMPTY;
    }

    slot = &transport->slots[read_position % transport->slot_count];
    *record = slot->record;
    *record_len = slot->record_len;
    return T32PERF_RAM_READY;
}

t32perf_ram_result_t t32perf_ram_transport_pop(
    t32perf_ram_transport_t *transport)
{
    uint32_t read_position;
    uint32_t write_position;

    if (!t32perf_ram_transport_is_valid(transport)) {
        return T32PERF_RAM_INVALID_ARGUMENT;
    }

    read_position = transport->read_position;
    write_position = transport->write_position;
    T32PERF_RAM_ACQUIRE_BARRIER();
    if (read_position == write_position) {
        return T32PERF_RAM_EMPTY;
    }

    T32PERF_RAM_RELEASE_BARRIER();
    transport->read_position = read_position + UINT32_C(1);
    return T32PERF_RAM_READY;
}

t32perf_ram_result_t t32perf_ram_transport_read(
    t32perf_ram_transport_t *transport,
    uint8_t *buffer,
    size_t buffer_size,
    size_t *record_len)
{
    const uint8_t *record;
    size_t available;
    t32perf_ram_result_t result;

    if ((buffer == NULL) || (record_len == NULL)) {
        return T32PERF_RAM_INVALID_ARGUMENT;
    }

    result = t32perf_ram_transport_peek(transport, &record, &available);
    if (result != T32PERF_RAM_READY) {
        return result;
    }

    *record_len = available;
    if (buffer_size < available) {
        return T32PERF_RAM_BUFFER_TOO_SMALL;
    }

    memcpy(buffer, record, available);
    return t32perf_ram_transport_pop(transport);
}

uint32_t t32perf_ram_transport_size(
    const t32perf_ram_transport_t *transport)
{
    uint32_t write_position;
    uint32_t read_position;

    if (!t32perf_ram_transport_is_valid(transport)) {
        return UINT32_C(0);
    }
    write_position = transport->write_position;
    read_position = transport->read_position;
    T32PERF_RAM_ACQUIRE_BARRIER();
    return (uint32_t)(write_position - read_position);
}
