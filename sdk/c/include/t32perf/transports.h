#ifndef T32PERF_TRANSPORTS_H
#define T32PERF_TRANSPORTS_H

#include "t32perf/event.h"

#ifdef __cplusplus
extern "C" {
#endif

t32perf_transport_result_t t32perf_null_transport_write(
    void *user_data,
    const uint8_t *record,
    size_t record_len);

t32perf_transport_t t32perf_null_transport(void);

typedef struct t32perf_ram_slot {
    size_t record_len;
    uint8_t record[T32PERF_WIRE_MAX_RECORD_SIZE];
} t32perf_ram_slot_t;

typedef struct t32perf_ram_transport {
    t32perf_ram_slot_t *slots;
    uint32_t slot_count;
    volatile uint32_t write_position;
    volatile uint32_t read_position;
} t32perf_ram_transport_t;

typedef enum t32perf_ram_result {
    T32PERF_RAM_READY = 0,
    T32PERF_RAM_EMPTY = 1,
    T32PERF_RAM_BUFFER_TOO_SMALL = 2,
    T32PERF_RAM_INVALID_ARGUMENT = 3
} t32perf_ram_result_t;

t32perf_ram_result_t t32perf_ram_transport_init(
    t32perf_ram_transport_t *transport,
    t32perf_ram_slot_t *slots,
    uint32_t slot_count);

t32perf_transport_t t32perf_ram_transport_as_transport(
    t32perf_ram_transport_t *transport);

t32perf_transport_result_t t32perf_ram_transport_write(
    void *user_data,
    const uint8_t *record,
    size_t record_len);

t32perf_ram_result_t t32perf_ram_transport_peek(
    t32perf_ram_transport_t *transport,
    const uint8_t **record,
    size_t *record_len);

t32perf_ram_result_t t32perf_ram_transport_pop(
    t32perf_ram_transport_t *transport);

t32perf_ram_result_t t32perf_ram_transport_read(
    t32perf_ram_transport_t *transport,
    uint8_t *buffer,
    size_t buffer_size,
    size_t *record_len);

uint32_t t32perf_ram_transport_size(
    const t32perf_ram_transport_t *transport);

#ifdef __cplusplus
}
#endif

#endif
