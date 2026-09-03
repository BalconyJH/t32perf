#include "t32perf/event.h"
#include "t32perf/transports.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CAPTURE_CAPACITY 16u

#if T32PERF_MAX_PAYLOAD_SIZE >= 13u
#define ASYNC_TEST_NAME "async"
#define ASYNC_TEST_NAME_LEN 5u
#else
#define ASYNC_TEST_NAME NULL
#define ASYNC_TEST_NAME_LEN 0u
#endif

typedef struct capture_transport {
    uint8_t records[CAPTURE_CAPACITY][T32PERF_WIRE_MAX_RECORD_SIZE];
    size_t lengths[CAPTURE_CAPACITY];
    t32perf_transport_result_t results[CAPTURE_CAPACITY];
    size_t result_count;
    size_t attempt_count;
} capture_transport_t;

static int failures;

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "%s:%d: check failed: %s\n",                    \
                    __FILE__, __LINE__, #condition);                           \
            failures += 1;                                                     \
        }                                                                      \
    } while (0)

static uint16_t read_u16_le(const uint8_t *input)
{
    return (uint16_t)((uint16_t)input[0] | ((uint16_t)input[1] << 8));
}

static uint32_t read_u32_le(const uint8_t *input)
{
    return (uint32_t)input[0] |
           ((uint32_t)input[1] << 8) |
           ((uint32_t)input[2] << 16) |
           ((uint32_t)input[3] << 24);
}

static uint64_t read_u64_le(const uint8_t *input)
{
    return (uint64_t)input[0] |
           ((uint64_t)input[1] << 8) |
           ((uint64_t)input[2] << 16) |
           ((uint64_t)input[3] << 24) |
           ((uint64_t)input[4] << 32) |
           ((uint64_t)input[5] << 40) |
           ((uint64_t)input[6] << 48) |
           ((uint64_t)input[7] << 56);
}

static t32perf_transport_result_t capture_write(
    void *user_data,
    const uint8_t *record,
    size_t record_len)
{
    capture_transport_t *capture = (capture_transport_t *)user_data;
    size_t index = capture->attempt_count;
    t32perf_transport_result_t result = T32PERF_TRANSPORT_ACCEPTED;

    if (index >= CAPTURE_CAPACITY) {
        return T32PERF_TRANSPORT_ERROR;
    }
    memcpy(capture->records[index], record, record_len);
    capture->lengths[index] = record_len;
    capture->attempt_count += 1u;
    if (index < capture->result_count) {
        result = capture->results[index];
    }
    return result;
}

static t32perf_transport_t capture_as_transport(capture_transport_t *capture)
{
    t32perf_transport_t transport;
    transport.write = capture_write;
    transport.user_data = capture;
    return transport;
}

static void test_golden_instant_record(void)
{
    static const uint8_t expected[] = {
        0x54, 0x33, 0x50, 0x46, 0x01, 0x01, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x44, 0x33, 0x22, 0x11,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0xd4, 0xc3, 0xb2, 0xa1, 0x0d, 0x0c, 0x0b, 0x0a,
        0x61, 0x62, 0x63
    };
    capture_transport_t capture = {0};
    t32perf_context_t context;

    CHECK(t32perf_context_init(
              &context, capture_as_transport(&capture), UINT32_C(0x11223344)) ==
          T32PERF_EMIT_ACCEPTED);
    CHECK(t32perf_instant(
              &context,
              UINT64_C(0x0102030405060708),
              UINT32_C(0xa1b2c3d4),
              UINT32_C(0x0a0b0c0d),
              "abc",
              3u) == T32PERF_EMIT_ACCEPTED);
    CHECK(capture.attempt_count == 1u);
    CHECK(capture.lengths[0] == sizeof(expected));
    CHECK(memcmp(capture.records[0], expected, sizeof(expected)) == 0);
}

static void test_event_payloads(void)
{
    capture_transport_t capture = {0};
    t32perf_context_t context;
    const uint8_t *payload;

    CHECK(t32perf_context_init(
              &context, capture_as_transport(&capture), UINT32_C(7)) ==
          T32PERF_EMIT_ACCEPTED);
    CHECK(t32perf_begin(&context, 1u, 2u, 3u, "begin", 5u) ==
          T32PERF_EMIT_ACCEPTED);
    CHECK(t32perf_end(&context, 2u, 2u, 3u, NULL, 0u) ==
          T32PERF_EMIT_ACCEPTED);
    CHECK(t32perf_counter(&context, 3u, 2u, 4u, INT64_C(-2)) ==
          T32PERF_EMIT_ACCEPTED);
    CHECK(t32perf_async_begin(
              &context,
              4u,
              2u,
              5u,
              UINT64_C(0x1122334455667788),
              ASYNC_TEST_NAME,
              ASYNC_TEST_NAME_LEN) == T32PERF_EMIT_ACCEPTED);
    CHECK(t32perf_async_end(
              &context,
              UINT64_C(0xfedcba9876543210),
              2u,
              5u,
              UINT64_C(0x1122334455667788)) == T32PERF_EMIT_ACCEPTED);

    CHECK(capture.attempt_count == 5u);
    CHECK(capture.records[0][T32PERF_WIRE_OFFSET_KIND] == T32PERF_EVENT_BEGIN);
    CHECK(capture.records[1][T32PERF_WIRE_OFFSET_KIND] == T32PERF_EVENT_END);
    CHECK(capture.records[2][T32PERF_WIRE_OFFSET_KIND] == T32PERF_EVENT_COUNTER);
    CHECK(capture.records[3][T32PERF_WIRE_OFFSET_KIND] ==
          T32PERF_EVENT_ASYNC_BEGIN);
    CHECK(capture.records[4][T32PERF_WIRE_OFFSET_KIND] ==
          T32PERF_EVENT_ASYNC_END);

    CHECK(read_u16_le(&capture.records[0][T32PERF_WIRE_OFFSET_PAYLOAD_LEN]) == 5u);
    CHECK(read_u16_le(&capture.records[1][T32PERF_WIRE_OFFSET_PAYLOAD_LEN]) == 0u);
    payload = &capture.records[2][T32PERF_WIRE_HEADER_SIZE];
    CHECK(read_u64_le(payload) == UINT64_MAX - UINT64_C(1));
    payload = &capture.records[3][T32PERF_WIRE_HEADER_SIZE];
    CHECK(read_u64_le(payload) == UINT64_C(0x1122334455667788));
#if ASYNC_TEST_NAME_LEN != 0u
    CHECK(memcmp(&payload[8], ASYNC_TEST_NAME, ASYNC_TEST_NAME_LEN) == 0);
#endif
    CHECK(read_u16_le(&capture.records[3][T32PERF_WIRE_OFFSET_PAYLOAD_LEN]) ==
          8u + ASYNC_TEST_NAME_LEN);
    payload = &capture.records[4][T32PERF_WIRE_HEADER_SIZE];
    CHECK(read_u64_le(payload) == UINT64_C(0x1122334455667788));
    CHECK(read_u64_le(&capture.records[4][T32PERF_WIRE_OFFSET_TIMESTAMP]) ==
          UINT64_C(0xfedcba9876543210));
}

static void test_lengths_and_overflow(void)
{
    static char maximum_name[T32PERF_MAX_PAYLOAD_SIZE];
    capture_transport_t capture = {0};
    t32perf_context_t context;
    t32perf_transport_t invalid_transport = {0};

    memset(maximum_name, 'x', sizeof(maximum_name));
    CHECK(t32perf_context_init(NULL, invalid_transport, 0u) ==
          T32PERF_EMIT_INVALID_ARGUMENT);
    CHECK(t32perf_context_init(&context, invalid_transport, 0u) ==
          T32PERF_EMIT_INVALID_ARGUMENT);
    CHECK(t32perf_context_init(&context, capture_as_transport(&capture), 0u) ==
          T32PERF_EMIT_ACCEPTED);
    CHECK(t32perf_instant(&context, 0u, 0u, 0u, NULL, 1u) ==
          T32PERF_EMIT_INVALID_ARGUMENT);
    CHECK(t32perf_instant(
              &context, 0u, 0u, 0u, maximum_name, sizeof(maximum_name)) ==
          T32PERF_EMIT_ACCEPTED);
    CHECK(capture.lengths[0] == T32PERF_WIRE_MAX_RECORD_SIZE);
    CHECK(t32perf_instant(
              &context, 0u, 0u, 0u, maximum_name, sizeof(maximum_name) + 1u) ==
          T32PERF_EMIT_PAYLOAD_TOO_LARGE);
    CHECK(t32perf_async_begin(
              &context,
              0u,
              0u,
              0u,
              1u,
              maximum_name,
              T32PERF_MAX_PAYLOAD_SIZE - 8u) == T32PERF_EMIT_ACCEPTED);
    CHECK(t32perf_async_begin(
              &context,
              0u,
              0u,
              0u,
              1u,
              maximum_name,
              T32PERF_MAX_PAYLOAD_SIZE - 7u) ==
          T32PERF_EMIT_PAYLOAD_TOO_LARGE);
    CHECK(t32perf_async_begin(
              &context, 0u, 0u, 0u, 1u, maximum_name, SIZE_MAX) ==
          T32PERF_EMIT_PAYLOAD_TOO_LARGE);
    CHECK(capture.attempt_count == 2u);
    CHECK(t32perf_context_next_sequence(&context) == 2u);
}

static void test_drop_report(void)
{
    capture_transport_t capture = {0};
    t32perf_context_t context;

    capture.results[0] = T32PERF_TRANSPORT_FULL;
    capture.results[1] = T32PERF_TRANSPORT_ACCEPTED;
    capture.results[2] = T32PERF_TRANSPORT_ACCEPTED;
    capture.result_count = 3u;

    CHECK(t32perf_context_init(&context, capture_as_transport(&capture), 10u) ==
          T32PERF_EMIT_ACCEPTED);
    CHECK(t32perf_instant(&context, 100u, 3u, 4u, "lost", 4u) ==
          T32PERF_EMIT_DROPPED);
    CHECK(t32perf_context_pending_dropped(&context) == 1u);
    CHECK(t32perf_instant(&context, 200u, 5u, 6u, "kept", 4u) ==
          T32PERF_EMIT_ACCEPTED);

    CHECK(capture.attempt_count == 3u);
    CHECK(read_u32_le(&capture.records[0][T32PERF_WIRE_OFFSET_SEQUENCE]) == 10u);
    CHECK(capture.records[1][T32PERF_WIRE_OFFSET_KIND] == T32PERF_EVENT_DROPPED);
    CHECK(read_u32_le(&capture.records[1][T32PERF_WIRE_OFFSET_SEQUENCE]) == 11u);
    CHECK(read_u64_le(&capture.records[1][T32PERF_WIRE_OFFSET_TIMESTAMP]) == 200u);
    CHECK(read_u32_le(&capture.records[1][T32PERF_WIRE_OFFSET_CONTEXT_ID]) == 5u);
    CHECK(read_u32_le(&capture.records[1][T32PERF_WIRE_HEADER_SIZE]) == 1u);
    CHECK(read_u32_le(&capture.records[2][T32PERF_WIRE_OFFSET_SEQUENCE]) == 12u);
    CHECK(capture.records[2][T32PERF_WIRE_OFFSET_KIND] == T32PERF_EVENT_INSTANT);
    CHECK(t32perf_context_pending_dropped(&context) == 0u);
    CHECK(t32perf_context_next_sequence(&context) == 13u);
}

static void test_full_drop_report_and_saturation(void)
{
    capture_transport_t capture = {0};
    t32perf_context_t context;

    capture.results[0] = T32PERF_TRANSPORT_FULL;
    capture.results[1] = T32PERF_TRANSPORT_FULL;
    capture.results[2] = T32PERF_TRANSPORT_ACCEPTED;
    capture.results[3] = T32PERF_TRANSPORT_ACCEPTED;
    capture.result_count = 4u;

    CHECK(t32perf_context_init(&context, capture_as_transport(&capture), 0u) ==
          T32PERF_EMIT_ACCEPTED);
    CHECK(t32perf_instant(&context, 1u, 1u, 1u, NULL, 0u) ==
          T32PERF_EMIT_DROPPED);
    CHECK(t32perf_instant(&context, 2u, 1u, 2u, NULL, 0u) ==
          T32PERF_EMIT_DROPPED);
    CHECK(t32perf_context_pending_dropped(&context) == 2u);
    CHECK(t32perf_instant(&context, 3u, 1u, 3u, NULL, 0u) ==
          T32PERF_EMIT_ACCEPTED);
    CHECK(capture.attempt_count == 4u);
    CHECK(capture.records[1][T32PERF_WIRE_OFFSET_KIND] == T32PERF_EVENT_DROPPED);
    CHECK(capture.records[2][T32PERF_WIRE_OFFSET_KIND] == T32PERF_EVENT_DROPPED);
    CHECK(read_u32_le(&capture.records[2][T32PERF_WIRE_HEADER_SIZE]) == 2u);
    CHECK(read_u32_le(&capture.records[3][T32PERF_WIRE_OFFSET_SEQUENCE]) == 3u);

    capture.attempt_count = 0u;
    capture.result_count = 1u;
    capture.results[0] = T32PERF_TRANSPORT_FULL;
    context.next_sequence = 0u;
    context.pending_dropped = UINT32_MAX;
    CHECK(t32perf_instant(&context, 4u, 1u, 4u, NULL, 0u) ==
          T32PERF_EMIT_DROPPED);
    CHECK(t32perf_context_pending_dropped(&context) == UINT32_MAX);
}

static void test_transport_error(void)
{
    capture_transport_t capture = {0};
    t32perf_context_t context;

    capture.results[0] = T32PERF_TRANSPORT_ERROR;
    capture.result_count = 1u;
    CHECK(t32perf_context_init(&context, capture_as_transport(&capture), 20u) ==
          T32PERF_EMIT_ACCEPTED);
    CHECK(t32perf_instant(&context, 1u, 1u, 1u, NULL, 0u) ==
          T32PERF_EMIT_TRANSPORT_ERROR);
    CHECK(t32perf_context_next_sequence(&context) == 21u);
    CHECK(t32perf_context_pending_dropped(&context) == 0u);

    memset(&capture, 0, sizeof(capture));
    capture.results[0] = T32PERF_TRANSPORT_FULL;
    capture.results[1] = T32PERF_TRANSPORT_ERROR;
    capture.results[2] = T32PERF_TRANSPORT_ACCEPTED;
    capture.results[3] = T32PERF_TRANSPORT_ACCEPTED;
    capture.result_count = 4u;
    CHECK(t32perf_context_init(&context, capture_as_transport(&capture), 0u) ==
          T32PERF_EMIT_ACCEPTED);
    CHECK(t32perf_instant(&context, 1u, 1u, 1u, NULL, 0u) ==
          T32PERF_EMIT_DROPPED);
    CHECK(t32perf_instant(&context, 2u, 1u, 2u, NULL, 0u) ==
          T32PERF_EMIT_TRANSPORT_ERROR);
    CHECK(t32perf_context_pending_dropped(&context) == 1u);
    CHECK(t32perf_instant(&context, 3u, 1u, 3u, NULL, 0u) ==
          T32PERF_EMIT_ACCEPTED);
    CHECK(capture.attempt_count == 4u);
    CHECK(read_u32_le(&capture.records[2][T32PERF_WIRE_HEADER_SIZE]) == 1u);
    CHECK(read_u32_le(&capture.records[3][T32PERF_WIRE_OFFSET_SEQUENCE]) == 3u);
}

static void test_sequence_wrap_and_null_transport(void)
{
    capture_transport_t capture = {0};
    t32perf_context_t context;
    t32perf_context_t null_context;

    CHECK(t32perf_context_init(
              &context, capture_as_transport(&capture), UINT32_MAX) ==
          T32PERF_EMIT_ACCEPTED);
    CHECK(t32perf_counter(&context, 1u, 2u, 3u, 4) == T32PERF_EMIT_ACCEPTED);
    CHECK(t32perf_counter(&context, 2u, 2u, 3u, 5) == T32PERF_EMIT_ACCEPTED);
    CHECK(read_u32_le(&capture.records[0][T32PERF_WIRE_OFFSET_SEQUENCE]) ==
          UINT32_MAX);
    CHECK(read_u32_le(&capture.records[1][T32PERF_WIRE_OFFSET_SEQUENCE]) == 0u);
    CHECK(t32perf_context_next_sequence(&context) == 1u);

    CHECK(t32perf_context_init(&null_context, t32perf_null_transport(), 9u) ==
          T32PERF_EMIT_ACCEPTED);
    CHECK(t32perf_async_end(&null_context, 1u, 2u, 3u, 4u) ==
          T32PERF_EMIT_ACCEPTED);
    CHECK(t32perf_context_next_sequence(&null_context) == 10u);
}

static void test_ram_transport(void)
{
    t32perf_ram_slot_t slots[2];
    t32perf_ram_transport_t ram;
    t32perf_transport_t transport;
    uint8_t first[] = {1u, 2u, 3u};
    uint8_t second[] = {4u, 5u};
    uint8_t third[] = {6u};
    uint8_t output[T32PERF_WIRE_MAX_RECORD_SIZE];
    size_t output_len = 0u;

    CHECK(t32perf_ram_transport_init(NULL, slots, 2u) ==
          T32PERF_RAM_INVALID_ARGUMENT);
    CHECK(t32perf_ram_transport_init(&ram, NULL, 2u) ==
          T32PERF_RAM_INVALID_ARGUMENT);
    CHECK(t32perf_ram_transport_init(&ram, slots, 0u) ==
          T32PERF_RAM_INVALID_ARGUMENT);
    CHECK(t32perf_ram_transport_init(&ram, slots, UINT32_C(0x80000000)) ==
          T32PERF_RAM_INVALID_ARGUMENT);
    CHECK(t32perf_ram_transport_init(&ram, slots, 2u) == T32PERF_RAM_READY);
    transport = t32perf_ram_transport_as_transport(&ram);

    CHECK(transport.write(transport.user_data, first, sizeof(first)) ==
          T32PERF_TRANSPORT_ACCEPTED);
    CHECK(transport.write(transport.user_data, second, sizeof(second)) ==
          T32PERF_TRANSPORT_ACCEPTED);
    CHECK(transport.write(transport.user_data, third, sizeof(third)) ==
          T32PERF_TRANSPORT_FULL);
    CHECK(t32perf_ram_transport_size(&ram) == 2u);
    CHECK(t32perf_ram_transport_read(&ram, output, 2u, &output_len) ==
          T32PERF_RAM_BUFFER_TOO_SMALL);
    CHECK(output_len == sizeof(first));
    CHECK(t32perf_ram_transport_size(&ram) == 2u);
    CHECK(t32perf_ram_transport_read(&ram, output, sizeof(output), &output_len) ==
          T32PERF_RAM_READY);
    CHECK(output_len == sizeof(first));
    CHECK(memcmp(output, first, sizeof(first)) == 0);
    CHECK(transport.write(transport.user_data, third, sizeof(third)) ==
          T32PERF_TRANSPORT_ACCEPTED);
    CHECK(t32perf_ram_transport_read(&ram, output, sizeof(output), &output_len) ==
          T32PERF_RAM_READY);
    CHECK(memcmp(output, second, sizeof(second)) == 0);
    CHECK(t32perf_ram_transport_read(&ram, output, sizeof(output), &output_len) ==
          T32PERF_RAM_READY);
    CHECK(memcmp(output, third, sizeof(third)) == 0);
    CHECK(t32perf_ram_transport_read(&ram, output, sizeof(output), &output_len) ==
          T32PERF_RAM_EMPTY);

    ram.write_position = UINT32_MAX;
    ram.read_position = UINT32_MAX;
    CHECK(transport.write(transport.user_data, first, sizeof(first)) ==
          T32PERF_TRANSPORT_ACCEPTED);
    CHECK(ram.write_position == 0u);
    CHECK(t32perf_ram_transport_read(&ram, output, sizeof(output), &output_len) ==
          T32PERF_RAM_READY);
    CHECK(ram.read_position == 0u);
    CHECK(memcmp(output, first, sizeof(first)) == 0);
    CHECK(transport.write(
              transport.user_data, first, T32PERF_WIRE_MAX_RECORD_SIZE + 1u) ==
          T32PERF_TRANSPORT_ERROR);
    CHECK(transport.write(transport.user_data, NULL, 0u) ==
          T32PERF_TRANSPORT_ERROR);
}

int main(void)
{
    test_golden_instant_record();
    test_event_payloads();
    test_lengths_and_overflow();
    test_drop_report();
    test_full_drop_report_and_saturation();
    test_transport_error();
    test_sequence_wrap_and_null_transport();
    test_ram_transport();

    if (failures != 0) {
        fprintf(stderr, "%d test check(s) failed\n", failures);
        return 1;
    }
    return 0;
}
