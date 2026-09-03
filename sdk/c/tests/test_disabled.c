#define T32PERF_ENABLE 0
#include "t32perf/event.h"

#include <stdint.h>

static int transport_calls;

static t32perf_transport_result_t counting_write(
    void *user_data,
    const uint8_t *record,
    size_t record_len)
{
    (void)user_data;
    (void)record;
    (void)record_len;
    transport_calls += 1;
    return T32PERF_TRANSPORT_ACCEPTED;
}

int main(void)
{
    t32perf_context_t context;
    t32perf_transport_t transport;

    context.transport.write = NULL;
    context.transport.user_data = NULL;
    context.next_sequence = UINT32_C(123);
    context.pending_dropped = UINT32_C(456);
    transport.write = counting_write;
    transport.user_data = NULL;

    if (t32perf_context_init(&context, transport, 7u) != T32PERF_EMIT_DISABLED) {
        return 1;
    }
    if (t32perf_instant(&context, 1u, 2u, 3u, "name", 4u) !=
        T32PERF_EMIT_DISABLED) {
        return 2;
    }
    if (t32perf_begin(&context, 1u, 2u, 3u, NULL, 0u) !=
        T32PERF_EMIT_DISABLED) {
        return 3;
    }
    if (t32perf_end(&context, 1u, 2u, 3u, NULL, 0u) !=
        T32PERF_EMIT_DISABLED) {
        return 4;
    }
    if (t32perf_counter(&context, 1u, 2u, 3u, -1) != T32PERF_EMIT_DISABLED) {
        return 5;
    }
    if (t32perf_async_begin(&context, 1u, 2u, 3u, 4u, NULL, 0u) !=
        T32PERF_EMIT_DISABLED) {
        return 6;
    }
    if (t32perf_async_end(&context, 1u, 2u, 3u, 4u) !=
        T32PERF_EMIT_DISABLED) {
        return 7;
    }
    if ((transport_calls != 0) ||
        (context.next_sequence != UINT32_C(123)) ||
        (context.pending_dropped != UINT32_C(456))) {
        return 8;
    }
    return 0;
}
