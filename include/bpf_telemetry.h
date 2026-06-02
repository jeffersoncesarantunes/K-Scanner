#ifndef BPF_TELEMETRY_H
#define BPF_TELEMETRY_H

#include <stdint.h>

#define BPF_EVENT_ADDR_STRLEN 20
#define BPF_EVENT_COMM_LEN    16

typedef struct {
    int      pid;
    char     addr[BPF_EVENT_ADDR_STRLEN];
    uint64_t raw_addr;
    uint64_t raw_len;
    uint64_t raw_prot;
    char     comm[BPF_EVENT_COMM_LEN];
} BpfRwxEvent;

typedef struct {
    int  active;
    int  event_count;
    int  ring_capacity;
    int  ring_head;
    int  ring_tail;
    BpfRwxEvent ring[256];
    char error_msg[256];
} BpfTelemetryState;

int  bpf_telemetry_init(BpfTelemetryState *state);
void bpf_telemetry_poll(BpfTelemetryState *state);
void bpf_telemetry_shutdown(BpfTelemetryState *state);
int  bpf_telemetry_drain_ring(BpfTelemetryState *state, BpfRwxEvent *out, int max);

#endif
