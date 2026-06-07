#include "bpf_telemetry.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>

#ifdef HAVE_LIBBPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>


#define BPF_OBJ_INSTALLED "/usr/local/share/kscanner/rwx_monitor.bpf.o"
#define BPF_OBJ_BUILDTREE "build/bpf/rwx_monitor.bpf.o"

struct bpf_telemetry_ctx {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    struct perf_buffer *pb;
    struct rlimit rlim_old;
    int map_fd;
    BpfTelemetryState *state;
};

static struct bpf_telemetry_ctx ctx = {0};

static void bump_rlimit_memlock(void)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    getrlimit(RLIMIT_MEMLOCK, &ctx.rlim_old);
    setrlimit(RLIMIT_MEMLOCK, &r);
}

static void restore_rlimit_memlock(void)
{
    setrlimit(RLIMIT_MEMLOCK, &ctx.rlim_old);
}

static void handle_event(void *cb_arg, int cpu, void *data, unsigned int sz)
{
    (void)cpu;
    BpfTelemetryState *s = (BpfTelemetryState *)cb_arg;
    if (!s) return;

    const struct {
        uint64_t pid;
        uint64_t addr;
        uint64_t len;
        uint64_t prot;
        uint64_t syscall_nr;
        char     comm[16];
    } *ev = (const void *)data;

    if (sz < sizeof(*ev)) return;

    int head = (s->ring_head + 1) % (int)(sizeof(s->ring) / sizeof(s->ring[0]));
    if (head == s->ring_tail) return;

    BpfRwxEvent *slot = &s->ring[s->ring_head];
    slot->pid        = (int)(ev->pid);
    slot->raw_addr   = ev->addr;
    slot->raw_len    = ev->len;
    slot->raw_prot   = ev->prot;
    slot->syscall_nr = ev->syscall_nr;
    if (ev->addr)
        snprintf(slot->addr, sizeof(slot->addr), "0x%lx",
                 (unsigned long)ev->addr);
    else
        slot->addr[0] = '\0';
    memcpy(slot->comm, ev->comm, sizeof(slot->comm) - 1);
    slot->comm[sizeof(slot->comm) - 1] = '\0';

    s->ring_head = head;
    s->event_count++;
    s->active = 1;
}

static void handle_lost(void *cb_arg, int cpu, __u64 cnt)
{
    (void)cb_arg;
    (void)cpu;
    (void)cnt;
}

static const char *resolve_bpf_obj_path(void)
{
    if (access(BPF_OBJ_INSTALLED, R_OK) == 0)
        return BPF_OBJ_INSTALLED;
    if (access(BPF_OBJ_BUILDTREE, R_OK) == 0)
        return BPF_OBJ_BUILDTREE;
    return NULL;
}

int bpf_telemetry_init(BpfTelemetryState *state)
{
    if (!state) return -1;
    memset(state, 0, sizeof(*state));
    state->ring_capacity = (int)(sizeof(state->ring) / sizeof(state->ring[0]));

    const char *obj_path = resolve_bpf_obj_path();
    if (!obj_path) {
        snprintf(state->error_msg, sizeof(state->error_msg),
                 "BPF object not found (checked '%s', '%s')",
                 BPF_OBJ_INSTALLED, BPF_OBJ_BUILDTREE);
        return -1;
    }

    libbpf_set_print(NULL);
    bump_rlimit_memlock();

    ctx.obj = bpf_object__open_file(obj_path, NULL);
    if (!ctx.obj) {
        snprintf(state->error_msg, sizeof(state->error_msg),
                 "bpf_object__open_file failed");
        restore_rlimit_memlock();
        return -1;
    }

    if (bpf_object__load(ctx.obj)) {
        snprintf(state->error_msg, sizeof(state->error_msg),
                 "bpf_object__load failed (no BPF support?)");
        bpf_object__close(ctx.obj);
        ctx.obj = NULL;
        restore_rlimit_memlock();
        return -1;
    }

    ctx.prog = bpf_object__find_program_by_name(ctx.obj, "trace_sys_enter");
    if (!ctx.prog) {
        snprintf(state->error_msg, sizeof(state->error_msg),
                 "BPF program 'trace_sys_enter' not found");
        bpf_object__close(ctx.obj);
        ctx.obj = NULL;
        restore_rlimit_memlock();
        return -1;
    }

    ctx.link = bpf_program__attach(ctx.prog);
    if (!ctx.link) {
        snprintf(state->error_msg, sizeof(state->error_msg),
                 "bpf_program__attach failed (no permission?)");
        bpf_object__close(ctx.obj);
        ctx.obj = NULL;
        restore_rlimit_memlock();
        return -1;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(ctx.obj, "rwx_events");
    if (!map) {
        bpf_telemetry_shutdown(state);
        snprintf(state->error_msg, sizeof(state->error_msg),
                 "BPF map 'rwx_events' not found");
        return -1;
    }

    ctx.map_fd = bpf_map__fd(map);
    if (ctx.map_fd < 0) {
        bpf_telemetry_shutdown(state);
        snprintf(state->error_msg, sizeof(state->error_msg),
                 "invalid BPF map fd");
        return -1;
    }

    ctx.state = state;
    ctx.pb = perf_buffer__new(ctx.map_fd, 8, handle_event, handle_lost,
                               state, NULL);
    if (!ctx.pb) {
        bpf_telemetry_shutdown(state);
        snprintf(state->error_msg, sizeof(state->error_msg),
                 "perf_buffer__new failed");
        return -1;
    }

    state->active = 1;
    return 0;
}

void bpf_telemetry_poll(BpfTelemetryState *state)
{
    if (!state || !state->active || !ctx.pb) return;
    perf_buffer__poll(ctx.pb, 0);
}

void bpf_telemetry_shutdown(BpfTelemetryState *state)
{
    if (state) state->active = 0;

    if (ctx.pb) {
        perf_buffer__free(ctx.pb);
        ctx.pb = NULL;
    }
    if (ctx.link) {
        bpf_link__destroy(ctx.link);
        ctx.link = NULL;
    }
    if (ctx.obj) {
        bpf_object__close(ctx.obj);
        ctx.obj = NULL;
    }
    restore_rlimit_memlock();
}

int bpf_telemetry_drain_ring(BpfTelemetryState *state, BpfRwxEvent *out, int max)
{
    if (!state || !out || max <= 0) return 0;
    int drained = 0;
    while (state->ring_tail != state->ring_head && drained < max) {
        *out++ = state->ring[state->ring_tail];
        state->ring_tail = (state->ring_tail + 1) % state->ring_capacity;
        drained++;
    }
    return drained;
}

#else

int bpf_telemetry_init(BpfTelemetryState *state)
{
    if (state) {
        memset(state, 0, sizeof(*state));
        snprintf(state->error_msg, sizeof(state->error_msg),
                 "eBPF support not compiled (install libbpf-dev)");
    }
    return -1;
}

void bpf_telemetry_poll(BpfTelemetryState *state) { (void)state; }

void bpf_telemetry_shutdown(BpfTelemetryState *state)
{
    if (state) state->active = 0;
}

int bpf_telemetry_drain_ring(BpfTelemetryState *state, BpfRwxEvent *out, int max)
{
    (void)state;
    (void)out;
    (void)max;
    return 0;
}

#endif
