// SPDX-License-Identifier: GPL-2.0
/*
 * K-Scanner eBPF Telemetry — Real-time RWX Memory Detection
 *
 * Hooks into sys_enter tracepoints for mmap(2) and mprotect(2)
 * to detect processes allocating writable+executable memory in real time.
 *
 * Architecture: x86_64 (syscall numbers hardcoded for raw_tp)
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define __NR_mmap      9
#define __NR_mprotect  10

#define PROT_WRITE     0x02
#define PROT_EXEC      0x04

struct rwx_event {
    __u64 pid;
    __u64 addr;
    __u64 len;
    __u64 prot;
    char  comm[16];
};

struct {
    __uint(type,       BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size,   sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 64);
} rwx_events SEC(".maps");

/*
 * Hook: sys_enter tracepoint (raw)
 * Monitors mmap(2) and mprotect(2) for PROT_WRITE | PROT_EXEC.
 *
 * ctx->args layout for raw_tp/sys_enter:
 *   args[0] = syscall number
 *   args[1] = arg0 (addr)
 *   args[2] = arg1 (length)
 *   args[3] = arg2 (prot)
 *   args[4] = arg3 (flags / dummy)
 *   args[5] = arg4 (fd / dummy)
 *   args[6] = arg5 (offset / dummy)
 */
SEC("raw_tp/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 nr = ctx->args[0];

    if (nr != __NR_mmap && nr != __NR_mprotect)
        return 0;

    __u64 prot = ctx->args[3];

    /* Skip regions that are NOT simultaneously writable AND executable */
    if (!(prot & PROT_WRITE) || !(prot & PROT_EXEC))
        return 0;

    struct rwx_event ev = {};
    __u64 pid_tgid   = bpf_get_current_pid_tgid();
    ev.pid  = pid_tgid >> 32;
    ev.addr = ctx->args[1];
    ev.len  = ctx->args[2];
    ev.prot = prot;
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));

    bpf_perf_event_output(ctx, &rwx_events, BPF_F_CURRENT_CPU,
                          &ev, sizeof(ev));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
