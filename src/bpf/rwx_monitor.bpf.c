#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define __NR_mmap      9
#define __NR_mprotect  10
#define __NR_shmat     30
#define __NR_execve    59

#define PROT_WRITE     0x02
#define PROT_EXEC      0x04
#define SHM_EXEC       0x8000

struct rwx_event {
    __u64 pid;
    __u64 addr;
    __u64 len;
    __u64 prot;
    __u64 syscall_nr;
    char  comm[16];
};

struct {
    __uint(type,       BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size,   sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 64);
} rwx_events SEC(".maps");

SEC("raw_tp/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 nr = ctx->args[0];

    if (nr == __NR_mmap) {
        __u64 prot = ctx->args[3];
        if (!(prot & PROT_WRITE) || !(prot & PROT_EXEC))
            return 0;
    } else if (nr == __NR_mprotect) {
        __u64 prot = ctx->args[3];
        if (!(prot & PROT_WRITE) || !(prot & PROT_EXEC))
            return 0;
    } else if (nr == __NR_shmat) {
        __u64 shmflg = ctx->args[3];
        if (!(shmflg & SHM_EXEC))
            return 0;
    } else if (nr == __NR_execve) {
    } else {
        return 0;
    }

    struct rwx_event ev = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev.pid  = pid_tgid >> 32;
    ev.syscall_nr = nr;
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));

    if (nr == __NR_mmap) {
        ev.addr = ctx->args[1];
        ev.len  = ctx->args[2];
        ev.prot = ctx->args[3];
    } else if (nr == __NR_mprotect) {
        ev.addr = ctx->args[1];
        ev.len  = ctx->args[2];
        ev.prot = ctx->args[3];
    } else if (nr == __NR_shmat) {
        ev.addr = ctx->args[2];
        ev.prot = ctx->args[3];
    } else if (nr == __NR_execve) {
        ev.addr = 0;
        ev.len  = 0;
        ev.prot = 0;
    }

    bpf_perf_event_output(ctx, &rwx_events, BPF_F_CURRENT_CPU,
                          &ev, sizeof(ev));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
