// memory_anomaly.c - detecta mmap/mprotect RWX em memória anônima
//
// Shellcode injection e reflective loading precisam de memória executável
// + gravável ao mesmo tempo, sem backing file. Isso é a assinatura.

#include "../headers/common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

#define PROT_WRITE    0x2
#define PROT_EXEC     0x4
#define MAP_ANONYMOUS 0x20

SEC("tracepoint/syscalls/sys_enter_mmap")
int tracepoint_mmap(struct trace_event_raw_sys_enter *ctx)
{
    __u64 len   = (__u64)ctx->args[1];
    __u32 prot  = (__u32)ctx->args[2];
    __u32 flags = (__u32)ctx->args[3];
    __s32 fd    = (__s32)ctx->args[4];
    struct event *e;

    if (!(prot & PROT_WRITE) || !(prot & PROT_EXEC))
        return 0;
    if (!(flags & MAP_ANONYMOUS) || fd != -1)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->tgid         = bpf_get_current_pid_tgid() & 0xffffffff;
    e->uid          = bpf_get_current_uid_gid() >> 32;
    e->gid          = bpf_get_current_uid_gid() & 0xffffffff;
    e->event_type   = EVENT_SUSPICIOUS_MMAP;
    e->severity     = SEV_HIGH;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->data.mmap.addr  = (__u64)ctx->args[0];
    e->data.mmap.len   = len;
    e->data.mmap.prot  = prot;
    e->data.mmap.flags = flags;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// mprotect detecta unpackers que alocam RW e depois promovem para RWX
SEC("tracepoint/syscalls/sys_enter_mprotect")
int tracepoint_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    __u32 prot = (__u32)ctx->args[2];
    struct event *e;

    if (!(prot & PROT_WRITE) || !(prot & PROT_EXEC))
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->tgid         = bpf_get_current_pid_tgid() & 0xffffffff;
    e->uid          = bpf_get_current_uid_gid() >> 32;
    e->gid          = bpf_get_current_uid_gid() & 0xffffffff;
    e->event_type   = EVENT_SUSPICIOUS_MMAP;
    e->severity     = SEV_HIGH;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->data.mmap.addr  = (__u64)ctx->args[0];
    e->data.mmap.len   = (__u64)ctx->args[1];
    e->data.mmap.prot  = prot;
    e->data.mmap.flags = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
