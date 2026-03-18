// bpf_defense.c - monitora carregamento de programas eBPF
//
// Meta-defesa: rootkits eBPF como Boopkit e TripleCross carregam seus
// próprios programas. Monitorando bpf(BPF_PROG_LOAD) vemos tudo,
// incluindo os maliciosos. Nossos próprios programas também aparecem —
// o engine Go filtra pelo PID do próprio processo.

#include "../headers/common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

#define BPF_PROG_LOAD 5

SEC("tracepoint/syscalls/sys_enter_bpf")
int tracepoint_bpf_load(struct trace_event_raw_sys_enter *ctx)
{
    int cmd = (int)ctx->args[0];
    union bpf_attr attr = {};
    struct event *e;

    if (cmd != BPF_PROG_LOAD)
        return 0;

    void *uattr = (void *)ctx->args[1];
    if (bpf_probe_read_user(&attr, sizeof(attr), uattr) < 0)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->tgid         = bpf_get_current_pid_tgid() & 0xffffffff;
    e->uid          = bpf_get_current_uid_gid() >> 32;
    e->gid          = bpf_get_current_uid_gid() & 0xffffffff;
    e->event_type   = EVENT_BPF_LOAD;
    e->severity     = SEV_MEDIUM;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->data.bpf_load.prog_type = attr.prog_type;
    e->data.bpf_load.insn_cnt  = attr.insn_cnt;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
