// module_load.c - detecta carregamento de módulos kernel via do_init_module

#include "../headers/common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("kprobe/do_init_module")
int kprobe_do_init_module(struct pt_regs *ctx)
{
    struct module *mod = (struct module *)PT_REGS_PARM1(ctx);
    if (!mod)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->tgid         = bpf_get_current_pid_tgid() & 0xffffffff;
    e->uid          = bpf_get_current_uid_gid() >> 32;
    e->gid          = bpf_get_current_uid_gid() & 0xffffffff;
    e->event_type   = EVENT_MODULE_HIDDEN;
    e->severity     = SEV_CRITICAL;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->data.kernel.addr = (__u64)(unsigned long)mod;
    bpf_probe_read_kernel_str(e->data.kernel.name,
                              sizeof(e->data.kernel.name),
                              BPF_CORE_READ(mod, name));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
