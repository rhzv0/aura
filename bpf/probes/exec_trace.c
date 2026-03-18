// exec_trace.c — rastreia execve para detectar shells e binários suspeitos

#include "../headers/common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline __u8 classify_exec(const char *path, int len)
{
    if (len <= 1)
        return SEV_INFO;

    int base = 0;
    #pragma unroll
    for (int i = 1; i < 64; i++) {
        if (path[i - 1] == '/')
            base = i;
    }

    /*
     * v3: esse limite foi adicionado depois do verifier rejeitar o build.
     * Sem ele, path[base+5] pode cair fora dos 64 bytes e o verifier nega.
     */
    if (base > 57)
        return SEV_INFO;

    __u8 b0 = path[base];
    __u8 b1 = path[base + 1];
    __u8 b2 = path[base + 2];
    __u8 b3 = path[base + 3];
    __u8 b4 = path[base + 4];
    __u8 b5 = path[base + 5];
    int blen = len - base;

    // shells
    if (blen >= 2 && b0=='s' && b1=='h' && (blen==2 || b2==0))           return SEV_HIGH;
    if (blen >= 4 && b0=='b' && b1=='a' && b2=='s' && b3=='h'
                  && (blen==4 || b4==0))                                   return SEV_HIGH;
    if (blen >= 4 && b0=='d' && b1=='a' && b2=='s' && b3=='h'
                  && (blen==4 || b4==0))                                   return SEV_HIGH;
    if (blen >= 3 && b0=='z' && b1=='s' && b2=='h' && (blen==3 || b3==0)) return SEV_HIGH;
    if (blen >= 3 && b0=='k' && b1=='s' && b2=='h' && (blen==3 || b3==0)) return SEV_HIGH;
    // netcat e variantes
    if (blen >= 2 && b0=='n' && b1=='c' && (blen==2 || b2==0))            return SEV_HIGH;
    if (blen >= 4 && b0=='n' && b1=='c' && b2=='a' && b3=='t'
                  && (blen==4 || b4==0))                                   return SEV_HIGH;
    if (blen >= 5 && b0=='s' && b1=='o' && b2=='c' && b3=='a' && b4=='t'
                  && (blen==5 || b5==0))                                   return SEV_HIGH;
    // linguagens usadas pra reverse shell
    if (blen >= 6 && b0=='p' && b1=='y' && b2=='t' && b3=='h' && b4=='o' && b5=='n')
        return SEV_HIGH;
    if (blen >= 4 && b0=='p' && b1=='e' && b2=='r' && b3=='l'
                  && (blen==4 || b4==0))                                   return SEV_HIGH;
    if (blen >= 4 && b0=='r' && b1=='u' && b2=='b' && b3=='y'
                  && (blen==4 || b4==0))                                   return SEV_HIGH;
    if (blen >= 3 && b0=='p' && b1=='h' && b2=='p' && (blen==3 || b3==0)) return SEV_HIGH;

    return SEV_INFO;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_execve(struct trace_event_raw_sys_enter *ctx)
{
    const char *upath = (const char *)ctx->args[0];
    if (!upath)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->tgid         = bpf_get_current_pid_tgid() & 0xffffffff;
    e->uid          = bpf_get_current_uid_gid() >> 32;
    e->gid          = bpf_get_current_uid_gid() & 0xffffffff;
    e->event_type   = EVENT_EXEC;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __builtin_memset(e->data.kernel.name, 0, sizeof(e->data.kernel.name));
    int n = bpf_probe_read_user_str(e->data.kernel.name,
                                    sizeof(e->data.kernel.name),
                                    upath);

    e->severity        = classify_exec((const char *)e->data.kernel.name, n);
    e->data.kernel.addr = bpf_get_current_pid_tgid() >> 32;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
