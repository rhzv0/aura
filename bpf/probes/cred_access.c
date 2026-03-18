// cred_access.c - detecta acesso a arquivos de credencial
//
// Monitora openat(). Dispara para:
//   /etc/shadow, /etc/gshadow
//   chaves SSH privadas (id_rsa, id_ed25519, id_ecdsa)
//
// Severidade: HIGH se uid == 0, CRITICAL se não for root lendo esses arquivos.

#include "../headers/common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

static __always_inline int is_cred_file(const char *upath, char *buf)
{
    int n = bpf_probe_read_user_str(buf, 64, upath);
    if (n <= 0)
        return 0;

    if (buf[0]=='/' && buf[1]=='e' && buf[2]=='t' && buf[3]=='c' && buf[4]=='/' &&
        buf[5]=='s' && buf[6]=='h' && buf[7]=='a' && buf[8]=='d' && buf[9]=='o' &&
        buf[10]=='w' && buf[11]==0)
        return 1;

    if (buf[0]=='/' && buf[1]=='e' && buf[2]=='t' && buf[3]=='c' && buf[4]=='/' &&
        buf[5]=='g' && buf[6]=='s' && buf[7]=='h' && buf[8]=='a' && buf[9]=='d' &&
        buf[10]=='o' && buf[11]=='w')
        return 1;

    #pragma unroll
    for (int i = 0; i < 48; i++) {
        if (buf[i] == 0)
            break;
        if (buf[i]=='i' && buf[i+1]=='d' && buf[i+2]=='_') {
            if (buf[i+3]=='r' && buf[i+4]=='s' && buf[i+5]=='a')
                return 1;
            if (buf[i+3]=='e' && buf[i+4]=='d' && buf[i+5]=='2') // id_ed25519
                return 1;
            if (buf[i+3]=='e' && buf[i+4]=='c' && buf[i+5]=='d') // id_ecdsa
                return 1;
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[1];

    char buf[64] = {};
    if (!is_cred_file(filename, buf))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->tgid         = bpf_get_current_pid_tgid() & 0xffffffff;
    e->uid          = bpf_get_current_uid_gid() >> 32;
    e->gid          = bpf_get_current_uid_gid() & 0xffffffff;
    e->event_type   = EVENT_CRED_ACCESS;
    e->severity     = SEV_HIGH;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (e->uid != 0)
        e->severity = SEV_CRITICAL;

    e->data.kernel.addr = 0;
    __builtin_memset(e->data.kernel.name, 0, sizeof(e->data.kernel.name));
    bpf_probe_read_user_str(e->data.kernel.name, sizeof(e->data.kernel.name), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
