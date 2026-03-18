// net_connect.c - monitora conexões TCP/UDP de saída (connect syscall)
//
// CRITICAL se o processo for shell ou ferramenta ofensiva conhecida.
// INFO para tudo o mais — não queremos ruído de conexões legítimas.

#include "../headers/common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct sockaddr_min {
    __u16 sa_family;
};

struct sockaddr_in_t {
    __u16 sin_family;
    __u16 sin_port;    // network byte order
    __u8  sin_addr[4];
};

struct sockaddr_in6_t {
    __u16  sin6_family;
    __u16  sin6_port;
    __u32  sin6_flowinfo;
    __u8   sin6_addr[16];
};

static __always_inline int is_suspicious_comm(const char comm[16])
{
    if (comm[0]=='b'&&comm[1]=='a'&&comm[2]=='s'&&comm[3]=='h'&&comm[4]==0) return 1;
    if (comm[0]=='s'&&comm[1]=='h'&&comm[2]==0)                              return 1;
    if (comm[0]=='d'&&comm[1]=='a'&&comm[2]=='s'&&comm[3]=='h'&&comm[4]==0) return 1;
    if (comm[0]=='z'&&comm[1]=='s'&&comm[2]=='h'&&comm[3]==0)                return 1;
    if (comm[0]=='k'&&comm[1]=='s'&&comm[2]=='h'&&comm[3]==0)                return 1;
    if (comm[0]=='a'&&comm[1]=='s'&&comm[2]=='h'&&comm[3]==0)                return 1;
    if (comm[0]=='b'&&comm[1]=='u'&&comm[2]=='s'&&comm[3]=='y'&&
        comm[4]=='b'&&comm[5]=='o'&&comm[6]=='x'&&comm[7]==0)                return 1;
    if (comm[0]=='n'&&comm[1]=='c'&&comm[2]==0)                              return 1;
    if (comm[0]=='n'&&comm[1]=='c'&&comm[2]=='a'&&comm[3]=='t'&&comm[4]==0) return 1;
    if (comm[0]=='n'&&comm[1]=='e'&&comm[2]=='t'&&comm[3]=='c'&&
        comm[4]=='a'&&comm[5]=='t'&&comm[6]==0)                              return 1;
    if (comm[0]=='s'&&comm[1]=='o'&&comm[2]=='c'&&comm[3]=='a'&&
        comm[4]=='t'&&comm[5]==0)                                            return 1;
    if (comm[0]=='n'&&comm[1]=='m'&&comm[2]=='a'&&comm[3]=='p'&&comm[4]==0) return 1;
    if (comm[0]=='p'&&comm[1]=='y'&&comm[2]=='t'&&comm[3]=='h'&&
        comm[4]=='o'&&comm[5]=='n'&&(comm[6]==0||comm[6]=='3'||comm[6]=='2')) return 1;
    if (comm[0]=='p'&&comm[1]=='e'&&comm[2]=='r'&&comm[3]=='l'&&comm[4]==0) return 1;
    if (comm[0]=='r'&&comm[1]=='u'&&comm[2]=='b'&&comm[3]=='y'&&comm[4]==0) return 1;
    if (comm[0]=='p'&&comm[1]=='h'&&comm[2]=='p'&&comm[3]==0)               return 1;
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint_connect(struct trace_event_raw_sys_enter *ctx)
{
    void *uaddr = (void *)ctx->args[1];
    struct sockaddr_min sa_min = {};
    struct event *e;
    char comm[16];

    if (!uaddr)
        return 0;

    if (bpf_probe_read_user(&sa_min, sizeof(sa_min), uaddr) < 0)
        return 0;

#define AF_INET  2
#define AF_INET6 10
    if (sa_min.sa_family != AF_INET && sa_min.sa_family != AF_INET6)
        return 0;

    bpf_get_current_comm(comm, sizeof(comm));

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->tgid         = bpf_get_current_pid_tgid() & 0xffffffff;
    e->uid          = bpf_get_current_uid_gid() >> 32;
    e->gid          = bpf_get_current_uid_gid() & 0xffffffff;
    e->event_type   = EVENT_NET_CONNECT;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->data.net.family     = sa_min.sa_family;
    e->data.net.suspicious = is_suspicious_comm(comm);
    e->severity = e->data.net.suspicious ? SEV_CRITICAL : SEV_INFO;

    if (sa_min.sa_family == AF_INET) {
        struct sockaddr_in_t sa4 = {};
        if (bpf_probe_read_user(&sa4, sizeof(sa4), uaddr) < 0)
            goto submit;
        e->data.net.dport     = sa4.sin_port;
        e->data.net.daddr[0]  = sa4.sin_addr[0];
        e->data.net.daddr[1]  = sa4.sin_addr[1];
        e->data.net.daddr[2]  = sa4.sin_addr[2];
        e->data.net.daddr[3]  = sa4.sin_addr[3];
    } else {
        struct sockaddr_in6_t sa6 = {};
        if (bpf_probe_read_user(&sa6, sizeof(sa6), uaddr) < 0)
            goto submit;
        e->data.net.dport = sa6.sin6_port;
        __builtin_memcpy(e->data.net.daddr6, sa6.sin6_addr, 16);
    }

submit:
    bpf_ringbuf_submit(e, 0);
    return 0;
}
