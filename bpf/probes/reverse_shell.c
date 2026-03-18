// reverse_shell.c - detecção de reverse shell em 3 estágios (v3)
//
// Estágio 1: sys_exit_socket  → registra fd retornado pelo socket()
// Estágio 2: sys_enter_dup3   → socket fd duplicado para stdin/stdout/stderr
// Estágio 3: sys_enter_execve → TGID está pendente E o path é um shell
//
// Os 3 estágios eliminam falsos positivos de daemons como sysstat/sa1
// que fazem socket+dup3 mas nunca executam shell nenhum.
//
// ATENÇÃO: sys_enter_dup2 existe só em x86_64. Se um dia precisar
// rodar isso em ARM64, esse hook vai precisar ser removido ou condicional.

#include "../headers/common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// key: ((u64)tgid << 32) | (u32)fd  →  value: 1
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,   __u64);
    __type(value, __u8);
} socket_fds SEC(".maps");

// key: tgid  →  value: socket fd que foi dup'd
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u32);
    __type(value, __u32);
} pending_rshell SEC(".maps");

SEC("tracepoint/syscalls/sys_exit_socket")
int tp_exit_socket(struct trace_event_raw_sys_exit *ctx)
{
    long ret = ctx->ret;
    if (ret < 0)
        return 0;

    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    __u64 key  = ((__u64)tgid << 32) | (__u32)ret;
    __u8  val  = 1;
    bpf_map_update_elem(&socket_fds, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int tp_enter_dup3(struct trace_event_raw_sys_enter *ctx)
{
    __u32 oldfd = (__u32)ctx->args[0];
    __u32 newfd = (__u32)ctx->args[1];

    if (newfd > 2)
        return 0;

    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    __u64 key  = ((__u64)tgid << 32) | oldfd;

    __u8 *tracked = bpf_map_lookup_elem(&socket_fds, &key);
    if (!tracked)
        return 0;

    __u32 tgid_key = tgid;
    __u32 sock_fd  = oldfd;
    bpf_map_update_elem(&pending_rshell, &tgid_key, &sock_fd, BPF_ANY);
    return 0;
}

// dup2 — só existe em x86_64
SEC("tracepoint/syscalls/sys_enter_dup2")
int tp_enter_dup2(struct trace_event_raw_sys_enter *ctx)
{
    __u32 oldfd = (__u32)ctx->args[0];
    __u32 newfd = (__u32)ctx->args[1];

    if (newfd > 2)
        return 0;

    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    __u64 key  = ((__u64)tgid << 32) | oldfd;

    __u8 *tracked = bpf_map_lookup_elem(&socket_fds, &key);
    if (!tracked)
        return 0;

    __u32 tgid_key = tgid;
    __u32 sock_fd  = oldfd;
    bpf_map_update_elem(&pending_rshell, &tgid_key, &sock_fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tp_exec_rshell(struct trace_event_raw_sys_enter *ctx)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    __u32 *sock_fd = bpf_map_lookup_elem(&pending_rshell, &tgid);
    if (!sock_fd)
        return 0;

    const char *filename = (const char *)ctx->args[0];
    char path[64] = {};
    int n = bpf_probe_read_user_str(path, sizeof(path), filename);
    if (n <= 0) {
        bpf_map_delete_elem(&pending_rshell, &tgid);
        return 0;
    }

    int last_slash = -1;
    #pragma unroll
    for (int i = 0; i < 63; i++) {
        if (path[i] == 0)
            break;
        if (path[i] == '/')
            last_slash = i;
    }

    int is_sh = 0;
    if (last_slash >= 0 && last_slash < 57) {
        __u8 b0 = path[last_slash + 1];
        __u8 b1 = (last_slash + 2 < 63) ? path[last_slash + 2] : 0;
        __u8 b2 = (last_slash + 3 < 63) ? path[last_slash + 3] : 0;
        __u8 b3 = (last_slash + 4 < 63) ? path[last_slash + 4] : 0;
        __u8 b4 = (last_slash + 5 < 63) ? path[last_slash + 5] : 0;
        __u8 b5 = (last_slash + 6 < 63) ? path[last_slash + 6] : 0;

        if (b0=='s' && b1=='h' && (b2==0 || b2=='/'))                       is_sh = 1;
        if (b0=='b' && b1=='a' && b2=='s' && b3=='h' && (b4==0 || b4=='/')) is_sh = 1;
        if (b0=='d' && b1=='a' && b2=='s' && b3=='h' && (b4==0 || b4=='/')) is_sh = 1;
        if (b0=='z' && b1=='s' && b2=='h' && (b3==0 || b3=='/'))            is_sh = 1;
        if (b0=='k' && b1=='s' && b2=='h' && (b3==0 || b3=='/'))            is_sh = 1;
        if (b0=='c' && b1=='s' && b2=='h' && (b3==0 || b3=='/'))            is_sh = 1;
        if (b0=='f' && b1=='i' && b2=='s' && b3=='h' && (b4==0 || b4=='/')) is_sh = 1;
        if (b0=='p' && b1=='y' && b2=='t' && b3=='h' && b4=='o' && b5=='n') is_sh = 1;
        if (b0=='n' && b1=='c' && (b2==0 || b2=='/'))                       is_sh = 1;
    }

    if (!is_sh) {
        bpf_map_delete_elem(&pending_rshell, &tgid);
        return 0;
    }

    __u32 saved_fd = *sock_fd;
    bpf_map_delete_elem(&pending_rshell, &tgid);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = tgid;
    e->tgid         = bpf_get_current_pid_tgid() & 0xffffffff;
    e->uid          = bpf_get_current_uid_gid() >> 32;
    e->gid          = bpf_get_current_uid_gid() & 0xffffffff;
    e->event_type   = EVENT_REVERSE_SHELL;
    e->severity     = SEV_CRITICAL;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->data.rshell.oldfd = saved_fd;
    e->data.rshell.newfd = 0xFF; // sinaliza confirmação via execve (v3)
    __builtin_memset(e->data.rshell.path, 0, sizeof(e->data.rshell.path));
    #pragma unroll
    for (int i = 0; i < 31; i++) {
        if (i < 63 && path[i] != 0)
            e->data.rshell.path[i] = path[i];
        else
            break;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
