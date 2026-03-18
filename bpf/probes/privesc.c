// privesc.c - detecta escalada de privilégio via commit_creds
//
// commit_creds é chamada toda vez que um processo adota novas credenciais.
// Hookar aqui captura o momento exato da troca — detecta dirty pipe
// (CVE-2022-0847), dirty cred, e exploits locais em geral.

#include "../headers/common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("kprobe/commit_creds")
int BPF_KPROBE(kprobe_commit_creds, struct cred *new)
{
    struct task_struct *task;
    struct cred *old;
    __u32 old_uid, old_gid, new_uid, new_gid;
    __u32 pid, tgid, uid, gid;
    struct event *e;

    task = (struct task_struct *)bpf_get_current_task();

    old = (struct cred *)BPF_CORE_READ(task, cred);
    old_uid = BPF_CORE_READ(old, uid.val);
    old_gid = BPF_CORE_READ(old, gid.val);
    new_uid = BPF_CORE_READ(new, uid.val);
    new_gid = BPF_CORE_READ(new, gid.val);

    /*
     * Só nos interessa old_uid != 0 E new_uid == 0.
     * Se old_uid já é 0, é sudo/setuid dropando privilégio — ruído.
     * Se new_uid != 0, não é escalada para root.
     */
    if (old_uid == 0 || new_uid != 0)
        return 0;

    pid  = bpf_get_current_pid_tgid() >> 32;
    tgid = bpf_get_current_pid_tgid() & 0xffffffff;
    uid  = bpf_get_current_uid_gid() >> 32;
    gid  = bpf_get_current_uid_gid() & 0xffffffff;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = pid;
    e->tgid         = tgid;
    e->uid          = uid;
    e->gid          = gid;
    e->event_type   = EVENT_PRIVESC;
    e->severity     = SEV_CRITICAL;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->data.privesc.old_uid = old_uid;
    e->data.privesc.old_gid = old_gid;
    e->data.privesc.new_uid = new_uid;
    e->data.privesc.new_gid = new_gid;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
