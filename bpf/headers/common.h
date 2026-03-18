#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

enum event_type {
    EVENT_PRIVESC          = 1,
    EVENT_PROCESS_HIDDEN   = 2,
    EVENT_MODULE_HIDDEN    = 3,
    EVENT_SUSPICIOUS_MMAP  = 4,
    EVENT_BPF_LOAD         = 5,
    EVENT_SYSCALL_HOOK     = 6,
    EVENT_NET_CONNECT      = 7,
    EVENT_REVERSE_SHELL    = 8,
    EVENT_EXEC             = 9,
    EVENT_CRED_ACCESS      = 10,
};

enum event_severity {
    SEV_INFO    = 1,
    SEV_MEDIUM  = 2,
    SEV_HIGH    = 3,
    SEV_CRITICAL = 4,
};

/*
 * Layout fixo: 120 bytes. Qualquer mudança aqui exige atualizar
 * rawEvent em internal/loader/loader.go (campo Data [72]byte).
 */
struct event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u8  comm[16];
    __u8  event_type;
    __u8  severity;
    // pad explícito: offset até aqui = 42, precisamos chegar em 48 → 6 bytes
    __u8  pad[6];

    union {
        struct {
            __u32 old_uid;
            __u32 old_gid;
            __u32 new_uid;
            __u32 new_gid;
        } privesc;

        struct {
            __u64 addr;
            __u64 len;
            __u32 prot;
            __u32 flags;
        } mmap;

        struct {
            __u32 prog_type;
            __u32 insn_cnt;
        } bpf_load;

        /* maior membro do union — define o tamanho total (72 bytes) */
        struct {
            __u64 addr;
            __u8  name[64];
        } kernel;

        /* IPs e porta em network byte order (big-endian) */
        struct {
            __u8  daddr[4];
            __u16 dport;
            __u16 family;
            __u8  daddr6[16];
            __u8  suspicious;
            __u8  _pad[3];
        } net;

        /* v3: path adicionado aqui para a detecção em 3 estágios */
        struct {
            __u32 oldfd;
            __u32 newfd;  // 0xFF = confirmação via execve
            char  path[32];
        } rshell;
    } data;
};
