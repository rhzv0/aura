package loader

// go:generate compila cada probe eBPF (.c) e gera os bindings Go (*_bpfel.go + *.o).
// Precisa rodar no host x86_64 com o vmlinux.h do kernel-alvo em bpf/headers/.
// Para regenerar: ssh no EC2, cd /opt/aura/src, go generate ./internal/loader/
//
// Os arquivos *_bpfel.go e *.o já estão commitados — não é necessário regenerar
// a menos que os probes .c sejam modificados.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" Privesc       ../../bpf/probes/privesc.c        -- -I../../bpf/headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" MemoryAnomaly ../../bpf/probes/memory_anomaly.c  -- -I../../bpf/headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" Bpfdefense    ../../bpf/probes/bpf_defense.c     -- -I../../bpf/headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" NetConnect    ../../bpf/probes/net_connect.c     -- -I../../bpf/headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" ReverseShell  ../../bpf/probes/reverse_shell.c   -- -I../../bpf/headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" ModuleLoad    ../../bpf/probes/module_load.c     -- -I../../bpf/headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" ExecTrace     ../../bpf/probes/exec_trace.c      -- -I../../bpf/headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" CredAccess    ../../bpf/probes/cred_access.c     -- -I../../bpf/headers
