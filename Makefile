# Aura v4.0.16 — eBPF Threat Detection Engine
#
# Pré-requisitos no host de build (x86_64, Ubuntu 22.04+):
#   sudo apt install clang-14 llvm-14 libbpf-dev
#   sudo snap install go --classic
#
# IMPORTANTE: bpf/headers/vmlinux.h deve vir do kernel onde Aura vai rodar:
#   sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h
#
# Os bindings gerados (*_bpfel.go, *.o) já estão commitados.
# Só regenerar se modificar os probes .c (requer host x86_64 com clang-14):
#   go generate ./internal/loader/

GO      ?= go
CLANG   ?= clang-14
VERSION ?= v4.0.16

BINARY  = aura-$(VERSION)-x86_64
CTL_BIN = aura-ctl-$(VERSION)-x86_64
OUTDIR  = ../bin

.PHONY: all generate build build-ctl clean install

all: build build-ctl

generate:
	@echo "[1/3] Compilando probes eBPF e gerando bindings..."
	$(GO) generate ./internal/loader/

build:
	@echo "[2/3] Compilando daemon Aura..."
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags="-s -w" -trimpath -o $(OUTDIR)/$(BINARY) ./cmd/aura/
	@ls -lh $(OUTDIR)/$(BINARY)

build-ctl:
	@echo "[3/3] Compilando aura-ctl..."
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags="-s -w" -trimpath -o $(OUTDIR)/$(CTL_BIN) ./cmd/aura-ctl/
	@ls -lh $(OUTDIR)/$(CTL_BIN)

clean:
	rm -f internal/loader/*_bpfel.go internal/loader/*_bpfeb.go
	rm -f internal/loader/*.o

install: build build-ctl
	mkdir -p /opt/aura/bin /var/log/aura
	cp $(OUTDIR)/$(BINARY) /opt/aura/bin/$(BINARY)
	cp $(OUTDIR)/$(CTL_BIN) /opt/aura/bin/$(CTL_BIN)
	ln -sf /opt/aura/bin/$(BINARY) /opt/aura/bin/aura-current
	ln -sf /opt/aura/bin/$(CTL_BIN) /opt/aura/bin/aura-ctl
	@echo "Instalado. Execute: systemctl start aura"
