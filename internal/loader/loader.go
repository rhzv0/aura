package loader

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/ebpf-detect/aura/internal/alerts"
	"github.com/ebpf-detect/aura/internal/mitigate"
	"github.com/ebpf-detect/aura/internal/mitre"
)

// Espelho do enum event_type do C
const (
	evtPrivesc        = 1
	_                 = 2 // reservado para probe eBPF de processo oculto (futuro)
	evtModuleHidden   = 3
	evtSuspiciousMmap = 4
	evtBpfLoad        = 5
	evtSyscallHook    = 6
	evtNetConnect     = 7
	evtReverseShell   = 8
	evtExec           = 9
	evtCredAccess     = 10
)

// rawEvent espelha struct event do C. Layout fixo, little-endian.
// Total: 120 bytes. Data[72] corresponde ao maior membro do union (kernel{}).
type rawEvent struct {
	TimestampNs uint64
	Pid         uint32
	Tgid        uint32
	Uid         uint32
	Gid         uint32
	Comm        [16]byte
	EventType   uint8
	Severity    uint8
	Pad         [6]byte
	Data        [72]byte
}

type Detector struct {
	privescObjs      PrivescObjects
	memAnomalyObjs   MemoryAnomalyObjects
	bpfDefenseObjs   BpfdefenseObjects
	netConnectObjs   NetConnectObjects
	reverseShellObjs ReverseShellObjects
	moduleLoadObjs   ModuleLoadObjects
	execTraceObjs    ExecTraceObjects
	credAccessObjs   CredAccessObjects

	links      []link.Link
	readers    []*ringbuf.Reader
	printer    *alerts.Printer
	whitelist  *alerts.Whitelist
	hiddenProc *HiddenProcDetector
	mitigateOn bool
	selfPID    uint32
	bootOffset int64
}

// calcBootOffset calcula a diferença entre CLOCK_REALTIME e CLOCK_MONOTONIC
// uma única vez no startup, para converter timestamps do eBPF para wall clock.
func calcBootOffset() int64 {
	var mono, real unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono)
	unix.ClockGettime(unix.CLOCK_REALTIME, &real)
	monoNs := mono.Sec*1e9 + int64(mono.Nsec)
	realNs := real.Sec*1e9 + int64(real.Nsec)
	return realNs - monoNs
}

func New(cfg alerts.Config, wl *alerts.Whitelist, mitigateOn bool) (*Detector, error) {
	p, err := alerts.NewPrinter(cfg)
	if err != nil {
		return nil, err
	}
	return &Detector{
		printer:    p,
		whitelist:  wl,
		hiddenProc: NewHiddenProcDetector(p),
		mitigateOn: mitigateOn,
		selfPID:    uint32(os.Getpid()),
		bootOffset: calcBootOffset(),
	}, nil
}

func (d *Detector) Load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("rlimit: %w", err)
	}

	if err := d.loadPrivesc(); err != nil {
		return fmt.Errorf("privesc probe: %w", err)
	}
	if err := d.loadMemoryAnomaly(); err != nil {
		return fmt.Errorf("memory anomaly probe: %w", err)
	}
	if err := d.loadBpfDefense(); err != nil {
		return fmt.Errorf("bpf defense probe: %w", err)
	}
	if err := d.loadNetConnect(); err != nil {
		return fmt.Errorf("net connect probe: %w", err)
	}
	if err := d.loadReverseShell(); err != nil {
		return fmt.Errorf("reverse shell probe: %w", err)
	}
	if err := d.loadModuleLoad(); err != nil {
		return fmt.Errorf("module load probe: %w", err)
	}
	if err := d.loadExecTrace(); err != nil {
		return fmt.Errorf("exec trace probe: %w", err)
	}
	if err := d.loadCredAccess(); err != nil {
		return fmt.Errorf("cred access probe: %w", err)
	}
	return nil
}

func (d *Detector) loadPrivesc() error {
	if err := LoadPrivescObjects(&d.privescObjs, nil); err != nil {
		return err
	}
	l, err := link.Kprobe("commit_creds", d.privescObjs.KprobeCommitCreds, nil)
	if err != nil {
		return fmt.Errorf("kprobe commit_creds: %w", err)
	}
	d.links = append(d.links, l)

	rd, err := ringbuf.NewReader(d.privescObjs.Events)
	if err != nil {
		return err
	}
	d.readers = append(d.readers, rd)
	return nil
}

func (d *Detector) loadMemoryAnomaly() error {
	if err := LoadMemoryAnomalyObjects(&d.memAnomalyObjs, nil); err != nil {
		return err
	}

	mmapLink, err := link.Tracepoint("syscalls", "sys_enter_mmap", d.memAnomalyObjs.TracepointMmap, nil)
	if err != nil {
		return fmt.Errorf("tracepoint mmap: %w", err)
	}
	d.links = append(d.links, mmapLink)

	mprotLink, err := link.Tracepoint("syscalls", "sys_enter_mprotect", d.memAnomalyObjs.TracepointMprotect, nil)
	if err != nil {
		return fmt.Errorf("tracepoint mprotect: %w", err)
	}
	d.links = append(d.links, mprotLink)

	rd, err := ringbuf.NewReader(d.memAnomalyObjs.Events)
	if err != nil {
		return err
	}
	d.readers = append(d.readers, rd)
	return nil
}

func (d *Detector) loadBpfDefense() error {
	if err := LoadBpfdefenseObjects(&d.bpfDefenseObjs, nil); err != nil {
		return err
	}
	l, err := link.Tracepoint("syscalls", "sys_enter_bpf", d.bpfDefenseObjs.TracepointBpfLoad, nil)
	if err != nil {
		return fmt.Errorf("tracepoint bpf: %w", err)
	}
	d.links = append(d.links, l)

	rd, err := ringbuf.NewReader(d.bpfDefenseObjs.Events)
	if err != nil {
		return err
	}
	d.readers = append(d.readers, rd)
	return nil
}

func (d *Detector) loadNetConnect() error {
	if err := LoadNetConnectObjects(&d.netConnectObjs, nil); err != nil {
		return err
	}
	l, err := link.Tracepoint("syscalls", "sys_enter_connect", d.netConnectObjs.TracepointConnect, nil)
	if err != nil {
		return fmt.Errorf("tracepoint connect: %w", err)
	}
	d.links = append(d.links, l)

	rd, err := ringbuf.NewReader(d.netConnectObjs.Events)
	if err != nil {
		return err
	}
	d.readers = append(d.readers, rd)
	return nil
}

func (d *Detector) loadReverseShell() error {
	if err := LoadReverseShellObjects(&d.reverseShellObjs, nil); err != nil {
		return err
	}

	exitSock, err := link.Tracepoint("syscalls", "sys_exit_socket", d.reverseShellObjs.TpExitSocket, nil)
	if err != nil {
		return fmt.Errorf("tracepoint exit_socket: %w", err)
	}
	d.links = append(d.links, exitSock)

	enterDup3, err := link.Tracepoint("syscalls", "sys_enter_dup3", d.reverseShellObjs.TpEnterDup3, nil)
	if err != nil {
		return fmt.Errorf("tracepoint enter_dup3: %w", err)
	}
	d.links = append(d.links, enterDup3)

	// v3: hook de execve para confirmação do 3º estágio
	enterExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", d.reverseShellObjs.TpExecRshell, nil)
	if err != nil {
		return fmt.Errorf("tracepoint execve (rshell): %w", err)
	}
	d.links = append(d.links, enterExecve)

	rd, err := ringbuf.NewReader(d.reverseShellObjs.Events)
	if err != nil {
		return err
	}
	d.readers = append(d.readers, rd)
	return nil
}

func (d *Detector) loadModuleLoad() error {
	if err := LoadModuleLoadObjects(&d.moduleLoadObjs, nil); err != nil {
		return err
	}
	l, err := link.Kprobe("do_init_module", d.moduleLoadObjs.KprobeDoInitModule, nil)
	if err != nil {
		return fmt.Errorf("kprobe do_init_module: %w", err)
	}
	d.links = append(d.links, l)

	rd, err := ringbuf.NewReader(d.moduleLoadObjs.Events)
	if err != nil {
		return err
	}
	d.readers = append(d.readers, rd)
	return nil
}

func (d *Detector) loadExecTrace() error {
	if err := LoadExecTraceObjects(&d.execTraceObjs, nil); err != nil {
		return err
	}
	l, err := link.Tracepoint("syscalls", "sys_enter_execve", d.execTraceObjs.TracepointExecve, nil)
	if err != nil {
		return fmt.Errorf("tracepoint execve: %w", err)
	}
	d.links = append(d.links, l)

	rd, err := ringbuf.NewReader(d.execTraceObjs.Events)
	if err != nil {
		return err
	}
	d.readers = append(d.readers, rd)
	return nil
}

func (d *Detector) loadCredAccess() error {
	if err := LoadCredAccessObjects(&d.credAccessObjs, nil); err != nil {
		return err
	}
	l, err := link.Tracepoint("syscalls", "sys_enter_openat", d.credAccessObjs.TpOpenat, nil)
	if err != nil {
		return fmt.Errorf("tracepoint openat (cred_access): %w", err)
	}
	d.links = append(d.links, l)

	rd, err := ringbuf.NewReader(d.credAccessObjs.Events)
	if err != nil {
		return err
	}
	d.readers = append(d.readers, rd)
	return nil
}

func (d *Detector) PrintStats() { d.printer.PrintStats() }

func (d *Detector) Printer() *alerts.Printer { return d.printer }

func (d *Detector) Close() {
	for _, r := range d.readers {
		r.Close()
	}
	for _, l := range d.links {
		l.Close()
	}
	d.privescObjs.Close()
	d.memAnomalyObjs.Close()
	d.bpfDefenseObjs.Close()
	d.netConnectObjs.Close()
	d.reverseShellObjs.Close()
	d.moduleLoadObjs.Close()
	d.execTraceObjs.Close()
	d.credAccessObjs.Close()
	d.printer.Close()
}

func (d *Detector) Run(stop <-chan struct{}) error {
	errCh := make(chan error, len(d.readers))

	go d.hiddenProc.Run(stop)

	for _, rd := range d.readers {
		go func(r *ringbuf.Reader) {
			for {
				rec, err := r.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					errCh <- err
					return
				}
				d.handleRecord(rec.RawSample)
			}
		}(rd)
	}

	select {
	case <-stop:
		return nil
	case err := <-errCh:
		return err
	}
}

func (d *Detector) handleRecord(raw []byte) {
	var e rawEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return
	}

	// Ignorar eventos do próprio processo detector
	if e.Pid == d.selfPID {
		return
	}

	comm := nullTermString(e.Comm[:])
	ts := time.Unix(0, int64(e.TimestampNs)+d.bootOffset)
	sev := mapSeverity(e.Severity)

	var a alerts.Alert
	a.Timestamp = ts
	a.Severity = sev
	a.PID = e.Pid
	a.UID = e.Uid
	a.Comm = comm

	switch e.EventType {
	case evtPrivesc:
		oldUID := binary.LittleEndian.Uint32(e.Data[0:4])
		oldGID := binary.LittleEndian.Uint32(e.Data[4:8])
		newUID := binary.LittleEndian.Uint32(e.Data[8:12])
		newGID := binary.LittleEndian.Uint32(e.Data[12:16])
		a.Type = "PRIVESC"
		a.Description = fmt.Sprintf("privilege escalation detected: uid %d→%d", oldUID, newUID)
		a.Details = map[string]any{
			"old_uid": oldUID, "old_gid": oldGID,
			"new_uid": newUID, "new_gid": newGID,
		}

	case evtSuspiciousMmap:
		addr   := binary.LittleEndian.Uint64(e.Data[0:8])
		length := binary.LittleEndian.Uint64(e.Data[8:16])
		prot   := binary.LittleEndian.Uint32(e.Data[16:20])
		flags  := binary.LittleEndian.Uint32(e.Data[20:24])
		a.Type = "MEMORY_ANOMALY"
		a.Description = "RWX anonymous memory mapping"
		a.Details = map[string]any{
			"addr":  fmt.Sprintf("0x%x", addr),
			"len":   length,
			"prot":  fmt.Sprintf("0x%x", prot),
			"flags": fmt.Sprintf("0x%x", flags),
		}

	case evtBpfLoad:
		progType := binary.LittleEndian.Uint32(e.Data[0:4])
		insnCnt  := binary.LittleEndian.Uint32(e.Data[4:8])
		a.Type = "BPF_LOAD"
		a.Description = fmt.Sprintf("eBPF program loaded (type=%d, insns=%d)", progType, insnCnt)
		a.Details = map[string]any{
			"prog_type": progType,
			"insn_cnt":  insnCnt,
		}

	case evtNetConnect:
		// layout net: daddr[4] | dport[2] | family[2] | daddr6[16] | suspicious[1] | pad[3]
		family     := binary.LittleEndian.Uint16(e.Data[6:8])
		dport      := binary.BigEndian.Uint16(e.Data[4:6])
		suspicious := e.Data[24]
		var dst string
		if family == 10 {
			dst = fmt.Sprintf("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%d",
				e.Data[8], e.Data[9], e.Data[10], e.Data[11],
				e.Data[12], e.Data[13], e.Data[14], e.Data[15],
				e.Data[16], e.Data[17], e.Data[18], e.Data[19],
				e.Data[20], e.Data[21], e.Data[22], e.Data[23],
				dport)
		} else {
			dst = fmt.Sprintf("%d.%d.%d.%d:%d", e.Data[0], e.Data[1], e.Data[2], e.Data[3], dport)
		}
		a.Type = "NET_CONNECT"
		a.Description = fmt.Sprintf("outbound connection → %s", dst)
		if suspicious == 1 {
			a.Description = fmt.Sprintf("shell/tool outbound connection → %s", dst)
		}
		a.Details = map[string]any{"dst": dst}

	case evtReverseShell:
		oldfd := binary.LittleEndian.Uint32(e.Data[0:4])
		newfd := binary.LittleEndian.Uint32(e.Data[4:8])
		a.Type = "REVERSE_SHELL"
		if newfd == 0xFF {
			// v3: confirmação pelos 3 estágios (socket + dup3 + execve)
			rshellPath := nullTermString(e.Data[8:40])
			a.Description = fmt.Sprintf("confirmed reverse shell: socket fd=%d, exec=%s", oldfd, rshellPath)
			a.Details = map[string]any{
				"socket_fd": oldfd,
				"exec_path": rshellPath,
				"confirmed": true,
			}
		} else {
			// detecção de 2 estágios (legado)
			fdName := map[uint32]string{0: "stdin", 1: "stdout", 2: "stderr"}
			a.Description = fmt.Sprintf("socket fd=%d redirected to %s (fd %d)", oldfd, fdName[newfd], newfd)
			a.Details = map[string]any{
				"socket_fd": oldfd,
				"target_fd": fmt.Sprintf("%d (%s)", newfd, fdName[newfd]),
			}
		}

	case evtModuleHidden:
		addr    := binary.LittleEndian.Uint64(e.Data[0:8])
		modName := nullTermString(e.Data[8:72])
		a.Type = "MODULE_LOAD"
		a.Description = fmt.Sprintf("kernel module loaded: %q at 0x%x", modName, addr)
		a.Details = map[string]any{
			"module": modName,
			"addr":   fmt.Sprintf("0x%x", addr),
		}

	case evtExec:
		path := nullTermString(e.Data[8:72])
		ppid := uint32(binary.LittleEndian.Uint64(e.Data[0:8]) >> 32)
		a.Type = "EXEC"
		a.Description = fmt.Sprintf("execve: %s", path)
		a.Details = map[string]any{"path": path, "ppid": ppid}
		d.hiddenProc.Track(e.Pid, comm)

	case evtCredAccess:
		path := nullTermString(e.Data[8:72])
		a.Type = "CRED_ACCESS"
		a.Description = fmt.Sprintf("credential file accessed: %s", path)
		a.Details = map[string]any{"path": path}

	default:
		return
	}

	tech := mitre.Lookup(a.Type)
	a.Technique = tech.ID
	a.Tactic = tech.Tactic

	if d.whitelist != nil && !d.whitelist.Allow(a) {
		return
	}

	d.printer.Emit(a)

	if d.mitigateOn && a.Severity == alerts.SevCritical {
		shouldKill := false
		switch a.Type {
		case "REVERSE_SHELL":
			shouldKill = true
		case "PRIVESC":
			if details, ok := a.Details["old_uid"]; ok {
				if uid, ok := details.(uint32); ok && uid != 0 {
					shouldKill = true
				}
			}
		}
		if shouldKill {
			if err := mitigate.KillProcess(a.PID); err != nil {
				fmt.Fprintf(os.Stderr, "[mitigate] kill pid %d failed: %v\n", a.PID, err)
			} else {
				fmt.Fprintf(os.Stderr, "[mitigate] killed pid %d (%s: %s)\n", a.PID, a.Type, a.Comm)
			}
		}
	}
}

func nullTermString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func mapSeverity(s uint8) alerts.Severity {
	switch s {
	case 4:
		return alerts.SevCritical
	case 3:
		return alerts.SevHigh
	case 2:
		return alerts.SevMedium
	default:
		return alerts.SevInfo
	}
}
