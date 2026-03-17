# Aura v4.0.16

eBPF threat detection with kill chain correlation and MITRE ATT&CK mapping.

Signed by rhzv0.

---

## How it works

Aura loads 8 eBPF probes directly into the Linux kernel. Each probe hooks a specific syscall or kernel function via tracepoints and kprobes, reads the relevant data in-kernel using CO-RE (Compile Once, Run Everywhere), and ships it to userspace through a ring buffer — zero disk I/O, zero missed events.

In userspace, a correlation engine tracks events per process tree. When a sequence of events matches a known attack pattern, Aura emits a kill chain alert with the full context. Every alert is tagged with its MITRE ATT&CK technique and tactic.

```
kernel space                         userspace
────────────────────────────────     ─────────────────────────────────────
kprobe/commit_creds              →   PRIVESC         [T1068]
tracepoint/mmap + mprotect       →   MEMORY_ANOMALY  [T1055]
tracepoint/bpf()                 →   BPF_LOAD        [T1014]
tracepoint/connect()             →   NET_CONNECT     [T1071.001]
socket → dup3 → execve (3-stage) →   REVERSE_SHELL   [T1059.004]
kprobe/do_init_module            →   MODULE_LOAD     [T1547.006]
tracepoint/execve()              →   EXEC            [T1059]
tracepoint/openat()              →   CRED_ACCESS     [T1003.008]
/proc scan goroutine (5s)        →   HIDDEN_PROCESS  [T1014]
                                 →   KILL_CHAIN      [correlation]
                                 →   RISK_SCORE      [scoring]
```

### Kill chain correlation

The engine tracks events per process tree within a 5-minute window. When a sequence matches a pattern, it emits a KILL_CHAIN alert:

| Pattern | Sequence | Severity |
|---|---|---|
| KILL_CHAIN_LATERAL | NET_CONNECT(CRITICAL) + EXEC + CRED_ACCESS | CRITICAL |
| KILL_CHAIN_PRIVESC_PERSIST | PRIVESC + MODULE_LOAD or EXEC | CRITICAL |
| KILL_CHAIN_FILELESS | MEMORY_ANOMALY + EXEC | HIGH |
| KILL_CHAIN_EBPF_ROOTKIT | BPF_LOAD + NET_CONNECT | CRITICAL |
| KILL_CHAIN_SHELL_ESCALATE | REVERSE_SHELL + PRIVESC or CRED_ACCESS | CRITICAL |

### Risk scoring

Each event adds to a per-process risk score (INFO +1, MEDIUM +5, HIGH +15, CRITICAL +30). Scores decay 20% per minute. Thresholds emit RISK_SCORE alerts at MEDIUM (50), HIGH (100), and CRITICAL (200).

---

## Requirements

- Linux kernel 5.8+ with BTF enabled (`/sys/kernel/btf/vmlinux`)
- Root or `CAP_BPF` + `CAP_SYS_ADMIN`

---

## Install

```bash
# Deploy daemon
sudo cp aura-v4.0.16-x86_64 /usr/local/bin/aura
sudo chmod +x /usr/local/bin/aura

# Deploy control CLI
sudo cp aura-ctl-v4.0.16-x86_64 /usr/local/bin/aura-ctl
sudo chmod +x /usr/local/bin/aura-ctl

# Log directory
sudo mkdir -p /var/log/aura
```

---

## Usage

**Daemon mode:**
```bash
sudo aura \
  -daemon \
  -log /var/log/aura/events.json \
  -level HIGH \
  -wall \
  -whitelist "sshd,sudo,systemd,cron,dockerd,sa1"
```

**Interactive (foreground):**
```bash
sudo aura -log /var/log/aura/events.json
```

**With Datadog:**
```bash
sudo aura -daemon \
  -log /var/log/aura/events.json \
  -datadog-api-key YOUR_KEY \
  -datadog-site datadoghq.com
```

**With webhook (Slack, custom):**
```bash
sudo aura -daemon \
  -log /var/log/aura/events.json \
  -webhook https://hooks.slack.com/services/...
```

**Disable correlation engine:**
```bash
sudo aura -no-correlate -log /var/log/aura/events.json
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-daemon` | false | Run in background |
| `-log FILE` | — | JSON log path |
| `-json` | false | JSON-only output (no color) |
| `-level` | INFO | Minimum severity: INFO / MEDIUM / HIGH / CRITICAL |
| `-wall` | false | Broadcast CRITICAL events to all terminals |
| `-whitelist` | — | Comma-separated process names to ignore |
| `-webhook URL` | — | HTTP POST endpoint (JSON) |
| `-email-to` | — | Alert recipient |
| `-email-smtp` | — | SMTP server address |
| `-datadog-api-key` | — | Datadog Events API key |
| `-datadog-site` | datadoghq.com | Datadog site |
| `-mitigate` | false | Auto-kill process on CRITICAL REVERSE_SHELL / PRIVESC |
| `-no-correlate` | false | Disable kill chain correlation |

---

## aura-ctl

```bash
# Dashboard — daemon status, event counts, kill chains
aura-ctl status

# Real-time event stream
aura-ctl watch
aura-ctl watch --level HIGH

# Show detected kill chains
aura-ctl chains

# Show process risk scores
aura-ctl risks

# Daemon control
aura-ctl stop
aura-ctl start
aura-ctl restart
```

---

## Log format

JSON, one event per line. Compatible with jq, Datadog, Splunk, Elastic.

```json
{
  "timestamp": "2026-03-17T20:48:52Z",
  "type": "REVERSE_SHELL",
  "severity": "CRITICAL",
  "technique": "T1059.004",
  "tactic": "Execution",
  "comm": "kworker/0:1",
  "pid": 1234,
  "uid": 0,
  "description": "reverse shell confirmed via execve: /bin/sh"
}
```

```json
{
  "type": "KILL_CHAIN",
  "severity": "CRITICAL",
  "technique": "Multiple",
  "tactic": "Multiple",
  "description": "Kill chain: C2 callback → execution → credential access",
  "details": {"events": 5, "pattern": "KILL_CHAIN_LATERAL"}
}
```

---

## Systemd

```ini
[Unit]
Description=Aura Threat Detection
After=network.target

[Service]
ExecStart=/usr/local/bin/aura -json -log /var/log/aura/events.json -wall -whitelist sshd,sudo,systemd,cron
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now aura
```

---

rhzv0
