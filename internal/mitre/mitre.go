package mitre

type Technique struct {
	ID     string
	Tactic string
	Name   string
}

var techniques = map[string]Technique{
	"PRIVESC":        {ID: "T1068", Tactic: "Privilege Escalation", Name: "Exploitation for Privilege Escalation"},
	"MEMORY_ANOMALY": {ID: "T1055", Tactic: "Defense Evasion", Name: "Process Injection"},
	"BPF_LOAD":       {ID: "T1014", Tactic: "Defense Evasion", Name: "Rootkit"},
	"NET_CONNECT":    {ID: "T1071.001", Tactic: "Command and Control", Name: "Web Protocols"},
	"REVERSE_SHELL":  {ID: "T1059.004", Tactic: "Execution", Name: "Unix Shell"},
	"MODULE_LOAD":    {ID: "T1547.006", Tactic: "Persistence", Name: "Kernel Modules and Extensions"},
	"EXEC":           {ID: "T1059", Tactic: "Execution", Name: "Command and Scripting Interpreter"},
	"CRED_ACCESS":    {ID: "T1003.008", Tactic: "Credential Access", Name: "/etc/passwd and /etc/shadow"},
	"HIDDEN_PROCESS": {ID: "T1014", Tactic: "Defense Evasion", Name: "Rootkit"},
}

func Lookup(eventType string) Technique {
	return techniques[eventType]
}
