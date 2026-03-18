package alerts

import (
	"fmt"
	"net/smtp"
	"strings"
	"time"
)

type EmailNotifier struct {
	smtpAddr string
	from     string
	to       []string
	minSev   Severity
}

func NewEmailNotifier(smtpAddr, from string, to []string, minSev Severity) *EmailNotifier {
	return &EmailNotifier{smtpAddr: smtpAddr, from: from, to: to, minSev: minSev}
}

func (e *EmailNotifier) MinSeverity() Severity { return e.minSev }

func (e *EmailNotifier) Notify(a Alert) error {
	subject := fmt.Sprintf("AURA ALERT [%s] %s on %s", a.Severity, a.Type, a.Comm)
	body := fmt.Sprintf(
		"Timestamp: %s\nSeverity: %s\nType: %s\nPID: %d\nUID: %d\nProcess: %s\nDescription: %s\n",
		a.Timestamp.Format(time.RFC3339), a.Severity, a.Type, a.PID, a.UID, a.Comm, a.Description,
	)
	msg := "From: " + e.from + "\r\n" +
		"To: " + strings.Join(e.to, ", ") + "\r\n" +
		"Subject: " + subject + "\r\n\r\n" +
		body
	return smtp.SendMail(e.smtpAddr, nil, e.from, e.to, []byte(msg))
}
