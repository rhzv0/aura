package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type DatadogNotifier struct {
	apiKey string
	minSev Severity
	client *http.Client
	site   string
}

func NewDatadogNotifier(apiKey string, minSev Severity, site string) *DatadogNotifier {
	if site == "" {
		site = "datadoghq.com"
	}
	return &DatadogNotifier{
		apiKey: apiKey,
		minSev: minSev,
		site:   site,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func (d *DatadogNotifier) MinSeverity() Severity { return d.minSev }

func (d *DatadogNotifier) Notify(a Alert) error {
	alertType := "info"
	switch a.Severity {
	case SevCritical:
		alertType = "error"
	case SevHigh, SevMedium:
		alertType = "warning"
	}

	tags := []string{
		"source:aura",
		fmt.Sprintf("severity:%s", a.Severity),
		fmt.Sprintf("event_type:%s", a.Type),
		fmt.Sprintf("comm:%s", a.Comm),
		fmt.Sprintf("pid:%d", a.PID),
	}

	payload := map[string]any{
		"title":            fmt.Sprintf("[AURA] %s — %s", a.Type, a.Comm),
		"text":             a.Description,
		"alert_type":       alertType,
		"source_type_name": "aura-ebpf",
		"tags":             tags,
		"date_happened":    a.Timestamp.Unix(),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	url := fmt.Sprintf("https://api.%s/api/v1/events", d.site)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", d.apiKey)

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("datadog API returned %d", resp.StatusCode)
	}
	return nil
}
