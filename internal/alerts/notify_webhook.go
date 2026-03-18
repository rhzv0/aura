package alerts

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

type WebhookNotifier struct {
	url    string
	minSev Severity
	client *http.Client
}

func NewWebhookNotifier(url string, minSev Severity) *WebhookNotifier {
	return &WebhookNotifier{
		url:    url,
		minSev: minSev,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func (w *WebhookNotifier) MinSeverity() Severity { return w.minSev }

func (w *WebhookNotifier) Notify(a Alert) error {
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	resp, err := w.client.Post(w.url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
