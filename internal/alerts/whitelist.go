package alerts

import "strings"

type Whitelist struct {
	comms []string
}

func NewWhitelist(comms []string) *Whitelist {
	return &Whitelist{comms: comms}
}

func (w *Whitelist) Allow(a Alert) bool {
	for _, c := range w.comms {
		if strings.EqualFold(a.Comm, c) {
			return false
		}
	}
	return true
}
