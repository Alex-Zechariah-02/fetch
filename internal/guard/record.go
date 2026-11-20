// One security log line: its fields and its encoding as one JSON line.

package guard

import (
	"encoding/json"
	"time"
)

// record is one security log line. Tokens, bodies and queries are never
// recorded.
type record struct {
	Seq          uint64    `json:"seq"`
	Time         time.Time `json:"time"`
	Kind         string    `json:"kind"`
	RequestID    string    `json:"request_id,omitempty"`
	API          string    `json:"api,omitempty"`
	Stage        string    `json:"stage,omitempty"`
	Decision     string    `json:"decision,omitempty"`
	Status       int       `json:"status,omitempty"`
	Error        string    `json:"error,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	Method       string    `json:"method,omitempty"`
	Path         string    `json:"path,omitempty"`
	Operation    string    `json:"operation,omitempty"`
	Subject      string    `json:"subject,omitempty"`
	Roles        []string  `json:"roles,omitempty"`
	IgnoredRoles []string  `json:"ignored_roles,omitempty"`
	Client       string    `json:"client_address,omitempty"`
	DurationMS   float64   `json:"duration_ms,omitempty"`
	Lost         uint64    `json:"lost,omitempty"`
	Accounts     int       `json:"accounts,omitempty"` // blocked list size after a replacement
	// First, Counts and Addresses are a refusal summary's interval start,
	// counts by reason and busiest client addresses.
	First     time.Time         `json:"first,omitzero"`
	Counts    map[string]uint64 `json:"counts,omitempty"`
	Addresses []addressCount    `json:"addresses,omitempty"`
	// File names a log file in log.archived, log.evicted and log.recovered,
	// with its size, SHA-256 and last record time (First is its first);
	// Archived is a compressed size, Target where the file was or went and
	// Offset the end of a replaced file's last synced batch.
	File     string    `json:"file,omitempty"`
	Bytes    int64     `json:"bytes,omitempty"`
	Digest   string    `json:"sha256,omitempty"`
	Last     time.Time `json:"last,omitzero"`
	Archived int64     `json:"archived_bytes,omitempty"`
	Target   string    `json:"target,omitempty"`
	Offset   int64     `json:"offset,omitempty"`
}

func appendRecord(buffer []byte, r *record) []byte {
	line, err := json.Marshal(r)
	if err != nil {
		panic(err) // a record holds only strings, numbers and times
	}
	return append(append(buffer, line...), '\n')
}
