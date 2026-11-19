// The gateway's process log as demo run reads it: the protected admission
// status the gateway reports at start, then every later change of it. Each
// read continues where the last one ended, and an over-long line is skipped.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// Bounds of one read of gateway.log: 4 MiB of new output at most, and a line
// that reaches 1 MiB without ending is not a gateway record, so it is skipped.
const (
	logChunk = 4 << 20
	logLine  = 1 << 20
)

// gatewayLog reads the gateway's log from offset on, one complete line at a time.
type gatewayLog struct {
	path     string
	offset   int64
	skipping bool // inside an over-long line, until its end
}

// logEvent is the part of a gateway log record that demo run reads.
type logEvent struct {
	Message   string `json:"msg"`
	Admission string `json:"admission"`
	Reason    string `json:"reason"`
	Error     string `json:"error"`
}

// next returns the complete records written since the last call. A partial
// last line is left for the next call.
func (g *gatewayLog) next() ([]logEvent, error) {
	file, err := os.Open(g.path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if _, err := file.Seek(g.offset, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, logChunk))
	if err != nil {
		return nil, err
	}
	var events []logEvent
	for {
		end := bytes.IndexByte(data, '\n')
		if end < 0 {
			break
		}
		line := data[:end]
		g.offset += int64(end + 1)
		data = data[end+1:]
		if g.skipping {
			g.skipping = false
			continue
		}
		var event logEvent
		if json.Unmarshal(line, &event) == nil && event.Message != "" {
			events = append(events, event)
		}
	}
	if len(data) >= logLine {
		g.offset += int64(len(data))
		g.skipping = true
	}
	return events, nil
}

// admission is the status of the start record among events, or "".
func admission(events []logEvent) string {
	for _, event := range events {
		if event.Message == "protected admission" {
			return event.Admission
		}
	}
	return ""
}

// admissionChanges are the lines that tell the operator protected admission
// stopped or resumed after the start, from records such as "protected
// admission unavailable" or "audit log failed; protected admission disabled".
func admissionChanges(events []logEvent) []string {
	var lines []string
	for _, event := range events {
		if event.Message == "protected admission" || !strings.Contains(event.Message, "protected admission") {
			continue
		}
		line := "gateway: " + event.Message
		if detail := strings.TrimSpace(event.Reason + " " + event.Error); detail != "" {
			line += fmt.Sprintf(" (%s)", detail)
		}
		lines = append(lines, line)
	}
	return lines
}
