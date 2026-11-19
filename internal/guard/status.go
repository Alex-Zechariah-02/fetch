// The guard's counters on the API's control listener: requests in flight,
// refusals for overload and a full rate table, rate counters held, records
// lost and the active log's size, which the log itself cannot show when it
// fails.

package guard

import (
	"encoding/json"
	"net/http"
)

// Status serves GET /guard on the API's control listener (behind its secret).
func (g *Guard) Status(w http.ResponseWriter, _ *http.Request) {
	data, err := json.Marshal(map[string]any{
		"api":                g.api,
		"in_flight":          g.inFlight.Load(),
		"max_in_flight":      maxInFlight,
		"refused_overloaded": g.overloads.Load(),
		"refused_capacity":   g.capacity.Load(),
		"rate_counters":      g.limiter.size(),
		"max_rate_counters":  maxCounters,
		"log_bytes":          g.log.written.Load(),
		"log_records_lost":   g.log.dropped.Load(),
		"log_failed":         g.log.failed.Load(),
		"blocked_accounts":   len(*g.blocked.Load()),
	})
	if err != nil {
		http.Error(w, "status unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(append(data, '\n'))
}
