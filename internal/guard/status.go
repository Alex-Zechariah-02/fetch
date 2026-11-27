// The guard's counters on the API's control listener: requests in flight,
// refusals for overload and a full rate table, rate counters held, records
// lost, the active log's size and the log's archive and disks, which the
// log itself cannot show when it fails.

package guard

import (
	"encoding/json"
	"net/http"
)

// Status serves GET /guard on the API's control listener (behind its secret).
func (g *Guard) Status(w http.ResponseWriter, _ *http.Request) {
	fields := map[string]any{
		"api":                g.api,
		"in_flight":          g.inFlight.Load(),
		"max_in_flight":      maxInFlight,
		"refused_overloaded": g.overloads.Load(),
		"refused_capacity":   g.capacity.Load(),
		"rate_counters":      g.limiter.size(),
		"max_rate_counters":  maxCounters,
		"log_bytes":          g.log.written.Load(),
		"log_records_lost":   g.log.dropped.Load(),
		"log_failed":         g.log.unavailable(),
		"log_recoveries":     g.log.recoveries.Load(),
		"log_slow_saves":     g.log.slow.Load(),
		"blocked_accounts":   len(*g.blocked.Load()),
	}
	if r := g.log.archive; r != nil {
		fields["log_archive_ok"] = r.usable.Load()
		fields["log_archive_bytes"] = r.stored.Load()
		fields["log_archive_budget_bytes"] = r.budget
		fields["log_pending_files"] = r.waiting.Load()
		fields["log_free_bytes"] = map[string]int64{"log": r.freeLog.Load(), "archive": r.freeArchive.Load()}
		fields["log_reserve_bytes"] = r.held.Load()
		fields["log_evictions"] = r.evictions.Load()
		fields["log_pressure_evictions"] = r.pressure.Load()
	}
	data, err := json.Marshal(fields)
	if err != nil {
		http.Error(w, "status unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(append(data, '\n'))
}
