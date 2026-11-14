// The API's security log: JSON Lines files, rotated at a size bound and
// written by one goroutine in batches, each batch synced to disk. An admission waits for its batch's
// sync before the handler runs; refusals and outcomes are queued without
// waiting and, when they cannot be, counted and written as a loss record.

package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	queueSize = 1024
	batchSize = 128
	// commitWait bounds an admission's wait for its sync (the gateway's
	// default audit wait).
	commitWait = 2 * time.Second
	maxPath    = 512
	// maxMethod is longer than any registered HTTP method; Go accepts any
	// token up to its 1 MiB header limit.
	maxMethod = 32
	// maxLogBytes and logFiles bound the log as the gateway's defaults bound
	// its own (gateway.audit_max_bytes, gateway.audit_max_files), so both
	// protected setups keep the same history.
	maxLogBytes = 64 << 20
	logFiles    = 8
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
}

type entry struct {
	record record
	done   chan error // nil when nobody waits
}

var errLogFailed = errors.New("security log unavailable")

// securityLog owns its file: only run writes, rotates or closes it.
type securityLog struct {
	path   string
	file   *os.File
	size   int64 // bytes in the active file
	limit  int64 // rotation size, maxLogBytes
	queue  chan entry
	seq    atomic.Uint64
	lost   atomic.Uint64
	failed atomic.Bool
	mu     sync.RWMutex // orders queueing against close
	closed bool
	done   chan struct{}
}

// openLog appends to path, creating it private to this user.
func openLog(path string) (*securityLog, error) {
	l := &securityLog{path: path, limit: maxLogBytes, queue: make(chan entry, queueSize), done: make(chan struct{})}
	if err := l.open(); err != nil {
		return nil, err
	}
	go l.run()
	return l, nil
}

// commit queues r and waits until it is synced; a failed or full log, or a
// wait longer than commitWait, refuses it.
func (l *securityLog) commit(ctx context.Context, r record) error {
	done := make(chan error, 1)
	if l.failed.Load() || !l.enqueue(r, done) {
		return errLogFailed
	}
	ctx, cancel := context.WithTimeout(ctx, commitWait)
	defer cancel()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return errLogFailed
	}
}

// note queues r without waiting, counting it as lost when it cannot be.
func (l *securityLog) note(r record) {
	if l.failed.Load() || !l.enqueue(r, nil) {
		l.lost.Add(1)
	}
}

// enqueue stamps and queues r. The last quarter of the queue is kept for
// admissions, so a flood of refusals never refuses a request that passed.
func (l *securityLog) enqueue(r record, done chan error) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed || done == nil && len(l.queue) >= queueSize-queueSize/4 {
		return false
	}
	r.Seq, r.Time = l.seq.Add(1), time.Now().UTC()
	if len(r.Method) > maxMethod {
		r.Method = r.Method[:maxMethod]
	}
	if len(r.Path) > maxPath {
		r.Path = r.Path[:maxPath]
	}
	select {
	case l.queue <- entry{r, done}:
		return true
	default:
		return false
	}
}

// run writes batches in queue order until close empties the queue.
func (l *securityLog) run() {
	defer close(l.done)
	batch := make([]entry, 0, batchSize)
	for first := range l.queue {
		batch = append(batch[:0], first)
	fill:
		for len(batch) < batchSize {
			select {
			case next, open := <-l.queue:
				if !open {
					break fill
				}
				batch = append(batch, next)
			default:
				break fill
			}
		}
		err := l.write(batch)
		for _, e := range batch {
			if e.done != nil {
				e.done <- err
			}
		}
	}
	if l.lost.Load() > 0 {
		l.write(nil)
	}
	l.file.Close()
}

// write appends the pending loss count and batch, then syncs. A failure
// disables admission for the rest of the process.
func (l *securityLog) write(batch []entry) error {
	if l.failed.Load() {
		return errLogFailed
	}
	var buffer []byte
	if lost := l.lost.Swap(0); lost > 0 {
		buffer = appendRecord(buffer, record{Seq: l.seq.Add(1), Time: time.Now().UTC(), Kind: "log.loss", Lost: lost})
	}
	for _, e := range batch {
		buffer = appendRecord(buffer, e.record)
	}
	if _, err := l.file.Write(buffer); err != nil {
		return l.fail(err)
	}
	l.size += int64(len(buffer))
	if err := l.file.Sync(); err != nil {
		return l.fail(err)
	}
	if l.size >= l.limit {
		if err := l.rotate(); err != nil {
			return l.fail(err)
		}
	}
	return nil
}

// open appends to the active file, creating it private to this user.
func (l *securityLog) open() error {
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return errors.Join(err, file.Close())
	}
	l.file, l.size = file, info.Size()
	return nil
}

// rotate closes the full active file as <path>.1, shifting older files up
// and deleting the oldest, so the log keeps at most logFiles files.
func (l *securityLog) rotate() error {
	if err := l.file.Close(); err != nil {
		return err
	}
	if err := os.Remove(fmt.Sprintf("%s.%d", l.path, logFiles-1)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for n := logFiles - 2; n >= 1; n-- {
		err := os.Rename(fmt.Sprintf("%s.%d", l.path, n), fmt.Sprintf("%s.%d", l.path, n+1))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(l.path, l.path+".1"); err != nil {
		return err
	}
	return l.open()
}

func (l *securityLog) fail(err error) error {
	if l.failed.CompareAndSwap(false, true) {
		fmt.Fprintf(os.Stderr, "security log failed; admission disabled: %v\n", err)
	}
	return errLogFailed
}

func appendRecord(buffer []byte, r record) []byte {
	line, err := json.Marshal(r)
	if err != nil {
		panic(err) // a record holds only strings, numbers and times
	}
	return append(append(buffer, line...), '\n')
}

// close stops queueing, writes everything queued and closes the file.
func (l *securityLog) close() {
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		close(l.queue)
	}
	l.mu.Unlock()
	<-l.done
}
