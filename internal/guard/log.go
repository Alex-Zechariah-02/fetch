// The API's security log: JSON Lines files, rotated at a size bound and
// written by one goroutine in batches, each batch synced to disk. Each
// request encodes its own line, and the writer takes everything queued into
// one batch, so its work per record is a copy and it keeps up while many
// requests share the CPU. An admission waits for its batch's sync before the
// handler runs; refusals and outcomes are queued without waiting and, when
// they cannot be, counted and written as a loss record.

package guard

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// queueSize is the gateway's audit queue at its default in-flight limit
	// (4 × 1,024); past it refusals are counted in a loss record, never
	// waited for. The writer drains up to the whole queue per sync, so one
	// slow turn of the writer is caught up in the next batch.
	queueSize = 4096
	// commitWait bounds an admission's wait for its sync (the gateway's
	// default audit wait).
	commitWait = 2 * time.Second
	// maxPath bounds a log line; every Fetch API path is far shorter.
	maxPath = 512
	// maxMethod is longer than any registered HTTP method; Go accepts any
	// token up to its 1 MiB header limit.
	maxMethod = 32
	// maxLogBytes and logFiles bound the log as the gateway's defaults bound
	// its own (gateway.audit_max_bytes, gateway.audit_max_files), so both
	// protected setups keep the same history.
	maxLogBytes = 64 << 20
	logFiles    = 8
	// keptBuffer is the batch memory the writer keeps between batches: a
	// drained queue of queueSize lines of about 320 bytes fits, so a busy log
	// reuses one buffer instead of allocating one per batch.
	keptBuffer = queueSize * 512
)

type entry struct {
	line []byte     // the record as one JSON line, encoded by its request
	done chan error // nil when nobody waits
	// state settles an admission once: the writer takes it (1), or a commit
	// whose wait ended withdraws it first (2), so it is never written.
	state *atomic.Int32
}

var (
	errLogFailed = errors.New("security log unavailable")
	// errLogTimedOut is commit's error when its wait ended first; the
	// admission was withdrawn, or is written and superseded by the refusal.
	errLogTimedOut = fmt.Errorf("%w: wait timed out", errLogFailed)
)

// securityLog owns its file: only run writes, rotates or closes it.
type securityLog struct {
	path string
	file *os.File
	size int64 // bytes of records in the active file: its logical end
	// filled is the file's size on disk: past size it is a synced zero tail.
	filled     int64
	limit      int64 // rotation size, maxLogBytes
	openFile   func(string, int, os.FileMode) (*os.File, error)
	queue      chan entry
	evictCh    chan entry
	buffer     []byte // the last batch's memory, reused; only run uses it
	seq        atomic.Uint64
	lost       atomic.Uint64 // not yet written in a loss record
	dropped    atomic.Uint64 // every record lost since start, for the control listener
	written    atomic.Int64  // bytes in the active file after the last batch
	health     atomic.Int32  // logHealth state; only moveHealth writes it (health.go)
	trouble                  // the writer's recovery state
	archive    *archiver
	slow       atomic.Int64 // saves that waited longer than slowSave
	recoveries atomic.Int64 // active files replaced after a failed write
	mu         sync.RWMutex // orders queueing against close
	closed     bool
	done       chan struct{}

	// spaceFails counts writes refused for want of space; the archiver evicts
	// one file on the log disk for each.
	spaceFails atomic.Uint64
}

// logOption configures an opened securityLog before its goroutines start.
type logOption func(*logConfig)

type logConfig struct {
	limit    int64
	pause    time.Duration
	openFile func(string, int, os.FileMode) (*os.File, error)
}

func withLimit(bytes int64) logOption {
	return func(c *logConfig) { c.limit = bytes }
}

func withReservePause(d time.Duration) logOption {
	return func(c *logConfig) { c.pause = d }
}

func withOpener(fn func(string, int, os.FileMode) (*os.File, error)) logOption {
	return func(c *logConfig) { c.openFile = fn }
}

// openLog writes to path from its logical end, creating it private to this
// user, and starts the archiver unless s names no archive folder.
func openLog(path string, s Storage, opts ...logOption) (*securityLog, error) {
	cfg := logConfig{limit: maxLogBytes, pause: defaultReservePause, openFile: os.OpenFile}
	for _, opt := range opts {
		opt(&cfg)
	}
	l := &securityLog{path: path, limit: cfg.limit, openFile: cfg.openFile, queue: make(chan entry, queueSize), evictCh: make(chan entry, 1), done: make(chan struct{})}
	if err := l.open(); err != nil {
		return nil, err
	}
	l.refuse = s.Refuse
	if s.Archive != "" {
		l.archive = newArchiver(l, s, cfg.pause)
		go l.archive.run()
	}
	go l.run()
	return l, nil
}

// commit queues r and waits until it is synced; a failed or full log, or a
// wait longer than commitWait, refuses it.
func (l *securityLog) commit(ctx context.Context, r *record) error {
	done, state := make(chan error, 1), new(atomic.Int32)
	if !l.enqueue(r, done, state) {
		return errLogFailed
	}
	ctx, cancel := context.WithTimeout(ctx, commitWait)
	defer cancel()
	start := time.Now()
	select {
	case err := <-done:
		if time.Since(start) >= slowSave {
			l.slow.Add(1)
		}
		return err
	case <-ctx.Done():
		state.CompareAndSwap(0, 2)
		return errLogTimedOut
	}
}

// note queues r without waiting, counting it as lost when it cannot be.
func (l *securityLog) note(r *record) {
	if !l.enqueue(r, nil, nil) {
		l.lost.Add(1)
		l.dropped.Add(1)
	}
}

// enqueue stamps and queues r. The last quarter of the queue is kept for
// admissions, so a flood of refusals never refuses a request that passed.
func (l *securityLog) enqueue(r *record, done chan error, state *atomic.Int32) bool {
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
	case l.queue <- entry{appendRecord(nil, r), done, state}:
		return true
	default:
		return false
	}
}

// run writes batches in queue order until close empties the queue.
func (l *securityLog) run() {
	defer close(l.done)
	batch := make([]entry, 0, queueSize)
	for {
		select {
		case e := <-l.evictCh:
			e.done <- l.writeEviction(e)
		case first, open := <-l.queue:
			if !open {
				goto finish
			}
			batch = take(batch[:0], first)
		fill:
			for len(batch) < queueSize {
				select {
				case next, open := <-l.queue:
					if !open {
						break fill
					}
					batch = take(batch, next)
				default:
					break fill
				}
			}
			if len(batch) == 0 {
				continue
			}
			err := l.write(batch)
			for _, e := range batch {
				if e.done != nil {
					e.done <- err
				}
			}
		}
	}
finish:
	if l.lost.Load() > 0 {
		l.write(nil)
	}
	l.archive.halt()
	if err := errors.Join(l.trim(), l.file.Close()); err != nil {
		fmt.Fprintf(os.Stderr, "security log close failed: %v\n", err)
	}
}

// take adds e to batch unless its commit withdrew it.
func take(batch []entry, e entry) []entry {
	if e.state != nil && !e.state.CompareAndSwap(0, 1) {
		return batch
	}
	return append(batch, e)
}

// write adds the pending loss count and batch at the logical end, then
// syncs. A batch the log cannot take (recover.go) is refused, its records
// that nobody waits for counted as lost.
func (l *securityLog) write(batch []entry) error {
	if !l.ready() {
		l.lose(batch, 0)
		return errLogFailed
	}
	lost := l.lost.Swap(0)
	buffer := l.buffer[:0]
	if lost > 0 {
		buffer = appendRecord(buffer, &record{Seq: l.seq.Add(1), Time: time.Now().UTC(), Kind: "log.loss", Lost: lost})
	}
	for _, e := range batch {
		buffer = append(buffer, e.line...)
	}
	// Synced before the admission returns, so an acknowledged request is on disk.
	err := l.persist(buffer)
	if err != nil && spaceError(err) && l.releaseReserve() {
		err = l.persist(buffer)
	}
	if err != nil {
		l.lose(batch, lost)
		return l.fail(err)
	}
	// A batch beyond a full queue's size is not kept, so idle memory stays bounded.
	if cap(buffer) <= keptBuffer {
		l.buffer = buffer
	}
	l.written.Store(l.size)
	if l.size >= l.limit {
		if err := l.rotate(); err != nil {
			return l.keepActive(err)
		}
		if l.currentHealth() == healthRotating {
			l.moveHealth(healthRotating, healthWriting)
		}
	}
	return nil
}

// close stops the archiver, whose records need the queue, then stops
// queueing, writes everything queued and closes the file.
func (l *securityLog) close() {
	l.archive.halt()
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		close(l.queue)
	}
	l.mu.Unlock()
	<-l.done
}
