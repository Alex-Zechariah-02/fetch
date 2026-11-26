// Security log health state: one typed state held in an atomic integer, with
// every transition checked against the legal move table.

package guard

type logHealth int32

const (
	healthWriting logHealth = iota
	healthRotating
	healthFull
	healthDown
	healthNoSpace
)

func allowedMove(from, to logHealth) bool {
	switch from {
	case healthWriting:
		return to == healthRotating || to == healthFull || to == healthDown || to == healthNoSpace
	case healthRotating:
		return to == healthWriting || to == healthFull || to == healthDown || to == healthNoSpace
	case healthFull:
		return to == healthWriting
	case healthDown:
		return to == healthWriting || to == healthDown || to == healthNoSpace
	case healthNoSpace:
		return to == healthWriting || to == healthNoSpace || to == healthDown
	default:
		return false
	}
}

func (l *securityLog) currentHealth() logHealth {
	return logHealth(l.health.Load())
}

// moveHealth moves the log from expected state from to state to when the
// transition table allows it. It is the only writer of l.health.
func (l *securityLog) moveHealth(from, to logHealth) bool {
	if !allowedMove(from, to) {
		return false
	}
	return l.health.CompareAndSwap(int32(from), int32(to))
}

// unavailable reports whether the log refuses records now.
func (l *securityLog) unavailable() bool {
	s := l.currentHealth()
	return s == healthFull || s == healthDown || s == healthNoSpace
}
