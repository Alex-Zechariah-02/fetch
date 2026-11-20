// Telling a full disk from a failed sync: a write refused for want of space
// may pass later in the same file; a failed sync never proves later writes
// durable, so it replaces the file (recover.go).

package guard

import "errors"

// syncError marks an error of a sync rather than of a write.
type syncError struct{ err error }

func (e syncError) Error() string { return e.err.Error() }
func (e syncError) Unwrap() error { return e.err }

// spaceError reports whether err is a write refused for want of space.
func spaceError(err error) bool {
	var failedSync syncError
	return !errors.As(err, &failedSync) && noSpace(err)
}
