package telemetry

import (
	"sync"
	"time"
)

// Timer tracks duration of phases within an operation.
// It is safe for concurrent use.
type Timer struct {
	mu        sync.Mutex
	start     time.Time
	lastPhase time.Time
	phases    []Phase
	total     time.Duration
	stopped   bool
}

// Phase represents a timed phase within an operation.
type Phase struct {
	Name     string        `json:"name"`
	Duration time.Duration `json:"duration_ms"`
	EndTime  time.Time     `json:"end_time"`
}

// NewTimer creates a new Timer starting now.
func NewTimer() *Timer {
	now := time.Now()
	return &Timer{
		start:     now,
		lastPhase: now,
		phases:    make([]Phase, 0, 8),
	}
}

// Phase records the duration since the last phase (or start) and begins a new phase.
// Returns the duration of the completed phase.
func (t *Timer) Phase(name string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.stopped {
		return 0
	}

	now := time.Now()
	duration := now.Sub(t.lastPhase)
	t.phases = append(t.phases, Phase{
		Name:     name,
		Duration: duration,
		EndTime:  now,
	})
	t.lastPhase = now
	return duration
}

// Stop stops the timer and returns the total duration.
// Subsequent calls to Phase() will be no-ops.
func (t *Timer) Stop() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.stopped {
		return t.total
	}

	t.total = time.Since(t.start)
	t.stopped = true
	return t.total
}

// Total returns the total duration from start.
// If the timer is stopped, returns the stopped duration.
func (t *Timer) Total() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.stopped {
		return t.total
	}
	return time.Since(t.start)
}

// Phases returns a copy of all recorded phases.
func (t *Timer) Phases() []Phase {
	t.mu.Lock()
	defer t.mu.Unlock()

	result := make([]Phase, len(t.phases))
	copy(result, t.phases)
	return result
}

// PhaseMap returns phases as a map of name to duration.
func (t *Timer) PhaseMap() map[string]time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()

	result := make(map[string]time.Duration, len(t.phases))
	for _, p := range t.phases {
		result[p.Name] = p.Duration
	}
	return result
}

// StartTime returns when the timer was started.
func (t *Timer) StartTime() time.Time {
	return t.start
}

// Stopwatch is a simple duration tracker for a single operation.
type Stopwatch struct {
	start time.Time
}

// NewStopwatch creates a new Stopwatch starting now.
func NewStopwatch() *Stopwatch {
	return &Stopwatch{start: time.Now()}
}

// Elapsed returns the time elapsed since the stopwatch started.
func (s *Stopwatch) Elapsed() time.Duration {
	return time.Since(s.start)
}

// Reset resets the stopwatch to now and returns the elapsed time.
func (s *Stopwatch) Reset() time.Duration {
	elapsed := time.Since(s.start)
	s.start = time.Now()
	return elapsed
}

// ElapsedMs returns elapsed time in milliseconds (for logging).
func (s *Stopwatch) ElapsedMs() int64 {
	return time.Since(s.start).Milliseconds()
}

