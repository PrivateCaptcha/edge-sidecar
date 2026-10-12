package api

import "sync"

type completionLimiter struct {
	mu     sync.Mutex
	limit  int
	active int
}

func (l *completionLimiter) acquire() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active >= l.limit {
		return false
	}
	l.active++
	return true
}

func (l *completionLimiter) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active--
}

func (l *completionLimiter) setLimit(limit int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.limit = limit
}
