package logger

import (
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
}

type LogHub struct {
	mu          sync.RWMutex
	entries     []LogEntry
	maxEntries  int
	subscribers map[chan LogEntry]struct{}
}

var DefaultHub = NewLogHub(500)

func NewLogHub(maxEntries int) *LogHub {
	if maxEntries <= 0 {
		maxEntries = 500
	}
	return &LogHub{
		entries:     make([]LogEntry, 0, maxEntries),
		maxEntries:  maxEntries,
		subscribers: make(map[chan LogEntry]struct{}),
	}
}

func (h *LogHub) Write(p []byte) (n int, err error) {
	msg := strings.TrimRight(string(p), "\r\n")
	if msg == "" {
		return len(p), nil
	}

	lines := strings.Split(msg, "\n")
	h.mu.Lock()
	now := time.Now().UTC().Format(time.RFC3339)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		entry := LogEntry{
			Timestamp: now,
			Message:   trimmed,
		}

		if len(h.entries) >= h.maxEntries {
			h.entries = h.entries[1:]
		}
		h.entries = append(h.entries, entry)

		for ch := range h.subscribers {
			select {
			case ch <- entry:
			default:
			}
		}
	}
	h.mu.Unlock()

	return len(p), nil
}

func (h *LogHub) GetEntries(limit int) []LogEntry {
	h.mu.RLock()
	defer h.mu.RUnlock()

	total := len(h.entries)
	if limit <= 0 || limit > total {
		limit = total
	}
	start := total - limit
	result := make([]LogEntry, limit)
	copy(result, h.entries[start:])
	return result
}

func (h *LogHub) Subscribe() (chan LogEntry, func()) {
	h.mu.Lock()
	ch := make(chan LogEntry, 100)
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subscribers, ch)
			close(ch)
			h.mu.Unlock()
		})
	}

	return ch, unsubscribe
}

func (h *LogHub) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = make([]LogEntry, 0, h.maxEntries)
}

func InitGlobalLogger() {
	multi := io.MultiWriter(os.Stderr, DefaultHub)
	log.SetOutput(multi)
	log.SetFlags(log.Ldate | log.Ltime)
}
