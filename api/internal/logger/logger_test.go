package logger

import (
	"fmt"
	"testing"
	"time"
)

func TestLogHubWriteAndGet(t *testing.T) {
	hub := NewLogHub(5)

	for i := 1; i <= 7; i++ {
		_, err := hub.Write([]byte(fmt.Sprintf("log line %d\n", i)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	entries := hub.GetEntries(10)
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}

	if entries[0].Message != "log line 3" {
		t.Errorf("expected first entry to be 'log line 3', got %s", entries[0].Message)
	}

	if entries[4].Message != "log line 7" {
		t.Errorf("expected last entry to be 'log line 7', got %s", entries[4].Message)
	}
}

func TestLogHubSubscription(t *testing.T) {
	hub := NewLogHub(10)
	ch, unsub := hub.Subscribe()
	defer unsub()

	_, _ = hub.Write([]byte("live message\n"))

	select {
	case entry := <-ch:
		if entry.Message != "live message" {
			t.Errorf("expected 'live message', got %s", entry.Message)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for subscription entry")
	}
}

func TestLogHubClear(t *testing.T) {
	hub := NewLogHub(10)
	_, _ = hub.Write([]byte("test 1\n"))
	_, _ = hub.Write([]byte("test 2\n"))

	if len(hub.GetEntries(10)) != 2 {
		t.Fatalf("expected 2 entries")
	}

	hub.Clear()
	if len(hub.GetEntries(10)) != 0 {
		t.Fatalf("expected 0 entries after clear")
	}
}
