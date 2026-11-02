package broker

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
)

func TestEventBroker_DebounceBatching(t *testing.T) {
	broker := NewEventBroker(50 * time.Millisecond)
	defer broker.Close()

	ch, unsub := broker.Subscribe()
	defer unsub()

	// Send 5 events in rapid succession
	for i := 1; i <= 5; i++ {
		broker.LogEvent(&filter.AuditEvent{
			ID:       fmt.Sprintf("ev-%d", i),
			ToolName: "test_tool",
			Decision: "ALLOW",
		})
	}

	select {
	case batch := <-ch:
		if len(batch) != 5 {
			t.Fatalf("expected batch of 5 events, got %d", len(batch))
		}
		if batch[0].ID != "ev-1" || batch[4].ID != "ev-5" {
			t.Errorf("unexpected event ordering in batch: %+v", batch)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatalf("timed out waiting for debounced event batch")
	}
}

func TestEventBroker_MultiClientBroadcast(t *testing.T) {
	broker := NewEventBroker(40 * time.Millisecond)
	defer broker.Close()

	ch1, unsub1 := broker.Subscribe()
	defer unsub1()
	ch2, unsub2 := broker.Subscribe()
	defer unsub2()

	if broker.SubscriberCount() != 2 {
		t.Fatalf("expected 2 active subscribers, got %d", broker.SubscriberCount())
	}

	broker.LogEvent(&filter.AuditEvent{ID: "broadcast-1", ToolName: "multi_test"})

	var batch1, batch2 []*filter.AuditEvent
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		select {
		case b := <-ch1:
			batch1 = b
		case <-time.After(300 * time.Millisecond):
		}
	}()

	go func() {
		defer wg.Done()
		select {
		case b := <-ch2:
			batch2 = b
		case <-time.After(300 * time.Millisecond):
		}
	}()

	wg.Wait()

	if len(batch1) != 1 || batch1[0].ID != "broadcast-1" {
		t.Fatalf("client 1 did not receive expected broadcast: %+v", batch1)
	}
	if len(batch2) != 1 || batch2[0].ID != "broadcast-1" {
		t.Fatalf("client 2 did not receive expected broadcast: %+v", batch2)
	}
}

func TestEventBroker_Unsubscribe(t *testing.T) {
	broker := NewEventBroker(30 * time.Millisecond)
	defer broker.Close()

	ch, unsub := broker.Subscribe()
	if broker.SubscriberCount() != 1 {
		t.Fatalf("expected 1 subscriber, got %d", broker.SubscriberCount())
	}

	unsub()
	// Idempotent unsubscribe call
	unsub()

	if broker.SubscriberCount() != 0 {
		t.Fatalf("expected 0 subscribers after unsub, got %d", broker.SubscriberCount())
	}

	// Channel should be drained / closed
	_, ok := <-ch
	if ok {
		t.Errorf("expected channel to be closed after unsubscribe")
	}
}

func TestEventBroker_SlowClientNonBlocking(t *testing.T) {
	broker := NewEventBroker(20 * time.Millisecond)
	defer broker.Close()

	slowCh, unsubSlow := broker.Subscribe()
	defer unsubSlow()

	fastCh, unsubFast := broker.Subscribe()
	defer unsubFast()

	// Fill slow client's buffer (buffer is 64)
	for i := 0; i < 70; i++ {
		broker.LogEvent(&filter.AuditEvent{ID: fmt.Sprintf("fill-%d", i)})
		time.Sleep(25 * time.Millisecond) // Let each tick flush a batch
	}

	// Fast client should still receive batches without delay
	select {
	case b := <-fastCh:
		if len(b) == 0 {
			t.Errorf("fast client received empty batch")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("fast client was blocked by slow client")
	}

	// Drain slowCh to avoid leaks
	for len(slowCh) > 0 {
		<-slowCh
	}
}

func TestEventBroker_HighFrequencyMicroBursts(t *testing.T) {
	broker := NewEventBroker(40 * time.Millisecond)
	defer broker.Close()

	ch, unsub := broker.Subscribe()
	defer unsub()

	const concurrentGoroutines = 25
	const eventsPerGoroutine = 20
	totalEvents := concurrentGoroutines * eventsPerGoroutine

	var wg sync.WaitGroup
	for g := 0; g < concurrentGoroutines; g++ {
		wg.Add(1)
		go func(routineID int) {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				broker.LogEvent(&filter.AuditEvent{
					ID:        fmt.Sprintf("burst-r%d-e%d", routineID, i),
					ToolName:  "concurrent_burst",
					LatencyMs: 0.1,
				})
			}
		}(g)
	}

	wg.Wait()

	receivedCount := 0
	timeout := time.After(1 * time.Second)

collectLoop:
	for {
		select {
		case batch, ok := <-ch:
			if !ok {
				break collectLoop
			}
			receivedCount += len(batch)
			if receivedCount >= totalEvents {
				break collectLoop
			}
		case <-timeout:
			break collectLoop
		}
	}

	if receivedCount != totalEvents {
		t.Fatalf("expected to receive %d total events, got %d", totalEvents, receivedCount)
	}
}
