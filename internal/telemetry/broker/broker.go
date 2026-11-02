package broker

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
)

// DefaultDebounceInterval is the standard event grouping window (150ms).
const DefaultDebounceInterval = 150 * time.Millisecond

// EventBroker buffers incoming audit events and broadcasts them in debounced batches to subscribers.
type EventBroker struct {
	debounceInterval time.Duration
	inbound          chan *filter.AuditEvent
	subscribers      map[chan []*filter.AuditEvent]struct{}
	mu               sync.RWMutex
	done             chan struct{}
	wg               sync.WaitGroup
	droppedCount     uint64
	isClosed         atomic.Bool
}

// NewEventBroker initializes and starts a new EventBroker.
func NewEventBroker(debounceInterval time.Duration) *EventBroker {
	if debounceInterval <= 0 {
		debounceInterval = DefaultDebounceInterval
	}

	b := &EventBroker{
		debounceInterval: debounceInterval,
		inbound:          make(chan *filter.AuditEvent, 4096),
		subscribers:      make(map[chan []*filter.AuditEvent]struct{}),
		done:             make(chan struct{}),
	}

	b.wg.Add(1)
	go b.run()

	return b
}

// LogEvent implements filter.AuditLogger.
// It places the event on an in-memory buffered channel in a non-blocking manner (< 1µs).
func (b *EventBroker) LogEvent(event *filter.AuditEvent) {
	if b == nil || event == nil || b.isClosed.Load() {
		return
	}

	select {
	case b.inbound <- event:
	default:
		// Queue full: increment counter and drop to protect proxy hot-path SLA
		atomic.AddUint64(&b.droppedCount, 1)
	}
}

// DroppedCount returns the number of dropped events due to buffer saturation.
func (b *EventBroker) DroppedCount() uint64 {
	return atomic.LoadUint64(&b.droppedCount)
}

// SubscriberCount returns the current number of active streaming subscribers.
func (b *EventBroker) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subscribers)
}

// Subscribe registers a new subscriber channel and returns an idempotent unsubscribe function.
func (b *EventBroker) Subscribe() (chan []*filter.AuditEvent, func()) {
	ch := make(chan []*filter.AuditEvent, 64)

	b.mu.Lock()
	if b.isClosed.Load() {
		b.mu.Unlock()
		close(ch)
		return ch, func() {}
	}
	b.subscribers[ch] = struct{}{}
	b.mu.Unlock()

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			b.mu.Lock()
			if _, exists := b.subscribers[ch]; exists {
				delete(b.subscribers, ch)
				close(ch)
			}
			b.mu.Unlock()
		})
	}

	return ch, unsubscribe
}

// run is the background ticker-driven batching and broadcast loop.
func (b *EventBroker) run() {
	defer b.wg.Done()

	ticker := time.NewTicker(b.debounceInterval)
	defer ticker.Stop()

	var currentBatch []*filter.AuditEvent

	flush := func() {
		if len(currentBatch) == 0 {
			return
		}

		// Create a copy of currentBatch for broadcast
		batch := make([]*filter.AuditEvent, len(currentBatch))
		copy(batch, currentBatch)
		currentBatch = nil

		b.mu.RLock()
		for subCh := range b.subscribers {
			select {
			case subCh <- batch:
			default:
				// Slow client: drop batch to prevent blocking the broker or other clients
			}
		}
		b.mu.RUnlock()
	}

	for {
		select {
		case <-b.done:
			// Drain remaining events in inbound channel
			for {
				select {
				case ev := <-b.inbound:
					currentBatch = append(currentBatch, ev)
				default:
					flush()
					return
				}
			}

		case ev := <-b.inbound:
			currentBatch = append(currentBatch, ev)

		case <-ticker.C:
			flush()
		}
	}
}

// Close gracefully terminates the broker and flushes any pending events.
func (b *EventBroker) Close() error {
	if !b.isClosed.CompareAndSwap(false, true) {
		return nil
	}

	close(b.done)
	b.wg.Wait()

	b.mu.Lock()
	for ch := range b.subscribers {
		close(ch)
		delete(b.subscribers, ch)
	}
	b.mu.Unlock()

	return nil
}
