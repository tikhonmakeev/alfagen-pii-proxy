package store

import (
	"crypto/sha256"
	"errors"
	"sync"
	"time"
)

// ErrCapacityExceeded возвращается, когда превышен лимит записей
// или лимит памяти хранилища.
var ErrCapacityExceeded = errors.New("store: capacity exceeded")

// Record — сохранённое состояние маскирования для одного payload_id.
type Record struct {
	SourceHash [32]byte
	Masked     string
	Tokens     map[string]string
}

// Store — потокобезопасное in-memory хранилище с TTL и ограничениями
// ёмкости. Ключ записи — пара (consumerID, payloadID); разные consumerID
// полностью изолированы.
type Store struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	maxBytes   int
	entries    map[string]*entry
	stop       chan struct{}
	done       chan struct{}
	closeOnce  sync.Once
}

type entry struct {
	record Record
	bytes  int
	expiry time.Time
}

// New создаёт хранилище с заданным TTL, максимальным числом записей и
// максимальным бюджетом памяти в мегабайтах. Значения <= 0 означают
// отсутствие соответствующего ограничения.
func New(ttl time.Duration, maxEntries, maxBytesMB int) *Store {
	s := &Store{
		ttl:        ttl,
		maxEntries: maxEntries,
		maxBytes:   maxBytesMB * 1024 * 1024,
		entries:    make(map[string]*entry),
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// Put сохраняет запись по ключу (consumerID, payloadID). Исходный текст
// не сохраняется — только его SHA256. Возвращает ErrCapacityExceeded при
// превышении лимита записей или памяти.
func (s *Store) Put(consumerID, payloadID, sourceText, masked string, tokens map[string]string) error {
	hash := sha256.Sum256([]byte(sourceText))
	bytes := len(masked)
	for _, v := range tokens {
		bytes += len(v)
	}
	tokensCopy := make(map[string]string, len(tokens))
	for k, v := range tokens {
		tokensCopy[k] = v
	}
	key := consumerID + "\x00" + payloadID
	rec := Record{SourceHash: hash, Masked: masked, Tokens: tokensCopy}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.entries[key]
	if !ok {
		if s.maxEntries > 0 && len(s.entries) >= s.maxEntries {
			return ErrCapacityExceeded
		}
	}
	total := s.totalBytesLocked()
	if existing != nil {
		total -= existing.bytes
	}
	if s.maxBytes > 0 && total+bytes > s.maxBytes {
		return ErrCapacityExceeded
	}

	s.entries[key] = &entry{record: rec, bytes: bytes, expiry: time.Now().Add(s.ttl)}
	return nil
}

// Get возвращает запись по ключу (consumerID, payloadID). Если запись
// не найдена или её TTL истёк — возвращает false.
func (s *Store) Get(consumerID, payloadID string) (Record, bool) {
	key := consumerID + "\x00" + payloadID
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if !ok {
		return Record{}, false
	}
	if time.Now().After(e.expiry) {
		delete(s.entries, key)
		return Record{}, false
	}
	return e.record, true
}

// Close останавливает фоновую очистку истёкших записей.
func (s *Store) Close() {
	s.closeOnce.Do(func() {
		close(s.stop)
		<-s.done
	})
}

func (s *Store) totalBytesLocked() int {
	total := 0
	for _, e := range s.entries {
		total += e.bytes
	}
	return total
}

func (s *Store) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			close(s.done)
			return
		case <-ticker.C:
			s.cleanup()
		}
	}
}

func (s *Store) cleanup() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.entries {
		if now.After(e.expiry) {
			delete(s.entries, k)
		}
	}
}