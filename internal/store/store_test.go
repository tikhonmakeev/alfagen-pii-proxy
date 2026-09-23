package store

import (
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"
)

const (
	tokenABCEmail = "[PII_abc_email_0]"
	putErrFmt     = "Put error: %v"
	ivanPetrov    = "Иван Петров"
	maskStr       = "mask"
	srcStr        = "src"
	consumerC     = "c"
	payloadP      = "p"
	tokenKeyT     = "t"
	tokenValV     = "v"
	payloadX      = "payloadX"
)

func TestPutGet(t *testing.T) {
	s := New(time.Minute, 100, 10)
	defer s.Close()

	source := ivanPetrov
	masked := tokenABCEmail
	tokens := map[string]string{tokenABCEmail: ivanPetrov}

	if err := s.Put("consumer1", "payload1", source, masked, tokens); err != nil {
		t.Fatalf(putErrFmt, err)
	}
	rec, ok := s.Get("consumer1", "payload1")
	if !ok {
		t.Fatal("record not found after Put")
	}
	if rec.Masked != masked {
		t.Fatalf("masked mismatch: got %q want %q", rec.Masked, masked)
	}
	if rec.Tokens[tokenABCEmail] != ivanPetrov {
		t.Fatalf("token value mismatch: %q", rec.Tokens[tokenABCEmail])
	}
	wantHash := sha256.Sum256([]byte(source))
	if rec.SourceHash != wantHash {
		t.Fatalf("source hash mismatch")
	}
}

func TestTTLExpiry(t *testing.T) {
	s := New(50*time.Millisecond, 100, 10)
	defer s.Close()

	if err := s.Put(consumerC, payloadP, "source", maskStr, map[string]string{tokenKeyT: tokenValV}); err != nil {
		t.Fatalf(putErrFmt, err)
	}
	if _, ok := s.Get(consumerC, payloadP); !ok {
		t.Fatal("record should be found before TTL expiry")
	}
	time.Sleep(80 * time.Millisecond)
	if _, ok := s.Get(consumerC, payloadP); ok {
		t.Fatal("record should be expired after TTL")
	}
}

func TestConsumerIsolation(t *testing.T) {
	s := New(time.Minute, 100, 10)
	defer s.Close()

	if err := s.Put("consumerA", payloadX, "source A", "maskA", map[string]string{tokenKeyT: "A"}); err != nil {
		t.Fatalf(putErrFmt, err)
	}
	if err := s.Put("consumerB", payloadX, "source B", "maskB", map[string]string{tokenKeyT: "B"}); err != nil {
		t.Fatalf(putErrFmt, err)
	}

	recA, okA := s.Get("consumerA", payloadX)
	if !okA || recA.Masked != "maskA" {
		t.Fatalf("consumerA record wrong: %+v ok=%v", recA, okA)
	}
	recB, okB := s.Get("consumerB", payloadX)
	if !okB || recB.Masked != "maskB" {
		t.Fatalf("consumerB record wrong: %+v ok=%v", recB, okB)
	}
}

func TestCapacityExceeded(t *testing.T) {
	s := New(time.Minute, 2, 10)
	defer s.Close()

	for i := 0; i < 2; i++ {
		if err := s.Put(consumerC, string(rune('a'+i)), srcStr, maskStr, map[string]string{tokenKeyT: tokenValV}); err != nil {
			t.Fatalf("Put %d error: %v", i, err)
		}
	}
	err := s.Put(consumerC, "third", srcStr, maskStr, map[string]string{tokenKeyT: tokenValV})
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected ErrCapacityExceeded, got %v", err)
	}
}

func TestMemoryLimitExceeded(t *testing.T) {
	// Бюджет 1 МБ, но одна запись с большим значением токена превысит его.
	s := New(time.Minute, 100, 1)
	defer s.Close()

	big := make([]byte, 2*1024*1024)
	for i := range big {
		big[i] = 'x'
	}
	err := s.Put(consumerC, payloadP, srcStr, maskStr, map[string]string{tokenKeyT: string(big)})
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected ErrCapacityExceeded, got %v", err)
	}
}

func TestConcurrent(t *testing.T) {
	s := New(time.Minute, 10000, 100)
	defer s.Close()

	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				key := string(rune('a'+g)) + string(rune('a'+i%26))
				_ = s.Put("consumer", key, "source", maskStr, map[string]string{tokenKeyT: tokenValV})
				_, _ = s.Get("consumer", key)
			}
		}(g)
	}
	wg.Wait()
}