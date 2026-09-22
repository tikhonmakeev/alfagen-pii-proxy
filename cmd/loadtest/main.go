// Пакет loadtest — нагрузочный тестовый клиент для проверки
// производительности и корректности работы HTTP-сервиса.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	maxAttempts      = 3
	stopAfterInvalid = 5
	requestTimeout   = 10 * time.Second
)

var piiValues = []string{
	"Иванов Иван Иванович",
	"ivan.ivanov@example.org",
	"+7 (999) 123-45-67",
	"4509 123456",
	"12.01.1990",
}

func compositeText() string {
	return "Клиент Иванов Иван Иванович, паспорт 4509 123456, дата рождения 12.01.1990, email ivan.ivanov@example.org, телефон +7 (999) 123-45-67"
}

type options struct {
	url         string
	rps         int
	duration    time.Duration
	concurrency int
	insecure    bool
	apiKey      string
}

type metrics struct {
	mu                    sync.Mutex
	requests              int
	invalid               int
	consecutiveInvalid    int
	maxConsecutiveInvalid int
	http429               int
	http429Persistent     int
	roundtripFailures     int
	recoveredByRetry      int
	failureReasons        map[string]int
	latencies             []time.Duration
}

func (m *metrics) recordSuccess(neededRetry bool, dur time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests++
	m.consecutiveInvalid = 0
	if neededRetry {
		m.recoveredByRetry++
	}
	m.latencies = append(m.latencies, dur)
}

func (m *metrics) recordInvalid(reason string, persistent429 bool, dur time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests++
	m.invalid++
	m.consecutiveInvalid++
	if m.consecutiveInvalid > m.maxConsecutiveInvalid {
		m.maxConsecutiveInvalid = m.consecutiveInvalid
	}
	if persistent429 {
		m.http429Persistent++
	}
	if reason != "" {
		m.failureReasons[reason]++
	}
	m.latencies = append(m.latencies, dur)
}

func (m *metrics) record429() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.http429++
}

func (m *metrics) recordRoundtripFailure() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roundtripFailures++
}

func (m *metrics) shouldStop() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.consecutiveInvalid >= stopAfterInvalid
}

type client struct {
	opts     options
	http     *http.Client
	idCounter int64
	metrics  *metrics
	stopCh   chan struct{}
	stopOnce sync.Once
}

func newClient(opts options) *client {
	tr := &http.Transport{}
	if opts.insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &client{
		opts:    opts,
		http:    &http.Client{Transport: tr, Timeout: requestTimeout},
		metrics: &metrics{failureReasons: make(map[string]int)},
		stopCh:  make(chan struct{}),
	}
}

func (c *client) stop() {
	c.stopOnce.Do(func() { close(c.stopCh) })
}

func (c *client) newPayloadID() string {
	return fmt.Sprintf("loadtest-%d", atomic.AddInt64(&c.idCounter, 1))
}

func (c *client) post(payload, payloadID string) (status int, body string, retryAfter int, err error) {
	reqBody, _ := json.Marshal(map[string]string{"payload": payload, "payload_id": payloadID})
	req, err := http.NewRequest("POST", c.opts.url, bytes.NewReader(reqBody))
	if err != nil {
		return 0, "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.opts.apiKey != "" {
		req.Header.Set("X-API-Key", c.opts.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", 0, err
	}
	ra := 0
	if v := resp.Header.Get("Retry-After"); v != "" {
		ra, _ = strconv.Atoi(v)
	}
	return resp.StatusCode, string(b), ra, nil
}

// doRequest выполняет один HTTP-запрос с ретраями. Возвращает результат,
// признак успеха, признак persistent-429 и признак того, что понадобился ретрай.
func (c *client) doRequest(payload, payloadID string) (result string, ok bool, persistent429 bool, neededRetry bool, reason string) {
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			neededRetry = true
		}
		status, body, retryAfter, err := c.post(payload, payloadID)
		if err != nil {
			reason = "transport: " + err.Error()
			c.sleepJitter(50, 150)
			continue
		}
		if status == http.StatusTooManyRequests {
			if retryAfter <= 0 {
				// Невалидный 429 (без Retry-After).
				reason = "invalid 429 (no Retry-After)"
				c.sleepJitter(50, 150)
				continue
			}
			c.metrics.record429()
			if attempt == maxAttempts-1 {
				persistent429 = true
				return "", false, true, neededRetry, "persistent 429"
			}
			c.sleep(time.Duration(retryAfter)*time.Second + jitter(0, 300))
			continue
		}
		if status != http.StatusOK {
			reason = fmt.Sprintf("status %d", status)
			c.sleepJitter(50, 150)
			continue
		}
		res, valid := parseResult(body)
		if !valid {
			reason = "invalid body"
			c.sleepJitter(50, 150)
			continue
		}
		return res, true, false, neededRetry, ""
	}
	return "", false, persistent429, neededRetry, reason
}

func (c *client) logicalRequest() {
	start := time.Now()
	payload := compositeText()
	payloadID := c.newPayloadID()

	mask, ok, persistent429, neededRetry, reason := c.doRequest(payload, payloadID)
	if !ok {
		c.metrics.recordInvalid(reason, persistent429, time.Since(start))
		return
	}
	if leaksPII(mask) {
		c.metrics.recordRoundtripFailure()
	}

	restored, ok2, persistent429_2, neededRetry2, reason2 := c.doRequest(mask, payloadID)
	if !ok2 {
		c.metrics.recordInvalid(reason2, persistent429_2, time.Since(start))
		return
	}
	if restored != payload {
		c.metrics.recordRoundtripFailure()
	}

	c.metrics.recordSuccess(neededRetry || neededRetry2, time.Since(start))
}

func leaksPII(mask string) bool {
	for _, v := range piiValues {
		if strings.Contains(mask, v) {
			return true
		}
	}
	return false
}

func parseResult(body string) (string, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return "", false
	}
	if len(m) != 1 {
		return "", false
	}
	raw, ok := m["result"]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

func (c *client) sleep(d time.Duration) {
	select {
	case <-time.After(d):
	case <-c.stopCh:
	}
}

func (c *client) sleepJitter(min, max int) {
	c.sleep(jitter(min, max))
}

func jitter(min, max int) time.Duration {
	if max <= min {
		return time.Duration(min) * time.Millisecond
	}
	return time.Duration(min+rand.Intn(max-min)) * time.Millisecond
}

func (c *client) run(ctx context.Context) {
	interval := time.Second / time.Duration(c.opts.rps)
	if interval <= 0 {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	sem := make(chan struct{}, c.opts.concurrency)
	deadline := time.Now().Add(c.opts.duration)
	var wg sync.WaitGroup

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-c.stopCh:
			wg.Wait()
			return
		case <-ticker.C:
			select {
			case sem <- struct{}{}:
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-sem }()
					c.logicalRequest()
					if c.metrics.shouldStop() {
						c.stop()
					}
				}()
			default:
				// Все воркеры заняты — пропускаем тик.
			}
		}
	}
	wg.Wait()
}

func (c *client) summary(elapsed time.Duration) map[string]interface{} {
	m := c.metrics
	m.mu.Lock()
	defer m.mu.Unlock()

	actualRPS := 0.0
	if elapsed.Seconds() > 0 {
		actualRPS = float64(m.requests) / elapsed.Seconds()
	}
	p50, p95, p99, maxMs := percentiles(m.latencies)

	return map[string]interface{}{
		"target_rps":              c.opts.rps,
		"elapsed_seconds":         elapsed.Seconds(),
		"requests":                m.requests,
		"actual_rps":              actualRPS,
		"invalid":                 m.invalid,
		"max_consecutive_invalid": m.maxConsecutiveInvalid,
		"http_429":                m.http429,
		"http_429_persistent":     m.http429Persistent,
		"roundtrip_failures":      m.roundtripFailures,
		"failure_reasons":         m.failureReasons,
		"recovered_by_retry":      m.recoveredByRetry,
		"p50_ms":                  p50,
		"p95_ms":                  p95,
		"p99_ms":                  p99,
		"max_ms":                  maxMs,
	}
}

func percentiles(lat []time.Duration) (p50, p95, p99, maxMs float64) {
	if len(lat) == 0 {
		return 0, 0, 0, 0
	}
	ms := make([]float64, len(lat))
	for i, d := range lat {
		ms[i] = float64(d.Microseconds()) / 1000.0
	}
	sort.Float64s(ms)
	idx := func(p float64) int {
		i := int(p * float64(len(ms)))
		if i >= len(ms) {
			i = len(ms) - 1
		}
		return i
	}
	return ms[idx(0.50)], ms[idx(0.95)], ms[idx(0.99)], ms[len(ms)-1]
}

func main() {
	var opts options
	flag.StringVar(&opts.url, "url", "http://127.0.0.1:8080/process", "endpoint address")
	flag.IntVar(&opts.rps, "rps", 1000, "target requests per second")
	flag.DurationVar(&opts.duration, "duration", 5*time.Minute, "total run duration")
	flag.IntVar(&opts.concurrency, "concurrency", 256, "max concurrent workers (1..256)")
	flag.BoolVar(&opts.insecure, "insecure", false, "accept self-signed HTTPS certificate")
	flag.Parse()

	if opts.concurrency < 1 {
		opts.concurrency = 1
	}
	if opts.concurrency > 256 {
		opts.concurrency = 256
	}
	if opts.rps < 1 {
		opts.rps = 1
	}
	opts.apiKey = os.Getenv("LOADTEST_API_KEY")

	c := newClient(opts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()

	start := time.Now()
	c.run(ctx)
	elapsed := time.Since(start)

	out, _ := json.Marshal(c.summary(elapsed))
	fmt.Println(string(out))

	if c.metrics.invalid > 0 || c.metrics.roundtripFailures > 0 {
		os.Exit(1)
	}
}