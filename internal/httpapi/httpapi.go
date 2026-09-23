package httpapi

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/tihon/pii-proxy-deepseek/internal/config"
	"github.com/tihon/pii-proxy-deepseek/internal/pii"
	"github.com/tihon/pii-proxy-deepseek/internal/store"
)

const (
	directionMask   = "mask"
	directionReject = "reject"
)

// Server — HTTP-слой сервиса.
type Server struct {
	detectors      []pii.Detector
	registry       *config.Registry
	store          *store.Store
	publicConsumer string
	inflight       chan struct{}
	logger         *log.Logger

	metrics         *prometheus.Registry
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	entitiesTotal   *prometheus.CounterVec
	tokensEstimated prometheus.Counter
}

// New создаёт HTTP-сервер.
func New(detectors []pii.Detector, registry *config.Registry, st *store.Store, publicConsumer string, maxInflight int) *Server {
	s := &Server{
		detectors:      detectors,
		registry:       registry,
		store:          st,
		publicConsumer: publicConsumer,
		inflight:       make(chan struct{}, maxInflight),
		logger:         log.New(os.Stdout, "", 0),
		metrics:        prometheus.NewRegistry(),
	}
	s.requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pii_requests_total",
		Help: "Total number of /process requests by direction and status",
	}, []string{"direction", "status"})
	s.requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pii_request_duration_seconds",
		Help:    "Duration of /process requests",
		Buckets: prometheus.DefBuckets,
	}, []string{})
	s.entitiesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pii_entities_total",
		Help: "Total number of detected PII entities by type",
	}, []string{"type"})
	s.tokensEstimated = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pii_tokens_estimated_total",
		Help: "Estimated number of tokens processed",
	})
	s.metrics.MustRegister(s.requestsTotal, s.requestDuration, s.entitiesTotal, s.tokensEstimated)
	return s
}

// Handler возвращает основной HTTP-обработчик.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/process", s.processHandler)
	mux.HandleFunc("/healthz", s.healthzHandler)
	return mux
}

// MetricsHandler возвращает обработчик метрик Prometheus.
func (s *Server) MetricsHandler() http.Handler {
	return promhttp.HandlerFor(s.metrics, promhttp.HandlerOpts{})
}

// StartMetrics запускает отдельный HTTP-listener для метрик.
func (s *Server) StartMetrics(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/", s.MetricsHandler())
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() { _ = srv.ListenAndServe() }()
	return srv
}

type processRequest struct {
	Payload   string `json:"payload"`
	PayloadID string `json:"payload_id"`
}

// processState — изменяемое состояние обработки одного запроса.
type processState struct {
	status       int
	direction    string
	foundTypes   []string
	payloadRunes int
	payloadID    string
}

func (s *Server) healthzHandler(w http.ResponseWriter, r *http.Request) {
	s.writeResult(w, http.StatusOK, "ok")
}

func (s *Server) processHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	st := &processState{status: http.StatusOK, direction: directionMask}
	defer s.recordMetrics(start, st)

	req, ok := s.parseRequest(w, r, st)
	if !ok {
		return
	}
	consumer, ok := s.authenticate(r)
	if !ok {
		s.reject(w, st, http.StatusUnauthorized, "unauthorized")
		return
	}
	release, ok := s.acquireSlot(w, st)
	if !ok {
		return
	}
	defer release()

	rec, found := s.store.Get(consumer.ID, req.PayloadID)
	if !found {
		s.handleMask(w, st, req, consumer, release)
		return
	}
	s.handleUnmask(w, st, req, consumer, rec)
}

// recordMetrics пишет метрики и лог по завершении обработки запроса.
func (s *Server) recordMetrics(start time.Time, st *processState) {
	s.requestsTotal.WithLabelValues(st.direction, strconv.Itoa(st.status)).Inc()
	s.requestDuration.WithLabelValues().Observe(time.Since(start).Seconds())
	s.tokensEstimated.Add(float64(st.payloadRunes) / 4.0)
	s.logRequest(st.payloadID, st.foundTypes, st.direction, st.status, time.Since(start))
}

// parseRequest разбирает и валидирует тело запроса.
func (s *Server) parseRequest(w http.ResponseWriter, r *http.Request, st *processState) (processRequest, bool) {
	var req processRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.reject(w, st, http.StatusBadRequest, "invalid json")
		return req, false
	}
	if req.Payload == "" || req.PayloadID == "" {
		s.reject(w, st, http.StatusBadRequest, "missing fields")
		return req, false
	}
	st.payloadRunes = utf8.RuneCountInString(req.Payload)
	st.payloadID = req.PayloadID
	return req, true
}

// acquireSlot занимает слот параллелизма. Возвращает идемпотентную
// функцию освобождения слота.
func (s *Server) acquireSlot(w http.ResponseWriter, st *processState) (func(), bool) {
	select {
	case s.inflight <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-s.inflight }) }, true
	default:
		s.reject(w, st, http.StatusTooManyRequests, "overloaded")
		return nil, false
	}
}

// reject записывает ответ об ошибке и помечает направление как reject.
func (s *Server) reject(w http.ResponseWriter, st *processState, status int, msg string) {
	st.status = status
	st.direction = directionReject
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "1")
	}
	s.writeResult(w, status, msg)
}

// handleMask обрабатывает ветку маскирования нового payload.
func (s *Server) handleMask(
	w http.ResponseWriter, st *processState, req processRequest,
	consumer *config.Consumer, release func(),
) {
	masked, tokens, types, err := s.maskPayload(req.Payload, consumer)
	if err != nil {
		s.reject(w, st, http.StatusServiceUnavailable, "internal error")
		return
	}
	st.foundTypes = types
	if err := s.store.Put(consumer.ID, req.PayloadID, req.Payload, masked, tokens); err != nil {
		if errors.Is(err, store.ErrCapacityExceeded) {
			release()
			s.reject(w, st, http.StatusTooManyRequests, "overloaded")
			return
		}
		s.reject(w, st, http.StatusServiceUnavailable, "internal error")
		return
	}
	st.status = http.StatusOK
	st.direction = directionMask
	s.writeResult(w, st.status, masked)
}

// handleUnmask обрабатывает ветку демаскирования существующего payload.
func (s *Server) handleUnmask(
	w http.ResponseWriter, st *processState, req processRequest,
	consumer *config.Consumer, rec store.Record,
) {
	hash := sha256.Sum256([]byte(req.Payload))
	if hash == rec.SourceHash {
		st.status = http.StatusOK
		st.direction = directionMask
		s.writeResult(w, st.status, rec.Masked)
		return
	}
	st.direction = "unmask"
	if !consumer.UnmaskEnabled {
		s.reject(w, st, http.StatusForbidden, "forbidden")
		return
	}
	if !containsAnyToken(req.Payload, rec.Tokens) {
		s.reject(w, st, http.StatusConflict, "conflict")
		return
	}
	restored := pii.Unmask(req.Payload, rec.Tokens)
	st.status = http.StatusOK
	s.writeResult(w, st.status, restored)
}

func (s *Server) maskPayload(payload string, consumer *config.Consumer) (masked string, tokens map[string]string, foundTypes []string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in detect/mask: %v", r)
		}
	}()
	var entities []pii.Entity
	seen := make(map[pii.Type]bool)
	for _, d := range s.detectors {
		for _, e := range d.Find(payload) {
			if !consumer.AllowsType(e.Type) {
				continue
			}
			entities = append(entities, e)
			if !seen[e.Type] {
				seen[e.Type] = true
				foundTypes = append(foundTypes, string(e.Type))
				s.entitiesTotal.WithLabelValues(string(e.Type)).Inc()
			}
		}
	}
	masked, tokens, err = pii.Mask(payload, entities)
	return
}

func (s *Server) authenticate(r *http.Request) (*config.Consumer, bool) {
	key := ""
	if h := r.Header.Get("X-API-Key"); h != "" {
		key = h
	} else if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		key = strings.TrimPrefix(auth, "Bearer ")
	}
	if key != "" {
		return s.registry.Authenticate(key)
	}
	if s.publicConsumer != "" {
		if c, ok := s.registry.ByID(s.publicConsumer); ok && c.Enabled {
			return c, true
		}
	}
	return nil, false
}

func (s *Server) writeResult(w http.ResponseWriter, status int, result string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"result": result})
}

func containsAnyToken(payload string, tokens map[string]string) bool {
	for token := range tokens {
		if strings.Contains(payload, token) {
			return true
		}
	}
	return false
}

func (s *Server) logRequest(payloadID string, types []string, direction string, status int, dur time.Duration) {
	pidHash := ""
	if payloadID != "" {
		h := sha256.Sum256([]byte(payloadID))
		pidHash = fmt.Sprintf("%x", h)[:12]
	}
	entry := map[string]interface{}{
		"time":           time.Now().Format(time.RFC3339Nano),
		"payload_id_hash": pidHash,
		"types":          types,
		"direction":      direction,
		"status":         status,
		"duration_ms":    float64(dur.Microseconds()) / 1000.0,
	}
	b, _ := json.Marshal(entry)
	s.logger.Println(string(b))
}