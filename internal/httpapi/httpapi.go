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

func (s *Server) healthzHandler(w http.ResponseWriter, r *http.Request) {
	s.writeResult(w, http.StatusOK, "ok")
}

func (s *Server) processHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := http.StatusOK
	direction := directionMask
	var foundTypes []string
	payloadRunes := 0
	payloadID := ""

	defer func() {
		s.requestsTotal.WithLabelValues(direction, strconv.Itoa(status)).Inc()
		s.requestDuration.WithLabelValues().Observe(time.Since(start).Seconds())
		s.tokensEstimated.Add(float64(payloadRunes) / 4.0)
		s.logRequest(payloadID, foundTypes, direction, status, time.Since(start))
	}()

	var req processRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		status = http.StatusBadRequest
		direction = directionReject
		s.writeResult(w, status, "invalid json")
		return
	}
	if req.Payload == "" || req.PayloadID == "" {
		status = http.StatusBadRequest
		direction = directionReject
		s.writeResult(w, status, "missing fields")
		return
	}
	payloadRunes = utf8.RuneCountInString(req.Payload)
	payloadID = req.PayloadID

	consumer, ok := s.authenticate(r)
	if !ok {
		status = http.StatusUnauthorized
		direction = directionReject
		s.writeResult(w, status, "unauthorized")
		return
	}

	slotAcquired := false
	select {
	case s.inflight <- struct{}{}:
		slotAcquired = true
		defer func() {
			if slotAcquired {
				<-s.inflight
			}
		}()
	default:
		status = http.StatusTooManyRequests
		direction = directionReject
		w.Header().Set("Retry-After", "1")
		s.writeResult(w, status, "overloaded")
		return
	}

	rec, found := s.store.Get(consumer.ID, req.PayloadID)
	if !found {
		masked, tokens, types, err := s.maskPayload(req.Payload, consumer)
		if err != nil {
			status = http.StatusServiceUnavailable
			direction = directionReject
			s.writeResult(w, status, "internal error")
			return
		}
		foundTypes = types
		if err := s.store.Put(consumer.ID, req.PayloadID, req.Payload, masked, tokens); err != nil {
			if errors.Is(err, store.ErrCapacityExceeded) {
				<-s.inflight
				slotAcquired = false
				status = http.StatusTooManyRequests
				direction = directionReject
				w.Header().Set("Retry-After", "1")
				s.writeResult(w, status, "overloaded")
				return
			}
			status = http.StatusServiceUnavailable
			direction = directionReject
			s.writeResult(w, status, "internal error")
			return
		}
		status = http.StatusOK
		direction = directionMask
		s.writeResult(w, status, masked)
		return
	}

	hash := sha256.Sum256([]byte(req.Payload))
	if hash == rec.SourceHash {
		status = http.StatusOK
		direction = directionMask
		s.writeResult(w, status, rec.Masked)
		return
	}

	direction = "unmask"
	if !consumer.UnmaskEnabled {
		status = http.StatusForbidden
		direction = directionReject
		s.writeResult(w, status, "forbidden")
		return
	}
	if !containsAnyToken(req.Payload, rec.Tokens) {
		status = http.StatusConflict
		direction = directionReject
		s.writeResult(w, status, "conflict")
		return
	}
	restored := pii.Unmask(req.Payload, rec.Tokens)
	status = http.StatusOK
	s.writeResult(w, status, restored)
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