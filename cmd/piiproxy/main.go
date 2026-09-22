// Пакет piiproxy — точка входа HTTP-сервиса, который принимает запросы,
// маскирует персональные данные и проксирует их к системам-потребителям.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/tihon/pii-proxy-deepseek/internal/config"
	"github.com/tihon/pii-proxy-deepseek/internal/httpapi"
	"github.com/tihon/pii-proxy-deepseek/internal/pii"
	"github.com/tihon/pii-proxy-deepseek/internal/store"
)

type settings struct {
	listenAddr     string
	metricsAddr    string
	tlsCertFile    string
	tlsKeyFile     string
	consumersPath  string
	publicConsumer string
	stateTTL       time.Duration
	stateMaxEntry  int
	stateMaxMB     int
	maxInflight    int
}

func main() {
	cfg, err := loadSettings()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}

	registry, err := config.Load(cfg.consumersPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "consumers config error:", err)
		os.Exit(1)
	}

	st := store.New(cfg.stateTTL, cfg.stateMaxEntry, cfg.stateMaxMB)
	defer st.Close()

	detectors := pii.Registry()
	server := httpapi.New(detectors, registry, st, cfg.publicConsumer, cfg.maxInflight)

	metricsSrv := server.StartMetrics(cfg.metricsAddr)

	mainSrv := &http.Server{
		Addr:    cfg.listenAddr,
		Handler: server.Handler(),
	}

	errCh := make(chan error, 1)
	go func() {
		if cfg.tlsCertFile != "" && cfg.tlsKeyFile != "" {
			errCh <- mainSrv.ListenAndServeTLS(cfg.tlsCertFile, cfg.tlsKeyFile)
		} else {
			errCh <- mainSrv.ListenAndServe()
		}
	}()

	// Ждём, пока listener начнёт слушать, либо ошибку запуска.
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "server error:", err)
			os.Exit(1)
		}
	case <-time.After(100 * time.Millisecond):
	}

	logReady(cfg.listenAddr)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = mainSrv.Shutdown(ctx)
	_ = metricsSrv.Shutdown(ctx)
}

func loadSettings() (*settings, error) {
	cfg := &settings{
		listenAddr:     getenv("LISTEN_ADDR", "127.0.0.1:8080"),
		metricsAddr:    getenv("METRICS_ADDR", "127.0.0.1:9090"),
		tlsCertFile:    os.Getenv("TLS_CERT_FILE"),
		tlsKeyFile:     os.Getenv("TLS_KEY_FILE"),
		consumersPath:  getenv("CONSUMERS_CONFIG", "consumers.yaml"),
		publicConsumer: os.Getenv("PUBLIC_CONSUMER"),
	}

	var err error
	if cfg.stateTTL, err = parseDurationSeconds("STATE_TTL_SECONDS", 1800); err != nil {
		return nil, err
	}
	if cfg.stateMaxEntry, err = parseInt("STATE_MAX_ENTRIES", 400000); err != nil {
		return nil, err
	}
	if cfg.stateMaxMB, err = parseInt("STATE_MAX_MB", 512); err != nil {
		return nil, err
	}
	if cfg.maxInflight, err = parseInt("MAX_INFLIGHT", 64); err != nil {
		return nil, err
	}
	return cfg, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseDurationSeconds(key string, def int) (time.Duration, error) {
	v := getenv(key, strconv.Itoa(def))
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid integer %q", key, v)
	}
	return time.Duration(n) * time.Second, nil
}

func parseInt(key string, def int) (int, error) {
	v := getenv(key, strconv.Itoa(def))
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid integer %q", key, v)
	}
	return n, nil
}

func logReady(addr string) {
	entry := map[string]string{"msg": "ready", "address": addr}
	b, _ := json.Marshal(entry)
	fmt.Fprintln(os.Stdout, string(b))
}