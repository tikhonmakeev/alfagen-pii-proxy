package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tihon/pii-proxy-deepseek/internal/config"
	"github.com/tihon/pii-proxy-deepseek/internal/pii"
	"github.com/tihon/pii-proxy-deepseek/internal/store"
)

const (
	secretA        = "secret-a"
	secretB        = "secret-b"
	envKeyA        = "KEY_A"
	envKeyB        = "KEY_B"
	pid1           = "pid-1"
	reqErrFmt      = "request error: %v"
	exp200Fmt      = "expected 200, got %d"
	gotQFmt        = "got %q"
	configParseFmt = "config parse: %v"
	ivanPetrov     = "Иван Петров"
	phoneStr       = "+7 (999) 123-45-67"
	sysA           = "sys_a"
	sysB           = "sys_b"
)

func testRegistry(t *testing.T) *config.Registry {
	t.Helper()
	t.Setenv(envKeyA, secretA)
	t.Setenv(envKeyB, secretB)
	reg, err := config.Parse([]byte(`
consumers:
  - id: sys_a
    api_key_env: KEY_A
    enabled: true
    allowed_types: []
    unmask_enabled: true
  - id: sys_b
    api_key_env: KEY_B
    enabled: true
    allowed_types: []
    unmask_enabled: false
`))
	if err != nil {
		t.Fatalf(configParseFmt, err)
	}
	return reg
}

func newTestServer(t *testing.T, reg *config.Registry, publicConsumer string, maxInflight int) *Server {
	t.Helper()
	st := store.New(time.Minute, 1000, 100)
	t.Cleanup(st.Close)
	return New(pii.Registry(), reg, st, publicConsumer, maxInflight)
}

func doProcess(t *testing.T, srv *httptest.Server, apiKey, payload, payloadID string) *http.Response {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"payload": payload, "payload_id": payloadID})
	req, _ := http.NewRequest("POST", srv.URL+"/process", bytes.NewReader(body))
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf(reqErrFmt, err)
	}
	return resp
}

func readResult(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	var out struct {
		Result string `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out.Result
}

func TestMaskNewPayload(t *testing.T) {
	reg := testRegistry(t)
	srv := httptest.NewServer(newTestServer(t, reg, "", 10).Handler())
	defer srv.Close()

	resp := doProcess(t, srv, secretA, "Иван Петров, телефон +7 (999) 123-45-67", pid1)
	if resp.StatusCode != 200 {
		t.Fatalf(exp200Fmt, resp.StatusCode)
	}
	result := readResult(t, resp)
	if !strings.Contains(result, "[PII_") {
		t.Fatalf("expected tokens in result, got %q", result)
	}
	if strings.Contains(result, "Иван") || strings.Contains(result, phoneStr) {
		t.Fatalf("PII should be masked, got %q", result)
	}
}

func TestRepeatSamePayload(t *testing.T) {
	reg := testRegistry(t)
	srv := httptest.NewServer(newTestServer(t, reg, "", 10).Handler())
	defer srv.Close()

	first := readResult(t, doProcess(t, srv, secretA, ivanPetrov, pid1))
	second := readResult(t, doProcess(t, srv, secretA, ivanPetrov, pid1))
	if first != second {
		t.Fatalf("repeat should return same mask: %q vs %q", first, second)
	}
}

func TestUnmaskLLMResponse(t *testing.T) {
	reg := testRegistry(t)
	srv := httptest.NewServer(newTestServer(t, reg, "", 10).Handler())
	defer srv.Close()

	masked := readResult(t, doProcess(t, srv, secretA, ivanPetrov, pid1))
	// Эмулируем ответ LLM: токен вставлен в другой текст.
	llmResp := "Клиент: " + masked + " подтвердил заявку"
	resp := doProcess(t, srv, secretA, llmResp, pid1)
	if resp.StatusCode != 200 {
		t.Fatalf(exp200Fmt, resp.StatusCode)
	}
	restored := readResult(t, resp)
	if !strings.Contains(restored, ivanPetrov) {
		t.Fatalf("expected restored name, got %q", restored)
	}
}

func TestUnmaskNoKnownToken(t *testing.T) {
	reg := testRegistry(t)
	srv := httptest.NewServer(newTestServer(t, reg, "", 10).Handler())
	defer srv.Close()

	_ = readResult(t, doProcess(t, srv, secretA, ivanPetrov, pid1))
	resp := doProcess(t, srv, secretA, "Совершенно другой текст без токенов", pid1)
	if resp.StatusCode != 409 {
		t.Fatalf("expected 409, got %d", resp.StatusCode)
	}
}

func TestUnmaskDisabled(t *testing.T) {
	reg := testRegistry(t)
	srv := httptest.NewServer(newTestServer(t, reg, "", 10).Handler())
	defer srv.Close()

	// sys_b имеет unmask_enabled=false.
	masked := readResult(t, doProcess(t, srv, secretB, ivanPetrov, pid1))
	llmResp := "Клиент: " + masked
	resp := doProcess(t, srv, secretB, llmResp, pid1)
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestUnauthorized(t *testing.T) {
	reg := testRegistry(t)
	srv := httptest.NewServer(newTestServer(t, reg, "", 10).Handler())
	defer srv.Close()

	resp := doProcess(t, srv, "", ivanPetrov, pid1)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestPublicConsumer(t *testing.T) {
	reg := testRegistry(t)
	srv := httptest.NewServer(newTestServer(t, reg, sysA, 10).Handler())
	defer srv.Close()

	resp := doProcess(t, srv, "", ivanPetrov, pid1)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 via public consumer, got %d", resp.StatusCode)
	}
}

func TestAllowedTypesFilter(t *testing.T) {
	t.Setenv(envKeyA, secretA)
	reg, err := config.Parse([]byte(`
consumers:
  - id: sys_a
    api_key_env: KEY_A
    enabled: true
    allowed_types: [email]
    unmask_enabled: true
`))
	if err != nil {
		t.Fatalf(configParseFmt, err)
	}
	srv := httptest.NewServer(newTestServer(t, reg, "", 10).Handler())
	defer srv.Close()

	// email маскируется, phone — нет (не в allowed_types).
	resp := doProcess(t, srv, secretA, "ivan@example.org и телефон +7 (999) 123-45-67", pid1)
	result := readResult(t, resp)
	if !strings.Contains(result, "[PII_") {
		t.Fatalf("email should be masked, got %q", result)
	}
	if !strings.Contains(result, phoneStr) {
		t.Fatalf("phone should NOT be masked (not allowed), got %q", result)
	}
}

func TestInvalidJSON(t *testing.T) {
	reg := testRegistry(t)
	srv := httptest.NewServer(newTestServer(t, reg, "", 10).Handler())
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/process", strings.NewReader("{not json"))
	req.Header.Set("X-API-Key", secretA)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf(reqErrFmt, err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	result := readResult(t, resp)
	if result == "" {
		t.Fatalf("result should be a non-empty string, got %q", result)
	}
}

func TestConsumerIsolation(t *testing.T) {
	reg := testRegistry(t)
	srv := httptest.NewServer(newTestServer(t, reg, "", 10).Handler())
	defer srv.Close()

	// sys_a создаёт payload_id.
	_ = readResult(t, doProcess(t, srv, secretA, ivanPetrov, pid1))
	// sys_b пытается демаскировать тот же payload_id — не должен раскрыть данные sys_a.
	resp := doProcess(t, srv, secretB, ivanPetrov, pid1)
	// Для sys_b это новый payload_id → маскирование, а не раскрытие.
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 (new masking for sys_b), got %d", resp.StatusCode)
	}
	result := readResult(t, resp)
	if strings.Contains(result, ivanPetrov) {
		t.Fatalf("sys_b should not reveal sys_a data, got %q", result)
	}
}

func TestHealthz(t *testing.T) {
	reg := testRegistry(t)
	srv := httptest.NewServer(newTestServer(t, reg, "", 10).Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf(reqErrFmt, err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf(exp200Fmt, resp.StatusCode)
	}
	if got := readResult(t, resp); got != "ok" {
		t.Fatalf("expected ok, got %q", got)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	reg := testRegistry(t)
	srv := newTestServer(t, reg, "", 10)
	mainSrv := httptest.NewServer(srv.Handler())
	defer mainSrv.Close()
	metricsSrv := httptest.NewServer(srv.MetricsHandler())
	defer metricsSrv.Close()

	// Сначала делаем /process запрос, чтобы метрики были записаны.
	_ = readResult(t, doProcess(t, mainSrv, secretA, ivanPetrov, pid1))

	resp, err := http.Get(metricsSrv.URL + "/")
	if err != nil {
		t.Fatalf(reqErrFmt, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf(exp200Fmt, resp.StatusCode)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if !strings.Contains(buf.String(), "pii_requests_total") {
		t.Fatalf("expected pii_requests_total metric")
	}
	if !strings.Contains(buf.String(), "pii_entities_total") {
		t.Fatalf("expected pii_entities_total metric")
	}
}