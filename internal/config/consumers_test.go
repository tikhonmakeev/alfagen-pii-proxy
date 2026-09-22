package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tihon/pii-proxy-deepseek/internal/pii"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "consumers.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadValid(t *testing.T) {
	t.Setenv("KEY_A", "secret-a")
	t.Setenv("KEY_B", "secret-b")
	t.Setenv("KEY_C", "secret-c")

	path := writeConfig(t, `
consumers:
  - id: system_a
    api_key_env: KEY_A
    enabled: true
    allowed_types: [email, phone]
    unmask_enabled: true
  - id: system_b
    api_key_env: KEY_B
    enabled: true
    allowed_types: []
    unmask_enabled: false
  - id: system_c
    api_key_env: KEY_C
    enabled: false
    allowed_types: [full_name]
    unmask_enabled: true
`)
	reg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if c, ok := reg.Authenticate("secret-a"); !ok || c.ID != "system_a" {
		t.Fatalf("authenticate system_a failed: %+v ok=%v", c, ok)
	}
	if c, ok := reg.Authenticate("secret-b"); !ok || c.ID != "system_b" {
		t.Fatalf("authenticate system_b failed: %+v ok=%v", c, ok)
	}
	// system_c disabled → not authenticated
	if _, ok := reg.Authenticate("secret-c"); ok {
		t.Fatal("disabled consumer should not authenticate")
	}
	if _, ok := reg.Authenticate("wrong-key"); ok {
		t.Fatal("unknown key should not authenticate")
	}
	if c, ok := reg.ByID("system_c"); !ok || c.ID != "system_c" {
		t.Fatalf("ByID system_c failed: %+v ok=%v", c, ok)
	}
}

func TestEmptyConsumers(t *testing.T) {
	path := writeConfig(t, "consumers: []\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for empty consumers")
	}
}

func TestDuplicateID(t *testing.T) {
	t.Setenv("KEY_A", "secret-a")
	t.Setenv("KEY_B", "secret-b")
	path := writeConfig(t, `
consumers:
  - id: dup
    api_key_env: KEY_A
    enabled: true
  - id: dup
    api_key_env: KEY_B
    enabled: true
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for duplicate id")
	}
}

func TestInvalidID(t *testing.T) {
	t.Setenv("KEY_A", "secret-a")
	path := writeConfig(t, `
consumers:
  - id: "bad id"
    api_key_env: KEY_A
    enabled: true
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid id with space")
	}

	long := make([]byte, 65)
	for i := range long {
		long[i] = 'a'
	}
	path = writeConfig(t, `
consumers:
  - id: "`+string(long)+`"
    api_key_env: KEY_A
    enabled: true
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for id longer than 64 chars")
	}
}

func TestUnknownType(t *testing.T) {
	t.Setenv("KEY_A", "secret-a")
	path := writeConfig(t, `
consumers:
  - id: sys
    api_key_env: KEY_A
    enabled: true
    allowed_types: [email, not_a_real_type]
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for unknown allowed type")
	}
}

func TestMultipleDocuments(t *testing.T) {
	t.Setenv("KEY_A", "secret-a")
	path := writeConfig(t, `
consumers:
  - id: sys
    api_key_env: KEY_A
    enabled: true
---
consumers:
  - id: other
    api_key_env: KEY_A
    enabled: true
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for multiple yaml documents")
	}
}

func TestUnknownField(t *testing.T) {
	t.Setenv("KEY_A", "secret-a")
	path := writeConfig(t, `
consumers:
  - id: sys
    api_key_env: KEY_A
    enabled: true
    allowed_typess: [email]
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestDuplicateAPIKey(t *testing.T) {
	t.Setenv("KEY_A", "secret-a")
	t.Setenv("KEY_B", "secret-a")
	path := writeConfig(t, `
consumers:
  - id: sys_a
    api_key_env: KEY_A
    enabled: true
  - id: sys_b
    api_key_env: KEY_B
    enabled: true
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for duplicate api key value")
	}
}

func TestAllowsTypeEmpty(t *testing.T) {
	c := &Consumer{AllowedTypes: nil}
	if !c.AllowsType(pii.Email) || !c.AllowsType(pii.Phone) {
		t.Fatal("empty allowed_types should allow all types")
	}
}

func TestAllowsTypeExplicit(t *testing.T) {
	c := &Consumer{AllowedTypes: []pii.Type{pii.Email}}
	if !c.AllowsType(pii.Email) {
		t.Fatal("explicit type should be allowed")
	}
	if c.AllowsType(pii.Phone) {
		t.Fatal("non-listed type should be disallowed")
	}
}

func TestUnmaskEnabledField(t *testing.T) {
	t.Setenv("KEY_A", "secret-a")
	path := writeConfig(t, `
consumers:
  - id: sys
    api_key_env: KEY_A
    enabled: true
    unmask_enabled: false
`)
	reg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	c, ok := reg.ByID("sys")
	if !ok {
		t.Fatal("consumer not found")
	}
	if c.UnmaskEnabled {
		t.Fatal("unmask_enabled should be false")
	}
}

func TestEmptyAPIKey(t *testing.T) {
	// Переменная окружения пустая — ключ пустой, но загрузка не падает.
	t.Setenv("NOT_SET_ENV_VAR", "")
	path := writeConfig(t, `
consumers:
  - id: public_sys
    api_key_env: NOT_SET_ENV_VAR
    enabled: true
`)
	reg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if _, ok := reg.Authenticate(""); ok {
		t.Fatal("Authenticate(\"\") should return false")
	}
	c, ok := reg.ByID("public_sys")
	if !ok {
		t.Fatal("ByID should find consumer with empty api key")
	}
	if c.APIKey != "" {
		t.Fatalf("expected empty APIKey, got %q", c.APIKey)
	}
}

func TestAuthenticateEmptyAlwaysFalse(t *testing.T) {
	t.Setenv("KEY_A", "secret-a")
	t.Setenv("NOT_SET_ENV_VAR", "")
	path := writeConfig(t, `
consumers:
  - id: sys_a
    api_key_env: KEY_A
    enabled: true
  - id: sys_b
    api_key_env: NOT_SET_ENV_VAR
    enabled: true
`)
	reg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if _, ok := reg.Authenticate(""); ok {
		t.Fatal("Authenticate(\"\") should always return false")
	}
}

func TestTwoEmptyAPIKeysNotDuplicate(t *testing.T) {
	t.Setenv("NOT_SET_A", "")
	t.Setenv("NOT_SET_B", "")
	path := writeConfig(t, `
consumers:
  - id: sys_a
    api_key_env: NOT_SET_A
    enabled: true
  - id: sys_b
    api_key_env: NOT_SET_B
    enabled: true
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("two empty api keys should not be a duplicate: %v", err)
	}
}