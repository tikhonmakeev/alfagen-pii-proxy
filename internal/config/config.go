package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tihon/pii-proxy-deepseek/internal/pii"
)

var idRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Consumer — одна система-потребитель.
type Consumer struct {
	ID            string
	APIKey        string
	Enabled       bool
	AllowedTypes  []pii.Type
	UnmaskEnabled bool
}

// AllowsType возвращает true, если тип разрешён для маскирования.
func (c *Consumer) AllowsType(t pii.Type) bool {
	if len(c.AllowedTypes) == 0 {
		return true
	}
	for _, at := range c.AllowedTypes {
		if at == t {
			return true
		}
	}
	return false
}

// Registry — реестр систем-потребителей.
type Registry struct {
	consumers []*Consumer
	byID      map[string]*Consumer
	byKey     map[string]*Consumer
}

// Load загружает и валидирует реестр потребителей из YAML-файла.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// rawConsumer — промежуточное представление потребителя из YAML.
type rawConsumer struct {
	ID            string   `yaml:"id"`
	APIKeyEnv     string   `yaml:"api_key_env"`
	Enabled       bool     `yaml:"enabled"`
	AllowedTypes  []string `yaml:"allowed_types"`
	UnmaskEnabled bool     `yaml:"unmask_enabled"`
}

// Parse разбирает и валидирует реестр потребителей из YAML-данных.
func Parse(data []byte) (*Registry, error) {
	if err := validateSingleDocument(data); err != nil {
		return nil, err
	}

	var raw struct {
		Consumers []rawConsumer `yaml:"consumers"`
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	if len(raw.Consumers) == 0 {
		return nil, errors.New("consumers list must not be empty")
	}

	reg := &Registry{
		byID:  make(map[string]*Consumer, len(raw.Consumers)),
		byKey: make(map[string]*Consumer, len(raw.Consumers)),
	}
	seenKeys := make(map[string]string, len(raw.Consumers))

	for i, rc := range raw.Consumers {
		c, err := validateConsumer(i, rc, reg, seenKeys)
		if err != nil {
			return nil, err
		}
		reg.consumers = append(reg.consumers, c)
		reg.byID[c.ID] = c
		if c.APIKey != "" {
			reg.byKey[c.APIKey] = c
		}
	}
	return reg, nil
}

// validateConsumer проверяет одного потребителя и строит его Consumer.
func validateConsumer(i int, rc rawConsumer, reg *Registry, seenKeys map[string]string) (*Consumer, error) {
	if !idRe.MatchString(rc.ID) {
		return nil, fmt.Errorf("consumer %d: invalid id %q", i, rc.ID)
	}
	if _, dup := reg.byID[rc.ID]; dup {
		return nil, fmt.Errorf("duplicate consumer id %q", rc.ID)
	}

	apiKey := os.Getenv(rc.APIKeyEnv)
	if apiKey != "" {
		if prev, dup := seenKeys[apiKey]; dup {
			return nil, fmt.Errorf("consumer %q and %q share the same api key", prev, rc.ID)
		}
		seenKeys[apiKey] = rc.ID
	}

	allowed, err := parseAllowedTypes(rc.ID, rc.AllowedTypes)
	if err != nil {
		return nil, err
	}

	return &Consumer{
		ID:            rc.ID,
		APIKey:        apiKey,
		Enabled:       rc.Enabled,
		AllowedTypes:  allowed,
		UnmaskEnabled: rc.UnmaskEnabled,
	}, nil
}

// parseAllowedTypes преобразует список типов из строк в pii.Type.
func parseAllowedTypes(id string, types []string) ([]pii.Type, error) {
	allowed := make([]pii.Type, 0, len(types))
	for _, t := range types {
		pt := pii.Type(t)
		if !knownType(pt) {
			return nil, fmt.Errorf("consumer %q: unknown allowed type %q", id, t)
		}
		allowed = append(allowed, pt)
	}
	return allowed, nil
}

// Authenticate возвращает потребителя по API-ключу, если он найден и
// включён.
func (r *Registry) Authenticate(apiKey string) (*Consumer, bool) {
	c, ok := r.byKey[apiKey]
	if !ok || !c.Enabled {
		return nil, false
	}
	return c, true
}

// ByID возвращает потребителя по id (без проверки enabled).
func (r *Registry) ByID(id string) (*Consumer, bool) {
	c, ok := r.byID[id]
	return c, ok
}

func knownType(t pii.Type) bool {
	for _, at := range pii.AllTypes {
		if at == t {
			return true
		}
	}
	return false
}

// validateSingleDocument проверяет, что YAML содержит ровно один документ.
func validateSingleDocument(data []byte) error {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	var first interface{}
	if err := dec.Decode(&first); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}
	var second interface{}
	if err := dec.Decode(&second); err == nil {
		return errors.New("yaml file must contain exactly one document")
	}
	return nil
}