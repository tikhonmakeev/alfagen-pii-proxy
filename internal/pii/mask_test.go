package pii

import (
	"strings"
	"testing"
)

func TestMaskRoundTrip(t *testing.T) {
	text := "Клиент Иванов Иван Иванович, телефон +7 (999) 123-45-67, почта ivan@example.org"
	entities := []Entity{
		{Type: FullName, Start: 13, End: 51, Value: "Иванов Иван Иванович"},
		{Type: Phone, Start: 68, End: 86, Value: "+7 (999) 123-45-67"},
		{Type: Email, Start: 99, End: 115, Value: "ivan@example.org"},
	}
	masked, tokens, err := Mask(text, entities)
	if err != nil {
		t.Fatalf("Mask error: %v", err)
	}
	if len(tokens) != 3 {
		t.Fatalf("expected 3 tokens, got %d", len(tokens))
	}
	restored := Unmask(masked, tokens)
	if restored != text {
		t.Fatalf("round trip mismatch:\n got %q\nwant %q", restored, text)
	}
}

func TestMaskSharedNonce(t *testing.T) {
	text := "Иван Петров и Анна Иванова"
	entities := []Entity{
		{Type: FullName, Start: 0, End: 21, Value: "Иван Петров"},
		{Type: FullName, Start: 25, End: 48, Value: "Анна Иванова"},
	}
	_, tokens, err := Mask(text, entities)
	if err != nil {
		t.Fatalf("Mask error: %v", err)
	}
	var nonces []string
	for token := range tokens {
		inner := strings.TrimSuffix(strings.TrimPrefix(token, "[PII_"), "]")
		parts := strings.SplitN(inner, "_", 2)
		if len(parts) != 2 {
			t.Fatalf("unexpected token format: %q", token)
		}
		nonces = append(nonces, parts[0])
	}
	if nonces[0] != nonces[1] {
		t.Fatalf("expected shared nonce, got %v", nonces)
	}
}

func TestMaskReorderedRepeatedTokens(t *testing.T) {
	text := "Иван Петров и Анна Иванова"
	entities := []Entity{
		{Type: FullName, Start: 0, End: 21, Value: "Иван Петров"},
		{Type: FullName, Start: 25, End: 48, Value: "Анна Иванова"},
	}
	_, tokens, err := Mask(text, entities)
	if err != nil {
		t.Fatalf("Mask error: %v", err)
	}
	var tokList []string
	for token := range tokens {
		tokList = append(tokList, token)
	}
	if len(tokList) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokList))
	}
	// Переставляем токены местами и повторяем один дважды.
	reordered := tokList[1] + " " + tokList[0] + " " + tokList[1]
	restored := Unmask(reordered, tokens)
	want := tokens[tokList[1]] + " " + tokens[tokList[0]] + " " + tokens[tokList[1]]
	if restored != want {
		t.Fatalf("reordered unmask mismatch:\n got %q\nwant %q", restored, want)
	}
}

func TestMaskOverlapping(t *testing.T) {
	text := "Иван Петров Иванович"
	entities := []Entity{
		{Type: FullName, Start: 0, End: 21, Value: "Иван Петров"},
		{Type: FullName, Start: 9, End: 38, Value: "Петров Иванович"},
	}
	masked, tokens, err := Mask(text, entities)
	if err != nil {
		t.Fatalf("Mask error: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token after overlap resolution, got %d", len(tokens))
	}
	restored := Unmask(masked, tokens)
	if restored != text {
		t.Fatalf("overlap round trip mismatch:\n got %q\nwant %q", restored, text)
	}
}

func TestMaskEmptyEntities(t *testing.T) {
	text := "Просто текст без персональных данных."
	masked, tokens, err := Mask(text, nil)
	if err != nil {
		t.Fatalf("Mask error: %v", err)
	}
	if masked != text {
		t.Fatalf("expected unchanged text, got %q", masked)
	}
	if len(tokens) != 0 {
		t.Fatalf("expected empty tokens, got %d", len(tokens))
	}
}

func TestUnmaskUnknownToken(t *testing.T) {
	masked := "Привет [PII_unknown_token_0] мир"
	tokens := map[string]string{"[PII_known_0]": "значение"}
	restored := Unmask(masked, tokens)
	if restored != masked {
		t.Fatalf("unknown token should be left as-is, got %q", restored)
	}
}