package pii

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Mask заменяет каждую сущность в тексте на токен вида
// [PII_<hex>_<тип>_<порядковыйномер>]. Все сущности одного вызова
// используют один и тот же случайный nonce. Возвращает замаскированный
// текст и map от токена к исходному значению.
func Mask(text string, entities []Entity) (string, map[string]string, error) {
	if len(entities) == 0 {
		return text, map[string]string{}, nil
	}
	nonce, err := randomHex()
	if err != nil {
		return "", nil, err
	}

	// Сортируем по длине span (убывание), затем по Confidence (убывание),
	// затем по Start (возрастание), чтобы при пересечении оставить самую
	// длинную сущность, а при равной длине — с большей уверенностью.
	sorted := make([]Entity, len(entities))
	copy(sorted, entities)
	sort.Slice(sorted, func(i, j int) bool {
		li, lj := sorted[i].End-sorted[i].Start, sorted[j].End-sorted[j].Start
		if li != lj {
			return li > lj
		}
		if sorted[i].Confidence != sorted[j].Confidence {
			return sorted[i].Confidence > sorted[j].Confidence
		}
		return sorted[i].Start < sorted[j].Start
	})

	var kept []Entity
	for _, e := range sorted {
		overlap := false
		for _, k := range kept {
			if e.Start < k.End && k.Start < e.End {
				overlap = true
				break
			}
		}
		if !overlap {
			kept = append(kept, e)
		}
	}

	// Порядковый номер — по порядку появления в тексте.
	sort.Slice(kept, func(i, j int) bool { return kept[i].Start < kept[j].Start })

	tokens := make(map[string]string, len(kept))
	masked := text
	for i := len(kept) - 1; i >= 0; i-- {
		e := kept[i]
		token := fmt.Sprintf("[PII_%s_%s_%d]", nonce, e.Type, i)
		tokens[token] = e.Value
		masked = masked[:e.Start] + token + masked[e.End:]
	}
	return masked, tokens, nil
}

// Unmask заменяет каждое вхождение каждого токена из tokens на его
// исходное значение. Неизвестные токены остаются без изменений.
func Unmask(maskedText string, tokens map[string]string) string {
	result := maskedText
	for token, value := range tokens {
		result = strings.ReplaceAll(result, token, value)
	}
	return result
}

// randomHex возвращает случайную hex-строку длиной 8-12 символов.
func randomHex() (string, error) {
	n := 4 + randInt(3) // 4-6 байт = 8-12 hex-символов
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randInt(max int) int {
	b := make([]byte, 1)
	if _, err := rand.Read(b); err != nil {
		return 0
	}
	return int(b[0]) % max
}