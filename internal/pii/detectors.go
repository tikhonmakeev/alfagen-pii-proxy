package pii

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// regexpDetector — детектор на основе регулярного выражения, где всё
// совпадение целиком является значением.
type regexpDetector struct {
	typ  Type
	re   *regexp.Regexp
	conf float64
}

func (d *regexpDetector) Type() Type { return d.typ }

func (d *regexpDetector) Find(text string) []Entity {
	lower := strings.ToLower(text)
	var out []Entity
	for _, loc := range d.re.FindAllStringIndex(lower, -1) {
		start, end := loc[0], loc[1]
		out = append(out, Entity{
			Type:       d.typ,
			Start:      start,
			End:        end,
			Value:      text[start:end],
			Confidence: d.conf,
		})
	}
	return out
}

// labelValueDetector — детектор, требующий метку перед значением.
// Значение — это группа 1; метка и разделитель исключаются из Value.
type labelValueDetector struct {
	typ  Type
	re   *regexp.Regexp
	conf float64
}

func (d *labelValueDetector) Type() Type { return d.typ }

func (d *labelValueDetector) Find(text string) []Entity {
	lower := strings.ToLower(text)
	var out []Entity
	for _, m := range d.re.FindAllStringSubmatchIndex(lower, -1) {
		start, end := m[2], m[3]
		if start < 0 || end < 0 {
			continue
		}
		out = append(out, Entity{
			Type:       d.typ,
			Start:      start,
			End:        end,
			Value:      text[start:end],
			Confidence: d.conf,
		})
	}
	return out
}

// Registry возвращает набор детекторов персональных данных.
func Registry() []Detector {
	return []Detector{
		emailDetector(),
		phoneDetector(),
		cardNumberDetector(),
		cvvDetector(),
		pinDetector(),
		innDetector(),
		passportNumberDetector(),
		driverLicenseDetector(),
		departmentCodeDetector(),
		birthDateDetector(),
		passportIssueDateDetector(),
		postalCodeDetector(),
		countryDetector(),
		cityDetector(),
		streetDetector(),
		houseFlatDetector(),
		addressDetector(),
		citizenshipDetector(),
		birthPlaceDetector(),
		issuingAuthorityDetector(),
		fullNameLabeledDetector(),
		fullNameSurnameFirstDetector(),
		fullNameGivenFirstDetector(),
		surnameInitialsDetector(),
		namePairDetector(),
		cardholderNameDetector(),
	}
}

func emailDetector() Detector {
	return &regexpDetector{
		typ:  Email,
		re:   regexp.MustCompile(`\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`),
		conf: 0.99,
	}
}

func phoneDetector() Detector {
	// +7 (999) 123-45-67, 8 999 123-45-67, 89991234567, 79991234567,
	// 8-903-123-45-67, +7-903-123-45-67, +7 999 111-22-33
	re := regexp.MustCompile(`(?:(?:тел\.?|мобильный|phone)\s*[:.\-]?\s*)?((?:\+?7|8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2})\b`)
	return &phoneDetectorImpl{re: re}
}

// phoneDetectorImpl — детектор телефона, исключающий бесплатные номера 8-800.
type phoneDetectorImpl struct {
	re *regexp.Regexp
}

func (d *phoneDetectorImpl) Type() Type { return Phone }

func (d *phoneDetectorImpl) Find(text string) []Entity {
	lower := strings.ToLower(text)
	var out []Entity
	for _, m := range d.re.FindAllStringSubmatchIndex(lower, -1) {
		start, end := m[2], m[3]
		if start < 0 || end < 0 {
			continue
		}
		if isTollFree(text[start:end]) {
			continue
		}
		out = append(out, Entity{
			Type:       Phone,
			Start:      start,
			End:        end,
			Value:      text[start:end],
			Confidence: 0.95,
		})
	}
	return out
}

// isTollFree возвращает true, если номер начинается с 8-800 или +7 800.
func isTollFree(v string) bool {
	digits := ""
	for _, r := range v {
		if r >= '0' && r <= '9' {
			digits += string(r)
		}
	}
	return strings.HasPrefix(digits, "8800") || strings.HasPrefix(digits, "7800")
}

func cardNumberDetector() Detector {
	// 16 цифр группами по 4, возможен доп. блок 1-3 цифры
	re := regexp.MustCompile(`(?:(?:номер\s+карты|card|карта)\s*[:.\-]?\s*)?(\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}(?:[\s\-]?\d{1,3})?)\b`)
	return &labelValueDetector{
		typ:  CardNumber,
		re:   re,
		conf: 0.97,
	}
}

func cvvDetector() Detector {
	re := regexp.MustCompile(`(?:cvv2?|cvc2?|код\s+безопасности|cvv-код|cvc-код|код\s+на\s+обороте\s+карты|код\s+с\s+обратной\s+стороны\s+карты|три\s+цифры\s+на\s+обороте)\s*[:.\-]?\s*(\d{3,4})\b`)
	return &labelValueDetector{
		typ:  CVV,
		re:   re,
		conf: 0.98,
	}
}

func pinDetector() Detector {
	re := regexp.MustCompile(`(пин-код|пин\s+код|пинкод|pin-код|pin|пин)\s*(?:карты|от\s+карты)?\s*[:.\-]?\s*(\d{4,6})\b`)
	return &pinDetectorImpl{re: re}
}

// pinDetectorImpl — детектор ПИН-кода. Отбрасывает совпадение, если сразу
// после метки идёт буква (например "пингвин 1234").
type pinDetectorImpl struct {
	re *regexp.Regexp
}

func (d *pinDetectorImpl) Type() Type { return PIN }

func (d *pinDetectorImpl) Find(text string) []Entity {
	lower := strings.ToLower(text)
	var out []Entity
	for _, m := range d.re.FindAllStringSubmatchIndex(lower, -1) {
		if e, ok := entityFromLabelMatch(m, text, lower, PIN, 0.98); ok {
			out = append(out, e)
		}
	}
	return out
}

func innDetector() Detector {
	re := regexp.MustCompile(`(инн|inn)\s*(?:клиента|физлица|физ\.лица|получателя|плательщика|заемщика|заёмщика|организации)?\s*[:.\-]?\s*(\d{10}|\d{12})\b`)
	return &innDetectorImpl{re: re}
}

// innDetectorImpl — детектор ИНН. Отбрасывает совпадение, если сразу после
// метки идёт буква (например "иннфо").
type innDetectorImpl struct {
	re *regexp.Regexp
}

func (d *innDetectorImpl) Type() Type { return Inn }

func (d *innDetectorImpl) Find(text string) []Entity {
	lower := strings.ToLower(text)
	var out []Entity
	for _, m := range d.re.FindAllStringSubmatchIndex(lower, -1) {
		if e, ok := entityFromLabelMatch(m, text, lower, Inn, 0.98); ok {
			out = append(out, e)
		}
	}
	return out
}

// followedByLetter возвращает true, если в позиции idx в lower стоит буква
// (ASCII или кириллица). Кириллица в UTF-8 — многобайтовая, поэтому
// проверяется старший байт (0xD0/0xD1).
func followedByLetter(lower string, idx int) bool {
	if idx >= len(lower) {
		return false
	}
	c := lower[idx]
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == 0xD0 || c == 0xD1
}

// entityFromLabelMatch строит Entity из совпадения регулярки с меткой
// (группа 1 — метка, группа 2 — значение). Возвращает false, если
// совпадение невалидно или сразу после метки идёт буква.
func entityFromLabelMatch(m []int, text, lower string, typ Type, conf float64) (Entity, bool) {
	labelEnd := m[3]
	start, end := m[4], m[5]
	if start < 0 || end < 0 {
		return Entity{}, false
	}
	if followedByLetter(lower, labelEnd) {
		return Entity{}, false
	}
	return Entity{
		Type:       typ,
		Start:      start,
		End:        end,
		Value:      text[start:end],
		Confidence: conf,
	}, true
}

func passportNumberDetector() Detector {
	// Форматы: "4509 123456", "4509123456", "28 24 568674", "серия 40 15 № 386540"
	re := regexp.MustCompile(`(?:(?:паспорт|серия|серии)\s+)?(\b\d{4}\s+\d{6}\b|\b\d{10}\b|\b\d{2}\s+\d{2}\s+\d{6}\b)`)
	seriesRe := regexp.MustCompile(`серия\s+(\d{2}\s+\d{2}|\d{4})\s+(?:№|номер)\s+(\d{6})`)
	return &passportNumberDetectorImpl{re: re, seriesRe: seriesRe}
}

// passportNumberDetectorImpl — детектор номера паспорта. Отбрасывает
// совпадение, если последнее или предпоследнее слово перед номером —
// метка другого документа (ИНН, в/у, удостоверение, права).
type passportNumberDetectorImpl struct {
	re       *regexp.Regexp
	seriesRe *regexp.Regexp
}

func (d *passportNumberDetectorImpl) Type() Type { return PassportNumber }

func (d *passportNumberDetectorImpl) Find(text string) []Entity {
	lower := strings.ToLower(text)
	var out []Entity
	for _, m := range d.re.FindAllStringSubmatchIndex(lower, -1) {
		start, end := m[2], m[3]
		if start < 0 || end < 0 {
			continue
		}
		if blockedByDocLabel(lower, start) {
			continue
		}
		out = append(out, Entity{
			Type:       PassportNumber,
			Start:      start,
			End:        end,
			Value:      text[start:end],
			Confidence: 0.9,
		})
	}
	for _, m := range d.seriesRe.FindAllStringSubmatchIndex(lower, -1) {
		if sStart, sEnd := m[2], m[3]; sStart >= 0 && sEnd >= 0 {
			out = append(out, Entity{
				Type:       PassportNumber,
				Start:      sStart,
				End:        sEnd,
				Value:      text[sStart:sEnd],
				Confidence: 0.9,
			})
		}
		if nStart, nEnd := m[4], m[5]; nStart >= 0 && nEnd >= 0 {
			out = append(out, Entity{
				Type:       PassportNumber,
				Start:      nStart,
				End:        nEnd,
				Value:      text[nStart:nEnd],
				Confidence: 0.9,
			})
		}
	}
	return out
}

// blockedByDocLabel возвращает true, если перед позицией start стоит метка
// другого документа.
func blockedByDocLabel(lower string, start int) bool {
	from := start - 40
	if from < 0 {
		from = 0
	}
	ctx := lower[from:start]
	words := docLabelWordRe.FindAllString(ctx, -1)
	if len(words) > 0 && docLabels[words[len(words)-1]] {
		return true
	}
	if len(words) > 1 && docLabels[words[len(words)-2]] {
		return true
	}
	return false
}

func driverLicenseDetector() Detector {
	re := regexp.MustCompile(`(?:в/у\s*№|в/у|ву|вод\.\s*удостоверение|водительское\s+удостоверение|права)\s*[:.\-]?\s*(\d{2}\s+\d{2}\s+\d{6}|\d{4}\s+\d{6}|\d{10})\b`)
	return &labelValueDetector{
		typ:  DriverLicenseNumber,
		re:   re,
		conf: 0.95,
	}
}

func departmentCodeDetector() Detector {
	re := regexp.MustCompile(`(?:(?:код\s+подразделения)\s*[:.\-]?\s*)?(\b\d{3}\-\d{3}\b)`)
	return &labelValueDetector{
		typ:  DepartmentCode,
		re:   re,
		conf: 0.9,
	}
}

func birthDateDetector() Detector {
	// Любая дата в форматах: дд.мм.гггг, мм/дд/гггг, гггг.дд.мм,
	// день месяц-словом год (с вариантами "года"/"г."), ISO гггг-мм-дд,
	// день в кавычках-ёлочках.
	re := regexp.MustCompile(`(?:(?:дата\s+рождения|родился|родилась|д\.р\.)\s*[:.\-]?\s*)?(\d{1,2}[./]\d{1,2}[./]\d{2,4}|\d{4}[./]\d{1,2}[./]\d{1,2}|\d{1,2}-\d{1,2}-\d{4}|\d{4}-\d{2}-\d{2}|«\d{1,2}»\s+(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+\d{2,4}|\d{1,2}\s+(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+\d{2,4}(?:\s+г(?:ода)?\.?)?)`)
	return &dateDetectorImpl{typ: BirthDate, re: re, conf: 0.85}
}

func passportIssueDateDetector() Detector {
	re := regexp.MustCompile(`(?:дата\s+выдачи(?:\s+паспорта)?|выдан|выдана|выдача)\s*[:.\-]?\s*(\d{1,2}[./]\d{1,2}[./]\d{2,4}|\d{4}[./]\d{1,2}[./]\d{1,2}|\d{1,2}-\d{1,2}-\d{4}|\d{4}-\d{2}-\d{2}|«\d{1,2}»\s+(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+\d{2,4}|\d{1,2}\s+(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+\d{2,4}(?:\s+г(?:ода)?\.?)?)`)
	return &dateDetectorImpl{typ: PassportIssueDate, re: re, conf: 0.9}
}

// dateDetectorImpl — детектор даты, отбрасывающий совпадение, если символ
// сразу перед датой — цифра, "-" или ")" (например хвост телефона "23-45-67").
type dateDetectorImpl struct {
	typ  Type
	re   *regexp.Regexp
	conf float64
}

func (d *dateDetectorImpl) Type() Type { return d.typ }

func (d *dateDetectorImpl) Find(text string) []Entity {
	lower := strings.ToLower(text)
	var out []Entity
	for _, m := range d.re.FindAllStringSubmatchIndex(lower, -1) {
		start, end := m[2], m[3]
		if start < 0 || end < 0 {
			continue
		}
		if start > 0 {
			prev := lower[start-1]
			if prev >= '0' && prev <= '9' || prev == '-' || prev == ')' {
				continue
			}
		}
		out = append(out, Entity{
			Type:       d.typ,
			Start:      start,
			End:        end,
			Value:      text[start:end],
			Confidence: d.conf,
		})
	}
	return out
}

func postalCodeDetector() Detector {
	re := regexp.MustCompile(`(?:почтовый\s+индекс|индекс)\s*[:.\-]?\s*(\d{6})\b|\b(\d{6}),\s+(\S)`)
	return &bankFilter{inner: &postalCodeDetectorImpl{re: re}}
}

// postalCodeDetectorImpl — детектор почтового индекса. Поддерживает как
// форму с меткой, так и голые 6 цифр перед запятой и названием города.
type postalCodeDetectorImpl struct {
	re *regexp.Regexp
}

func (d *postalCodeDetectorImpl) Type() Type { return PostalCode }

func (d *postalCodeDetectorImpl) Find(text string) []Entity {
	lower := strings.ToLower(text)
	var out []Entity
	for _, m := range d.re.FindAllStringSubmatchIndex(lower, -1) {
		start, end := -1, -1
		if m[2] >= 0 {
			start, end = m[2], m[3]
		} else if m[4] >= 0 {
			// Голая форма: после запятой и пробела должна идти заглавная
			// буква (название города) или "г.".
			start, end = m[4], m[5]
			next := m[6]
			if next < 0 || next >= len(text) {
				continue
			}
			r, _ := utf8.DecodeRuneInString(text[next:])
			if !unicode.IsUpper(r) && !strings.HasPrefix(text[next:], "г.") {
				continue
			}
		}
		if start < 0 || end < 0 {
			continue
		}
		out = append(out, Entity{
			Type:       PostalCode,
			Start:      start,
			End:        end,
			Value:      text[start:end],
			Confidence: 0.9,
		})
	}
	return out
}

func countryDetector() Detector {
	re := regexp.MustCompile(`(?:страна\s+(?:проживания|регистрации|рождения|выдачи\s+паспорта|гражданства)|страна(?:[^а-яa-z0-9]|$))\s*[:.\-]?\s*([^\s;,\n]+(?:\s+[^\s;,\n]+){0,2})`)
	return &labelValueDetector{typ: Country, re: re, conf: 0.9}
}

func cityDetector() Detector {
	re := regexp.MustCompile(`(?:город|г\.)\s*[:.\-]?\s*([^\s;,\n]+)`)
	return &bankFilter{inner: &labelValueDetector{typ: City, re: re, conf: 0.9}}
}

func streetDetector() Detector {
	prefixRe := regexp.MustCompile(`(?:улица|ул\.|пр-т|проспект|пер\.|бульвар|шоссе)\s*[:.\-]?\s*([^\s;,\n]+(?:\s+[^\s;,\n]+)?)`)
	postfixRe := regexp.MustCompile(`([^\s;,\n]+)\s+улица`)
	return &bankFilter{inner: &streetDetectorImpl{prefixRe: prefixRe, postfixRe: postfixRe}}
}

// streetDetectorImpl — детектор улицы с префиксной и постфиксной формами.
type streetDetectorImpl struct {
	prefixRe  *regexp.Regexp
	postfixRe *regexp.Regexp
}

func (d *streetDetectorImpl) Type() Type { return Street }

func (d *streetDetectorImpl) Find(text string) []Entity {
	lower := strings.ToLower(text)
	var out []Entity
	for _, m := range d.prefixRe.FindAllStringSubmatchIndex(lower, -1) {
		start, end := m[2], m[3]
		if start < 0 || end < 0 {
			continue
		}
		out = append(out, Entity{
			Type:       Street,
			Start:      start,
			End:        end,
			Value:      text[start:end],
			Confidence: 0.9,
		})
	}
	for _, m := range d.postfixRe.FindAllStringSubmatchIndex(lower, -1) {
		start, end := m[2], m[3]
		if start < 0 || end < 0 {
			continue
		}
		out = append(out, Entity{
			Type:       Street,
			Start:      start,
			End:        end,
			Value:      text[start:end],
			Confidence: 0.9,
		})
	}
	return out
}

func houseFlatDetector() Detector {
	re := regexp.MustCompile(`(?:дом|д\.|квартира|кв\.|корпус|корп\.|строение|стр\.)\s*[:.\-]?\s*(\d+(?:[а-яa-z])?(?:[/\-]\d+)?)`)
	return &bankFilter{inner: &labelValueDetector{typ: HouseFlat, re: re, conf: 0.9}}
}

func addressDetector() Detector {
	re := regexp.MustCompile(`(?:(?:адрес\s+(?:проживания|регистрации|клиента|доставки)|адрес(?:а|у|ом|е)?(?:[^а-яa-z0-9]|$))|проживает|зарегистрирован(?:а)?)\s*[:.\-]?\s*([^;\n]{3,180})`)
	return &addressDetectorImpl{re: re}
}

func citizenshipDetector() Detector {
	re := regexp.MustCompile(`(?:является\s+гражданином|гражданином|гражданкой|гражданин|гражданка|гражданство)\s*[:.\-]?\s*([^\s;,\n]+(?:\s+[^\s;,\n]+){0,2})`)
	return &citizenshipDetectorImpl{re: re}
}

// citizenshipDetectorImpl — детектор гражданства. Значение — 1-3 слова,
// каждое с заглавной буквы; останавливается на первом слове со строчной.
type citizenshipDetectorImpl struct {
	re *regexp.Regexp
}

func (d *citizenshipDetectorImpl) Type() Type { return Citizenship }

func (d *citizenshipDetectorImpl) Find(text string) []Entity {
	lower := strings.ToLower(text)
	var out []Entity
	for _, m := range d.re.FindAllStringSubmatchIndex(lower, -1) {
		start, end := m[2], m[3]
		if start < 0 || end < 0 {
			continue
		}
		val := trimToCapitalized(text[start:end])
		if val == "" {
			continue
		}
		out = append(out, Entity{
			Type:       Citizenship,
			Start:      start,
			End:        start + len(val),
			Value:      val,
			Confidence: 0.9,
		})
	}
	return out
}

// trimToCapitalized оставляет только ведущие слова, начинающиеся с заглавной.
func trimToCapitalized(s string) string {
	words := strings.Fields(s)
	var kept []string
	for _, w := range words {
		r, _ := utf8.DecodeRuneInString(w)
		if !unicode.IsUpper(r) {
			break
		}
		kept = append(kept, w)
	}
	return strings.Join(kept, " ")
}

func birthPlaceDetector() Detector {
	re := regexp.MustCompile(`место\s+рождения\s*[:.\-]?\s*((?:г\.|гор\.|пос\.|п\.|с\.|д\.|дер\.|пгт\s*)?[^,;\n]+)`)
	return &birthPlaceDetectorImpl{re: re}
}

// birthPlaceDetectorImpl — детектор места рождения с обрезкой значения
// на ". " за которой идёт слово с заглавной буквы.
type birthPlaceDetectorImpl struct {
	re *regexp.Regexp
}

func (d *birthPlaceDetectorImpl) Type() Type { return BirthPlace }

func (d *birthPlaceDetectorImpl) Find(text string) []Entity {
	lower := strings.ToLower(text)
	var out []Entity
	for _, m := range d.re.FindAllStringSubmatchIndex(lower, -1) {
		start, end := m[2], m[3]
		if start < 0 || end < 0 {
			continue
		}
		val := trimBirthPlace(text[start:end])
		if val == "" {
			continue
		}
		out = append(out, Entity{
			Type:       BirthPlace,
			Start:      start,
			End:        start + len(val),
			Value:      val,
			Confidence: 0.9,
		})
	}
	return out
}

// trimBirthPlace обрезает значение на ". " за которой идёт заглавная буква,
// пропуская точки в сокращениях (г., гор., пос. и т.п.).
func trimBirthPlace(s string) string {
	lower := strings.ToLower(s)
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '.' && s[i+1] == ' ' && !isAbbrevDot(lower, i) {
			next := i + 2
			if next < len(s) {
				r, _ := utf8.DecodeRuneInString(s[next:])
				if unicode.IsUpper(r) {
					return strings.TrimSpace(s[:i])
				}
			}
		}
	}
	return strings.TrimSpace(s)
}

func issuingAuthorityDetector() Detector {
	re := regexp.MustCompile(`(?:орган\s+выдачи|орган,\s*выдавший\s+паспорт|паспорт\s+выдан|выдан)\s*[:.\-]?\s*((?:тп\s+уфмс|оуфмс|уфмс|мвд|умвд|овд|гу\s+мвд|отдел|отделом)[^;\n]*)`)
	bareRe := regexp.MustCompile(`(?m)^\s*(тп\s+уфмс|отделом\s+уфмс|отдел\s+уфмс|гу\s+мвд|овд\s+района|умвд)[^;\n]*`)
	return &issuingAuthorityDetectorImpl{re: re, bareRe: bareRe}
}

// issuingAuthorityDetectorImpl — детектор органа выдачи с обрезкой значения
// по дате, "код подразделения" и хвостовым пробелам.
type issuingAuthorityDetectorImpl struct {
	re     *regexp.Regexp
	bareRe *regexp.Regexp
}

func (d *issuingAuthorityDetectorImpl) Type() Type { return IssuingAuthority }

func (d *issuingAuthorityDetectorImpl) Find(text string) []Entity {
	lower := strings.ToLower(text)
	var out []Entity
	for _, m := range d.re.FindAllStringSubmatchIndex(lower, -1) {
		start, end := m[2], m[3]
		if start < 0 || end < 0 {
			continue
		}
		if e, ok := d.buildEntity(text, lower, start, end); ok {
			out = append(out, e)
		}
	}
	for _, m := range d.bareRe.FindAllStringSubmatchIndex(lower, -1) {
		start, end := m[0], m[1]
		if start < 0 || end < 0 {
			continue
		}
		for start < end && (text[start] == ' ' || text[start] == '\t') {
			start++
		}
		if e, ok := d.buildEntity(text, lower, start, end); ok {
			out = append(out, e)
		}
	}
	return out
}

func (d *issuingAuthorityDetectorImpl) buildEntity(text, lower string, start, end int) (Entity, bool) {
	val := text[start:end]
	valLower := lower[start:end]
	if idx := dateStartIndex(valLower); idx >= 0 {
		val = val[:idx]
		valLower = valLower[:idx]
	}
	if idx := strings.Index(valLower, ", код подразделения"); idx >= 0 {
		val = val[:idx]
	}
	val = strings.TrimRight(val, " \t")
	if val == "" {
		return Entity{}, false
	}
	return Entity{
		Type:       IssuingAuthority,
		Start:      start,
		End:        start + len(val),
		Value:      val,
		Confidence: 0.9,
	}, true
}

// dateInTextRe — любой формат даты в тексте.
var dateInTextRe = regexp.MustCompile(`\d{1,2}[./]\d{1,2}[./]\d{2,4}|\d{4}[./]\d{1,2}[./]\d{1,2}|\d{1,2}-\d{1,2}-\d{4}|\d{4}-\d{2}-\d{2}`)

// dateStartIndex возвращает индекс начала первой даты в s или -1.
func dateStartIndex(s string) int {
	loc := dateInTextRe.FindStringIndex(s)
	if loc == nil {
		return -1
	}
	return loc[0]
}

// bankFilter отбрасывает сущности, найденные внутри сегмента текста,
// описывающего адрес отделения банка (не персональные данные).
type bankFilter struct {
	inner Detector
}

func (d *bankFilter) Type() Type { return d.inner.Type() }

func (d *bankFilter) Find(text string) []Entity {
	lower := strings.ToLower(text)
	var out []Entity
	for _, e := range d.inner.Find(text) {
		if isBankSegment(lower, e.Start) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// addressDetectorImpl — детектор адреса с отсечением банковских адресов
// и обрезкой хвостовых пробелов.
type addressDetectorImpl struct {
	re *regexp.Regexp
}

func (d *addressDetectorImpl) Type() Type { return Address }

func (d *addressDetectorImpl) Find(text string) []Entity {
	lower := strings.ToLower(text)
	var out []Entity
	for _, m := range d.re.FindAllStringSubmatchIndex(lower, -1) {
		start, end := m[2], m[3]
		if start < 0 || end < 0 {
			continue
		}
		val := trimAddress(text[start:end])
		end = start + len(val)
		if isBankSegment(lower, start) {
			continue
		}
		// Полный адрес почти всегда содержит номер дома/цифру.
		// Это отсекает ложные срабатывания вроде "по адресу проживания клиента".
		if !strings.ContainsAny(val, "0123456789") {
			continue
		}
		out = append(out, Entity{
			Type:       Address,
			Start:      start,
			End:        end,
			Value:      val,
			Confidence: 0.8,
		})
	}
	return out
}

// trimAddress обрезает адрес на ";", переводе строки, ". " + заглавная,
// или ", " + слово со строчной, не являющееся адресным маркером.
func trimAddress(s string) string {
	lower := strings.ToLower(s)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ';', '\n':
			return strings.TrimSpace(s[:i])
		case '.':
			if i+1 < len(s) && s[i+1] == ' ' && !isAbbrevDot(lower, i) {
				next := i + 2
				if next < len(s) {
					r, _ := utf8.DecodeRuneInString(s[next:])
					if unicode.IsUpper(r) {
						return strings.TrimSpace(s[:i+1])
					}
				}
			}
		case ',':
			if i+1 < len(s) && s[i+1] == ' ' {
				word := nextWord(s, i+2)
				if word == "" {
					continue
				}
				r, _ := utf8.DecodeRuneInString(word)
				if !unicode.IsUpper(r) && !addressMarker[strings.ToLower(word)] {
					return strings.TrimSpace(s[:i])
				}
			}
		}
	}
	return strings.TrimSpace(s)
}

// isAbbrevDot возвращает true, если точка на позиции dotIdx — часть
// известного сокращения (г., ул., д., кв., обл. и т.п.).
func isAbbrevDot(s string, dotIdx int) bool {
	return abbrevDotRe.MatchString(s[:dotIdx+1])
}

// abbrevDotRe — известные сокращения, после которых точка не завершает адрес.
var abbrevDotRe = regexp.MustCompile(`(?:г|ул|д|кв|корп|стр|пер|обл|пр-т|р-н|гор|пос|п|с|дер|пгт)\.$`)

// nextWord возвращает следующее слово, начинающееся с позиции idx.
func nextWord(s string, idx int) string {
	loc := wordStartRe.FindStringIndex(s[idx:])
	if loc == nil {
		return ""
	}
	return s[idx+loc[0] : idx+loc[1]]
}

// wordStartRe — слово из букв и цифр (кириллица или латиница, оба регистра).
var wordStartRe = regexp.MustCompile(`[а-яёa-zА-ЯЁA-Z0-9]+`)

// addressMarker — слова-маркеры адреса, после которых адрес продолжается.
var addressMarker = map[string]bool{
	"ул": true, "улица": true, "д": true, "дом": true, "кв": true,
	"квартира": true, "корп": true, "стр": true, "пр-т": true,
	"проспект": true, "пер": true, "обл": true, "р-н": true, "г": true,
}

// isBankSegment возвращает true, если позиция pos находится в сегменте
// (от предыдущего ';' до следующего ';' или конца строки), содержащем
// упоминание банка.
func isBankSegment(lower string, pos int) bool {
	segStart := strings.LastIndex(lower[:pos], ";")
	if segStart < 0 {
		segStart = 0
	} else {
		segStart++
	}
	segEnd := strings.Index(lower[pos:], ";")
	if segEnd < 0 {
		segEnd = len(lower)
	} else {
		segEnd = pos + segEnd
	}
	return strings.Contains(lower[segStart:segEnd], "банк")
}

func fullNameLabeledDetector() Detector {
	re := regexp.MustCompile(`(?:фио|ф\.и\.о\.|клиент(?:а)?|заёмщик(?:а)?|заемщик(?:а)?|получатель|плательщик|меня\s+зовут)\s*[:.\-]?\s*((?:[А-Яа-яЁё]\.|[А-Яа-яЁё]+)(?:\s+(?:[А-Яа-яЁё]\.|[А-Яа-яЁё]+)){1,2})`)
	return &publicFigureFilter{inner: &capitalizedWordsFilter{inner: &labelValueDetector{typ: FullName, re: re, conf: 0.95}}}
}

func fullNameSurnameFirstDetector() Detector {
	re := regexp.MustCompile(`[А-Яа-яЁё]+\s+[А-Яа-яЁё]+\s+(?:[А-Яа-яЁё]+(?:ов|ев)ич(?:а|у|ем|е)?|[А-Яа-яЁё]+(?:ов|ев)н(?:а|ы|е|ой))`)
	return &publicFigureFilter{inner: &capitalizedWordsFilter{inner: &regexpDetector{typ: FullName, re: re, conf: 0.8}}}
}

func fullNameGivenFirstDetector() Detector {
	re := regexp.MustCompile(`[А-Яа-яЁё]+\s+(?:[А-Яа-яЁё]+(?:ов|ев)ич|[А-Яа-яЁё]+(?:ов|ев)н(?:а|ы|е|ой))\s+[А-Яа-яЁё]+`)
	return &publicFigureFilter{inner: &capitalizedWordsFilter{inner: &regexpDetector{typ: FullName, re: re, conf: 0.8}}}
}

// capitalizedWordsFilter пропускает только сущности, у которых каждое слово
// начинается с заглавной буквы или целиком заглавное (по исходному тексту).
type capitalizedWordsFilter struct {
	inner Detector
}

func (d *capitalizedWordsFilter) Type() Type { return d.inner.Type() }

func (d *capitalizedWordsFilter) Find(text string) []Entity {
	var out []Entity
	for _, e := range d.inner.Find(text) {
		if allWordsCapitalized(text[e.Start:e.End]) {
			out = append(out, e)
		}
	}
	return out
}

// allWordsCapitalized возвращает true, если каждое слово в s начинается
// с заглавной буквы или целиком заглавное.
func allWordsCapitalized(s string) bool {
	words := cyrillicWordRe.FindAllString(s, -1)
	if len(words) == 0 {
		return false
	}
	for _, w := range words {
		r, _ := utf8.DecodeRuneInString(w)
		if !unicode.IsUpper(r) {
			return false
		}
	}
	return true
}

// surnameInitialsDetectorImpl — детектор "Фамилия И.О." и "И.О. Фамилия".
type surnameInitialsDetectorImpl struct {
	re *regexp.Regexp
}

func (d *surnameInitialsDetectorImpl) Type() Type { return FullName }

func (d *surnameInitialsDetectorImpl) Find(text string) []Entity {
	lower := strings.ToLower(text)
	var out []Entity
	for _, m := range d.re.FindAllStringSubmatchIndex(lower, -1) {
		start, end := m[0], m[1]
		if start < 0 || end < 0 {
			continue
		}
		if !allWordsCapitalized(text[start:end]) {
			continue
		}
		out = append(out, Entity{
			Type:       FullName,
			Start:      start,
			End:        end,
			Value:      text[start:end],
			Confidence: 0.8,
		})
	}
	return out
}

func surnameInitialsDetector() Detector {
	re := regexp.MustCompile(`[а-яё]+\s+[а-яё]\.\s*[а-яё]\.|[а-яё]\.\s*[а-яё]\.\s+[а-яё]+`)
	return &surnameInitialsDetectorImpl{re: re}
}

func namePairDetector() Detector {
	return &publicFigureFilter{inner: &namePairDetectorImpl{}}
}

func cardholderNameDetector() Detector {
	re := regexp.MustCompile(`(?:имя\s+держателя(?:\s+карты)?|держатель\s+карты|держатель|держателя|на\s+имя|cardholder(?:\s+name)?)\s*[:.\-]?\s*([a-z]{2,}(?:\s+[a-z]{2,}){1,2})`)
	return &cardholderNameDetectorImpl{re: re}
}

// cardholderNameDetectorImpl — детектор имени держателя карты латиницей
// заглавными буквами. Также распознаёт весь payload из 2-3 латинских слов.
type cardholderNameDetectorImpl struct {
	re *regexp.Regexp
}

func (d *cardholderNameDetectorImpl) Type() Type { return CardholderName }

func (d *cardholderNameDetectorImpl) Find(text string) []Entity {
	lower := strings.ToLower(text)
	var out []Entity
	for _, m := range d.re.FindAllStringSubmatchIndex(lower, -1) {
		start, end := m[2], m[3]
		if start < 0 || end < 0 {
			continue
		}
		if !allLatinUpper(text[start:end]) {
			continue
		}
		out = append(out, Entity{
			Type:       CardholderName,
			Start:      start,
			End:        end,
			Value:      text[start:end],
			Confidence: 0.9,
		})
	}
	if trimmed := strings.TrimSpace(text); allLatinUpper(trimmed) {
		start := strings.Index(text, trimmed)
		out = append(out, Entity{
			Type:       CardholderName,
			Start:      start,
			End:        start + len(trimmed),
			Value:      trimmed,
			Confidence: 0.9,
		})
	}
	return out
}

// allLatinUpper возвращает true, если s — это 2-3 латинских слова заглавными.
func allLatinUpper(s string) bool {
	words := strings.Fields(s)
	if len(words) < 2 || len(words) > 3 {
		return false
	}
	for _, w := range words {
		if !latinUpperWordRe.MatchString(w) {
			return false
		}
	}
	return true
}

// publicFigureFilter исключает известные публичные фигуры (например
// "Александр Пушкин"), если рядом нет явного признака клиента банка.
type publicFigureFilter struct {
	inner Detector
}

func (d *publicFigureFilter) Type() Type { return d.inner.Type() }

func (d *publicFigureFilter) Find(text string) []Entity {
	lower := strings.ToLower(text)
	hasClient := strings.Contains(lower, "клиент") || strings.Contains(lower, "фио") ||
		strings.Contains(lower, "заёмщик") || strings.Contains(lower, "заемщик")
	var out []Entity
	for _, e := range d.inner.Find(text) {
		if !hasClient && containsPublicFigure(strings.ToLower(e.Value)) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// containsPublicFigure возвращает true, если в lower встречается фамилия
// известной публичной фигуры.
func containsPublicFigure(lower string) bool {
	for name := range publicFigures {
		if strings.Contains(lower, name) {
			return true
		}
	}
	return false
}

// namePairDetectorImpl — детектор пары "Имя Фамилия" без метки на основе
// словаря имён и эвристики окончания фамилии.
type namePairDetectorImpl struct{}

func (d *namePairDetectorImpl) Type() Type { return FullName }

func (d *namePairDetectorImpl) Find(text string) []Entity {
	words := cyrillicWordRe.FindAllStringIndex(text, -1)
	var out []Entity
	for i := 0; i+1 < len(words); i++ {
		if strings.TrimSpace(text[words[i][1]:words[i+1][0]]) != "" {
			continue
		}
		w1 := strings.ToLower(text[words[i][0]:words[i][1]])
		w2 := strings.ToLower(text[words[i+1][0]:words[i+1][1]])
		if (commonNames[w1] && looksLikeSurname(w2)) || (commonNames[w2] && looksLikeSurname(w1)) {
			out = append(out, Entity{
				Type:       FullName,
				Start:      words[i][0],
				End:        words[i+1][1],
				Value:      text[words[i][0]:words[i+1][1]],
				Confidence: 0.7,
			})
		}
	}
	return out
}

var cyrillicWordRe = regexp.MustCompile(`[А-Яа-яЁё]+(?:-[А-Яа-яЁё]+)?`)

// docLabelWordRe — слово для проверки меток документов: буквы, цифры и "/".
var docLabelWordRe = regexp.MustCompile(`[а-яa-z0-9/]+`)

// latinUpperWordRe — латинское слово заглавными буквами.
var latinUpperWordRe = regexp.MustCompile(`^[A-Z]{2,}$`)

// docLabels — метки документов, блокирующие распознавание номера паспорта.
var docLabels = map[string]bool{
	"инн": true, "inn": true, "в/у": true, "ву": true,
	"удостоверение": true, "права": true,
}

// publicFigures — фамилии известных публичных фигур, которые не маскируются
// как ФИО, если рядом нет признака клиента.
var publicFigures = map[string]bool{
	"гагарин": true, "пушкин": true, "толстой": true, "лермонтов": true,
	"чехов": true, "достоевский": true, "менделеев": true, "королёв": true,
	"ломоносов": true, "есенин": true, "маяковский": true,
}

var commonNames = map[string]bool{
	"александр": true, "алексей": true, "андрей": true, "анна": true,
	"анастасия": true, "артём": true, "артем": true, "борис": true,
	"валерий": true, "василий": true, "вера": true, "виктор": true,
	"владимир": true, "галина": true, "дарья": true, "денис": true,
	"дмитрий": true, "евгений": true, "екатерина": true, "елена": true,
	"елизавета": true, "иван": true, "игорь": true, "илья": true,
	"ирина": true, "кирилл": true, "константин": true, "ксения": true,
	"лев": true, "леонид": true, "людмила": true, "максим": true,
	"марина": true, "мария": true, "михаил": true, "надежда": true,
	"наталья": true, "никита": true, "николай": true, "олег": true,
	"ольга": true, "павел": true, "пётр": true, "петр": true, "полина": true,
	"роман": true, "светлана": true, "сергей": true, "софия": true,
	"тимур": true, "татьяна": true, "юлия": true, "юрий": true, "яна": true,
}

var surnameSuffixes = []string{"ов", "ев", "ёв", "ин", "ын", "ова", "ева", "ёва", "ина", "ский", "ская", "енко"}

func looksLikeSurname(w string) bool {
	for _, s := range surnameSuffixes {
		if strings.HasSuffix(w, s) {
			return true
		}
	}
	return false
}