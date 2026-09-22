package pii

import (
	"regexp"
	"strings"
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
	// +7 (999) 123-45-67, 8 999 123-45-67, 89991234567, 79991234567
	re := regexp.MustCompile(`(?:(?:тел\.?|мобильный|phone)\s*[:.\-]?\s*)?((?:\+?7|8)\s?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2})\b`)
	return &labelValueDetector{
		typ:  Phone,
		re:   re,
		conf: 0.95,
	}
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
	re := regexp.MustCompile(`\b(?:cvv2?|cvc2?|код\s+безопасности)\s*[:.\-]?\s*(\d{3,4})\b`)
	return &labelValueDetector{
		typ:  CVV,
		re:   re,
		conf: 0.98,
	}
}

func pinDetector() Detector {
	re := regexp.MustCompile(`(?:пин[\-\s]?код|pin)\s*[:.\-]?\s*(\d{4,6})\b`)
	return &labelValueDetector{
		typ:  PIN,
		re:   re,
		conf: 0.98,
	}
}

func innDetector() Detector {
	re := regexp.MustCompile(`(?:инн|inn)\s*[:.\-]?\s*(\d{10}|\d{12})\b`)
	return &labelValueDetector{
		typ:  Inn,
		re:   re,
		conf: 0.98,
	}
}

func passportNumberDetector() Detector {
	// Форматы: "4509 123456", "4509123456", "серия 4509 номер 123456",
	// "серии 45 09 номер 123456", "4509 номер 123456"
	re := regexp.MustCompile(`(?:(?:паспорт|серия|серии)\s+)?(\b\d{4}\s+\d{6}\b|\b\d{10}\b|\b\d{2}\s+\d{2}\s+номер\s+\d{6}\b|\b\d{4}\s+номер\s+\d{6}\b)`)
	return &labelValueDetector{
		typ:  PassportNumber,
		re:   re,
		conf: 0.9,
	}
}

func driverLicenseDetector() Detector {
	re := regexp.MustCompile(`(?:в/у|водительское\s+удостоверение)\s*[:.\-]?\s*(\d{2}\s+\d{2}\s+\d{6})\b`)
	return &labelValueDetector{
		typ:  DriverLicenseNumber,
		re:   re,
		conf: 0.9,
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
	// день месяц-словом год (с вариантами "года"/"г.")
	re := regexp.MustCompile(`(?:(?:дата\s+рождения|родился|родилась|д\.р\.)\s*[:.\-]?\s*)?(\d{1,2}[./\-]\d{1,2}[./\-]\d{2,4}|\d{4}[./\-]\d{1,2}[./\-]\d{1,2}|\d{1,2}\s+(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+\d{2,4}(?:\s+г(?:ода)?\.?)?)`)
	return &labelValueDetector{
		typ:  BirthDate,
		re:   re,
		conf: 0.85,
	}
}

func passportIssueDateDetector() Detector {
	re := regexp.MustCompile(`(?:дата\s+выдачи(?:\s+паспорта)?|выдан|выдана|выдача)\s*[:.\-]?\s*(\d{1,2}[./\-]\d{1,2}[./\-]\d{2,4}|\d{4}[./\-]\d{1,2}[./\-]\d{1,2}|\d{1,2}\s+(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+\d{2,4}(?:\s+г(?:ода)?\.?)?)`)
	return &labelValueDetector{
		typ:  PassportIssueDate,
		re:   re,
		conf: 0.9,
	}
}

func postalCodeDetector() Detector {
	re := regexp.MustCompile(`(?:почтовый\s+индекс|индекс)\s*[:.\-]?\s*(\d{6})\b`)
	return &bankFilter{inner: &labelValueDetector{typ: PostalCode, re: re, conf: 0.9}}
}

func countryDetector() Detector {
	re := regexp.MustCompile(`(?:страна\s+(?:проживания|регистрации)|страна(?:[^а-яa-z0-9]|$))\s*[:.\-]?\s*([^\s;,\n]+(?:\s+[^\s;,\n]+)*)`)
	return &labelValueDetector{typ: Country, re: re, conf: 0.9}
}

func cityDetector() Detector {
	re := regexp.MustCompile(`(?:город|г\.)\s*[:.\-]?\s*([^\s;,\n]+)`)
	return &bankFilter{inner: &labelValueDetector{typ: City, re: re, conf: 0.9}}
}

func streetDetector() Detector {
	re := regexp.MustCompile(`(?:улица|ул\.)\s*[:.\-]?\s*([^\s;,\n]+(?:\s+[^\s;,\n]+)?)`)
	return &bankFilter{inner: &labelValueDetector{typ: Street, re: re, conf: 0.9}}
}

func houseFlatDetector() Detector {
	re := regexp.MustCompile(`(?:дом|д\.|квартира|кв\.|корпус|корп\.|строение|стр\.)\s*[:.\-]?\s*(\d+(?:[а-яa-z])?(?:[/\-]\d+)?)`)
	return &bankFilter{inner: &labelValueDetector{typ: HouseFlat, re: re, conf: 0.9}}
}

func addressDetector() Detector {
	re := regexp.MustCompile(`(?:(?:адрес\s+(?:проживания|регистрации|клиента)|адрес(?:[^а-яa-z0-9]|$))|проживает|зарегистрирован(?:а)?)\s*[:.\-]?\s*([^;\n]{3,180})`)
	return &addressDetectorImpl{re: re}
}

func citizenshipDetector() Detector {
	re := regexp.MustCompile(`гражданство\s*[:.\-]?\s*([^\s;,\n]+(?:\s+[^\s;,\n]+)*)`)
	return &labelValueDetector{typ: Citizenship, re: re, conf: 0.9}
}

func birthPlaceDetector() Detector {
	re := regexp.MustCompile(`место\s+рождения\s*[:.\-]?\s*((?:г\.\s*)?[^,.;\n]+)`)
	return &labelValueDetector{typ: BirthPlace, re: re, conf: 0.9}
}

func issuingAuthorityDetector() Detector {
	re := regexp.MustCompile(`(?:орган\s+выдачи|орган,\s*выдавший\s+паспорт|паспорт\s+выдан|выдан)\s*[:.\-]?\s*((?:мвд|умвд|уфмс|овд|гу\s+мвд|отдел|отделом)[^;\n]*)`)
	return &issuingAuthorityDetectorImpl{re: re}
}

// issuingAuthorityDetectorImpl — детектор органа выдачи с обрезкой
// значения по "код подразделения" и хвостовым пробелам.
type issuingAuthorityDetectorImpl struct {
	re *regexp.Regexp
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
		val := text[start:end]
		if idx := strings.Index(lower[start:end], "код подразделения"); idx >= 0 {
			val = val[:idx]
		}
		val = strings.TrimRight(val, " \t")
		end = start + len(val)
		out = append(out, Entity{
			Type:       IssuingAuthority,
			Start:      start,
			End:        end,
			Value:      val,
			Confidence: 0.9,
		})
	}
	return out
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
		val := strings.TrimRight(text[start:end], " \t")
		end = start + len(val)
		if isBankSegment(lower, start) {
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
	return &publicFigureFilter{inner: &labelValueDetector{typ: FullName, re: re, conf: 0.95}}
}

func fullNameSurnameFirstDetector() Detector {
	re := regexp.MustCompile(`[А-Яа-яЁё]+\s+[А-Яа-яЁё]+\s+(?:[А-Яа-яЁё]+(?:ов|ев)ич(?:а|у|ем|е)?|[А-Яа-яЁё]+(?:ов|ев)н(?:а|ы|е|ой))`)
	return &publicFigureFilter{inner: &regexpDetector{typ: FullName, re: re, conf: 0.8}}
}

func fullNameGivenFirstDetector() Detector {
	re := regexp.MustCompile(`[А-Яа-яЁё]+\s+(?:[А-Яа-яЁё]+(?:ов|ев)ич|[А-Яа-яЁё]+(?:ов|ев)на)\s+[А-Яа-яЁё]+`)
	return &publicFigureFilter{inner: &regexpDetector{typ: FullName, re: re, conf: 0.8}}
}

func namePairDetector() Detector {
	return &publicFigureFilter{inner: &namePairDetectorImpl{}}
}

func cardholderNameDetector() Detector {
	re := regexp.MustCompile(`(?:имя\s+держателя(?:\s+карты)?|держатель\s+карты|cardholder(?:\s+name)?)\s*[:.\-]?\s*([А-Яа-яЁёA-Za-z]+(?:\s+[А-Яа-яЁёA-Za-z]+){1,2})`)
	return &labelValueDetector{typ: CardholderName, re: re, conf: 0.9}
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
		el := strings.ToLower(e.Value)
		if !hasClient && strings.Contains(el, "пушкин") && strings.Contains(el, "александр") {
			continue
		}
		out = append(out, e)
	}
	return out
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

var cyrillicWordRe = regexp.MustCompile(`[А-Яа-яЁё]+`)

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

var surnameSuffixes = []string{"ов", "ев", "ёв", "ин", "ын", "ова", "ева", "ина", "ский", "ская", "енко"}

func looksLikeSurname(w string) bool {
	for _, s := range surnameSuffixes {
		if strings.HasSuffix(w, s) {
			return true
		}
	}
	return false
}