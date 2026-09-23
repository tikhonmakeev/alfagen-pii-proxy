package pii

import (
	"strings"
	"testing"
)

func findFirst(t *testing.T, d Detector, text string) Entity {
	t.Helper()
	es := d.Find(text)
	if len(es) == 0 {
		t.Fatalf("no match for %q in %q", d.Type(), text)
	}
	return es[0]
}

func TestEmail(t *testing.T) {
	e := findFirst(t, emailDetector(), "Почта: test.person@example.org")
	if e.Value != "test.person@example.org" {
		t.Fatalf("got %q", e.Value)
	}
	if e.Type != Email {
		t.Fatalf("got type %q", e.Type)
	}
}

func TestPhone(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Телефон +7 (999) 123-45-67", "+7 (999) 123-45-67"},
		{"тел. 89991234567", "89991234567"},
		{"мобильный 8 999 123-45-67", "8 999 123-45-67"},
		{"+79991234567", "+79991234567"},
		{"8-903-123-45-67", "8-903-123-45-67"},
		{"8 (903) 123-45-67", "8 (903) 123-45-67"},
		{"+7-903-123-45-67", "+7-903-123-45-67"},
		{"+7 999 111-22-33", "+7 999 111-22-33"},
		{"89161234567", "89161234567"},
	} {
		e := findFirst(t, phoneDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf("for %q got %q, want %q", tc.in, e.Value, tc.want)
		}
	}
}

func TestCardNumber(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Карта 4111 1111 1111 1111", "4111 1111 1111 1111"},
		{"номер карты 4111-1111-1111-1111", "4111-1111-1111-1111"},
		{"4111 1111 1111 1111 123", "4111 1111 1111 1111 123"},
	} {
		e := findFirst(t, cardNumberDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf("for %q got %q, want %q", tc.in, e.Value, tc.want)
		}
	}
}

func TestCVV(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"CVV: 123", "123"},
		{"cvv2 456", "456"},
		{"CVC: 789", "789"},
		{"cvc2 012", "012"},
		{"Код безопасности 789 на обороте", "789"},
		{"cvv-код 345", "345"},
		{"cvc-код 678", "678"},
	} {
		e := findFirst(t, cvvDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf("for %q got %q, want %q", tc.in, e.Value, tc.want)
		}
	}
}

func TestPIN(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"ПИН-код: 9876", "9876"},
		{"Мой пин 4321", "4321"},
		{"ПИН-код карты: 0000", "0000"},
		{"PIN: 9876", "9876"},
		{"пин код 1234", "1234"},
		{"пинкод 5678", "5678"},
		{"pin-код 1111", "1111"},
		{"ПИН от карты: 2222", "2222"},
	} {
		e := findFirst(t, pinDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf("for %q got %q, want %q", tc.in, e.Value, tc.want)
		}
	}
}

func TestPINNoFalsePositive(t *testing.T) {
	es := pinDetector().Find("пингвин 1234")
	if len(es) != 0 {
		t.Fatalf("пингвин should not match PIN, got %+v", es)
	}
}

func TestINN(t *testing.T) {
	e := findFirst(t, innDetector(), "ИНН: 123456789012")
	if e.Value != "123456789012" {
		t.Fatalf("got %q", e.Value)
	}
}

func TestPassportNumber(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Паспорт 4509 123456", "4509 123456"},
		{"паспорт серия 4509 номер 123456", "4509 номер 123456"},
		{"У него паспорт серии 45 09 номер 123456", "45 09 номер 123456"},
		{"паспорт 4509123456", "4509123456"},
		{"4509 123456", "4509 123456"},
	} {
		e := findFirst(t, passportNumberDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf("for %q got %q, want %q", tc.in, e.Value, tc.want)
		}
	}
}

func TestDriverLicense(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Водительское удостоверение 77 01 123456", "77 01 123456"},
		{"В/У: 7701123456", "7701123456"},
		{"ВУ 99 12 345678 категории B", "99 12 345678"},
		{"вод. удостоверение 7701 123456", "7701 123456"},
		{"права: 77 01 123456", "77 01 123456"},
	} {
		e := findFirst(t, driverLicenseDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf("for %q got %q, want %q", tc.in, e.Value, tc.want)
		}
	}
}

func TestDocumentDisambiguation(t *testing.T) {
	// "В/У: 7701123456" → только driver_license_number
	es := findAll(t, "В/У: 7701123456")
	if !hasType(es, DriverLicenseNumber) {
		t.Fatalf("expected driver_license_number, got %+v", es)
	}
	if hasType(es, PassportNumber) {
		t.Fatalf("expected no passport_number, got %+v", es)
	}

	// "ВУ 99 12 345678 категории B" → driver_license_number
	es = findAll(t, "ВУ 99 12 345678 категории B")
	if !hasType(es, DriverLicenseNumber) {
		t.Fatalf("expected driver_license_number, got %+v", es)
	}
	if hasType(es, PassportNumber) {
		t.Fatalf("expected no passport_number, got %+v", es)
	}

	// "ИНН 7707083893" → только inn
	es = findAll(t, "ИНН 7707083893")
	if !hasType(es, Inn) {
		t.Fatalf("expected inn, got %+v", es)
	}
	if hasType(es, PassportNumber) {
		t.Fatalf("expected no passport_number, got %+v", es)
	}

	// "паспорт 4509 123456" → passport_number
	es = findAll(t, "паспорт 4509 123456")
	if !hasType(es, PassportNumber) {
		t.Fatalf("expected passport_number, got %+v", es)
	}
	if hasType(es, DriverLicenseNumber) {
		t.Fatalf("expected no driver_license_number, got %+v", es)
	}
}

func TestDepartmentCode(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Код подразделения: 770-001", "770-001"},
		{"770-001", "770-001"},
	} {
		e := findFirst(t, departmentCodeDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf("for %q got %q, want %q", tc.in, e.Value, tc.want)
		}
	}
}

func TestBirthDate(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"дата рождения: 31.12.1990", "31.12.1990"},
		{"родился 12/31/1990", "12/31/1990"},
		{"1990.31.12", "1990.31.12"},
		{"12 января 1990", "12 января 1990"},
		{"12 января 1990 года", "12 января 1990 года"},
		{"12 января 1990 г.", "12 января 1990 г."},
		{"дата рождения: 31-12-1990", "31-12-1990"},
	} {
		e := findFirst(t, birthDateDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf("for %q got %q, want %q", tc.in, e.Value, tc.want)
		}
	}
}

func TestBirthDateNoFalsePositive(t *testing.T) {
	// Хвост телефона "23-45-67" не должен считаться датой.
	es := birthDateDetector().Find("Телефон 8-903-123-45-67")
	if len(es) != 0 {
		t.Fatalf("phone tail should not match birth date, got %+v", es)
	}
	// Дефисный формат с 2-значным годом не принимается.
	es = birthDateDetector().Find("дата рождения: 31-12-90")
	if len(es) != 0 {
		t.Fatalf("2-digit year hyphen date should not match, got %+v", es)
	}
}

func TestPassportIssueDate(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Дата выдачи: 21.09.2010", "21.09.2010"},
		{"Дата выдачи: 21-09-2010", "21-09-2010"},
	} {
		e := findFirst(t, passportIssueDateDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf("for %q got %q, want %q", tc.in, e.Value, tc.want)
		}
	}
}

func TestPassportIssueDateNoFalsePositive(t *testing.T) {
	es := passportIssueDateDetector().Find("Телефон 8-903-123-45-67")
	if len(es) != 0 {
		t.Fatalf("phone tail should not match issue date, got %+v", es)
	}
}

func TestPostalCode(t *testing.T) {
	e := findFirst(t, postalCodeDetector(), "Индекс: 123456")
	if e.Value != "123456" {
		t.Fatalf("got %q", e.Value)
	}
}

func TestCountry(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Страна: Россия", "Россия"},
		{"Страна: Новая Зеландия", "Новая Зеландия"},
	} {
		e := findFirst(t, countryDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf("for %q got %q, want %q", tc.in, e.Value, tc.want)
		}
	}
}

func TestCity(t *testing.T) {
	e := findFirst(t, cityDetector(), "Город: Казань")
	if e.Value != "Казань" {
		t.Fatalf("got %q", e.Value)
	}
}

func TestStreet(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Улица: Ленина", "Ленина"},
		{"Улица: 8 Марта", "8 Марта"},
		{"Улица: Красных Зорь", "Красных Зорь"},
	} {
		e := findFirst(t, streetDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf("for %q got %q, want %q", tc.in, e.Value, tc.want)
		}
	}
}

func TestHouseFlat(t *testing.T) {
	es := houseFlatDetector().Find("Дом: 15; квартира: 27")
	if len(es) == 0 {
		t.Fatal("no match")
	}
	if es[0].Value != "15" {
		t.Fatalf("got %q, want %q", es[0].Value, "15")
	}
}

func TestAddress(t *testing.T) {
	e := findFirst(t, addressDetector(), "Адрес: г. Москва, ул. Ленина, д. 5, кв. 12")
	if e.Value != "г. Москва, ул. Ленина, д. 5, кв. 12" {
		t.Fatalf("got %q", e.Value)
	}
}

func TestCitizenship(t *testing.T) {
	e := findFirst(t, citizenshipDetector(), "Гражданство: Российская Федерация")
	if e.Value != "Российская Федерация" {
		t.Fatalf("got %q", e.Value)
	}
}

func TestBirthPlace(t *testing.T) {
	e := findFirst(t, birthPlaceDetector(), "Место рождения: г. Казань")
	if e.Value != "г. Казань" {
		t.Fatalf("got %q", e.Value)
	}
}

func TestIssuingAuthority(t *testing.T) {
	e := findFirst(t, issuingAuthorityDetector(), "Паспорт выдан ОВД района Арбат;")
	if e.Value != "ОВД района Арбат" {
		t.Fatalf("got %q", e.Value)
	}
}

func findAll(t *testing.T, text string) []Entity {
	t.Helper()
	var out []Entity
	for _, d := range Registry() {
		out = append(out, d.Find(text)...)
	}
	return out
}

func hasValue(es []Entity, v string) bool {
	for _, e := range es {
		if e.Value == v {
			return true
		}
	}
	return false
}

func hasType(es []Entity, typ Type) bool {
	for _, e := range es {
		if e.Type == typ {
			return true
		}
	}
	return false
}

func TestAddressBankExclusion(t *testing.T) {
	es := findAll(t, "Адрес отделения банка: г. Москва, ул. Ленина, д. 5")
	if hasType(es, Address) {
		t.Fatalf("bank address should not match, got %+v", es)
	}

	es = findAll(t, "Офис банка: г. Казань, ул. Баумана, д. 2")
	if hasType(es, Address) {
		t.Fatalf("bank office should not match, got %+v", es)
	}
}

func TestAddressBankThenClient(t *testing.T) {
	es := findAll(t, "Офис банка: г. Казань, ул. Баумана, д. 2; адрес клиента: г. Москва, ул. Ленина, д. 5")
	if hasValue(es, "Казань") {
		t.Fatalf("bank city should be excluded, got %+v", es)
	}
	if !hasValue(es, "Москва") {
		t.Fatalf("client city should be present, got %+v", es)
	}
}

func TestAddressNoFalsePositive(t *testing.T) {
	es := findAll(t, "Посылка уйдёт по адресу проживания клиента.")
	if hasType(es, Address) {
		t.Fatalf("no real address should not match, got %+v", es)
	}
}

func TestFullNameLabeled(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Клиент Иванов Иван Иванович", "Иванов Иван Иванович"},
		{"ФИО: Иванов И. И.", "Иванов И. И."},
		{"Клиент Анна Петрова", "Анна Петрова"},
		{"Клиент Иван Иванович Иванов", "Иван Иванович Иванов"},
	} {
		e := findFirst(t, fullNameLabeledDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf("for %q got %q, want %q", tc.in, e.Value, tc.want)
		}
	}
}

func TestFullNameSurnameFirst(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Оператор передал звонок от Николаева Сергея Павловича менеджеру.", "Николаева Сергея Павловича"},
		{"Заявление подано в отношении Петровой Анны Сергеевны.", "Петровой Анны Сергеевны"},
	} {
		e := findFirst(t, fullNameSurnameFirstDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf("for %q got %q, want %q", tc.in, e.Value, tc.want)
		}
	}
}

func TestFullNameGivenFirst(t *testing.T) {
	e := findFirst(t, fullNameGivenFirstDetector(), "Иван Иванович Иванов подписал документ.")
	if e.Value != "Иван Иванович Иванов" {
		t.Fatalf("got %q", e.Value)
	}
}

func TestFullNamePair(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Иван Петров прислал письмо", "Иван Петров"},
		{"Пишет вам Тимур Абдуллаев по поводу заявки", "Тимур Абдуллаев"},
	} {
		e := findFirst(t, namePairDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf("for %q got %q, want %q", tc.in, e.Value, tc.want)
		}
	}
}

func hasFullNameContaining(es []Entity, sub string) bool {
	for _, e := range es {
		if e.Type == FullName && strings.Contains(strings.ToLower(e.Value), sub) {
			return true
		}
	}
	return false
}

func TestPublicFigureExclusion(t *testing.T) {
	es := findAll(t, "Поэт Александр Пушкин написал стихи.")
	if hasFullNameContaining(es, "пушкин") {
		t.Fatalf("public figure should be excluded, got %+v", es)
	}

	es = findAll(t, "Александр Сергеевич Пушкин — поэт.")
	if hasFullNameContaining(es, "пушкин") {
		t.Fatalf("public figure should be excluded, got %+v", es)
	}

	es = findAll(t, "Клиент Александр Пушкин")
	if !hasFullNameContaining(es, "пушкин") {
		t.Fatalf("client with public figure name should match, got %+v", es)
	}
}

func TestCardholderName(t *testing.T) {
	e := findFirst(t, cardholderNameDetector(), "Cardholder: IVAN IVANOV")
	if e.Value != "IVAN IVANOV" {
		t.Fatalf("got %q", e.Value)
	}
}

func TestAddressDativeCase(t *testing.T) {
	e := findFirst(t, addressDetector(), "Выезд специалиста по адресу: Новосибирск, Гоголя 10-3.")
	if e.Value != "Новосибирск, Гоголя 10-3." {
		t.Fatalf("got %q", e.Value)
	}
}

func TestHyphenatedNameNoFalsePositive(t *testing.T) {
	text := "В переписке участвует Иван-Пётр Лебедев-Ростовский."
	es := namePairDetector().Find(text)
	for _, e := range es {
		if e.Type == FullName {
			t.Fatalf("hyphenated name should not produce full_name, got %+v", es)
		}
	}
	// Другие детекторы ФИО тоже не должны ложно сработать.
	all := findAll(t, text)
	for _, e := range all {
		if e.Type == FullName {
			t.Fatalf("hyphenated name should not produce full_name, got %+v", all)
		}
	}
}