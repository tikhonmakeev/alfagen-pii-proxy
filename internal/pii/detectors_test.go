package pii

import (
	"strings"
	"testing"
)

const (
	forGotWantFmt = "for %q got %q, want %q"
	inn7707083893 = "7707083893"
	passport4509  = "4509 123456"
	vu7701123456  = "В/У: 7701123456"
	dept770001    = "770-001"
	noPassportFmt = "expected no passport_number, got %+v"
	passportFmt   = "expected passport_number, got %+v"
	pushkin       = "пушкин"
	innClient     = "ИНН клиента 7707083893"
	passport226   = "13 75 332091"
	driver77      = "77 01 123456"
	vuCategoryB   = "ВУ 99 12 345678 категории B"
	publicFigFmt  = "public figure should be excluded, got %+v"
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
		t.Fatalf(gotQFmt, e.Value)
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
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
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
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
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
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
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
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
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
	for _, tc := range []struct{ in, want string }{
		{"ИНН: 123456789012", "123456789012"},
		{innClient, inn7707083893},
		{"ИНН физлица 7707083893", inn7707083893},
		{"ИНН получателя 7707083893", inn7707083893},
		{"ИНН организации 7707083893", inn7707083893},
	} {
		e := findFirst(t, innDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
		}
	}
}

func TestINNNoFalsePositive(t *testing.T) {
	es := innDetector().Find("ИНН и паспорт 4509123456")
	if len(es) != 0 {
		t.Fatalf("ИНН и паспорт should not match inn, got %+v", es)
	}
}

func TestPassportNumber(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Паспорт 4509 123456", passport4509},
		{"паспорт 4509123456", "4509123456"},
		{passport4509, passport4509},
		{"Паспорт 28 24 568674, прошу", "28 24 568674"},
		{passport226, passport226},
		{"паспорт гражданина РФ 47 08 620831", "47 08 620831"},
	} {
		e := findFirst(t, passportNumberDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
		}
	}
}

func TestPassportSeriesNumber(t *testing.T) {
	for _, tc := range []struct{ in, series, number string }{
		{"серия 40 15 № 386540", "40 15", "386540"},
		{"серия 8318 номер 673781", "8318", "673781"},
	} {
		es := passportNumberDetector().Find(tc.in)
		if !hasValue(es, tc.series) {
			t.Fatalf("for %q expected series %q, got %+v", tc.in, tc.series, es)
		}
		if !hasValue(es, tc.number) {
			t.Fatalf("for %q expected number %q, got %+v", tc.in, tc.number, es)
		}
	}
}

func TestDriverLicense(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Водительское удостоверение 77 01 123456", driver77},
		{vu7701123456, "7701123456"},
		{vuCategoryB, "99 12 345678"},
		{"вод. удостоверение 7701 123456", "7701 123456"},
		{"права: 77 01 123456", driver77},
	} {
		e := findFirst(t, driverLicenseDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
		}
	}
}

func TestDocumentDisambiguation(t *testing.T) {
	// vu7701123456 → только driver_license_number
	es := findAll(t, vu7701123456)
	if !hasType(es, DriverLicenseNumber) {
		t.Fatalf("expected driver_license_number, got %+v", es)
	}
	if hasType(es, PassportNumber) {
		t.Fatalf(noPassportFmt, es)
	}

	// vuCategoryB → driver_license_number
	es = findAll(t, vuCategoryB)
	if !hasType(es, DriverLicenseNumber) {
		t.Fatalf("expected driver_license_number, got %+v", es)
	}
	if hasType(es, PassportNumber) {
		t.Fatalf(noPassportFmt, es)
	}

	// "ИНН 7707083893" → только inn
	es = findAll(t, "ИНН 7707083893")
	if !hasType(es, Inn) {
		t.Fatalf("expected inn, got %+v", es)
	}
	if hasType(es, PassportNumber) {
		t.Fatalf(noPassportFmt, es)
	}

	// innClient → только inn (не passport_number)
	es = findAll(t, innClient)
	if !hasType(es, Inn) {
		t.Fatalf("expected inn, got %+v", es)
	}
	if hasType(es, PassportNumber) {
		t.Fatalf(noPassportFmt, es)
	}

	// "паспорт 4509 123456" → passport_number
	es = findAll(t, "паспорт 4509 123456")
	if !hasType(es, PassportNumber) {
		t.Fatalf(passportFmt, es)
	}
	if hasType(es, DriverLicenseNumber) {
		t.Fatalf("expected no driver_license_number, got %+v", es)
	}

	// "Инна Петрова, паспорт 4509 123456" → passport_number
	es = findAll(t, "Инна Петрова, паспорт 4509 123456")
	if !hasType(es, PassportNumber) {
		t.Fatalf(passportFmt, es)
	}

	// "Выдать Петрову паспорт 4509 123456" → passport_number
	es = findAll(t, "Выдать Петрову паспорт 4509 123456")
	if !hasType(es, PassportNumber) {
		t.Fatalf(passportFmt, es)
	}
}

func TestDepartmentCode(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Код подразделения: 770-001", dept770001},
		{dept770001, dept770001},
	} {
		e := findFirst(t, departmentCodeDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
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
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
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
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
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
	for _, tc := range []struct{ in, want string }{
		{"Индекс: 123456", "123456"},
		{"Отправьте на 420000, Казань, ул. Баумана, 5.", "420000"},
		{"Адрес: 630099, Новосибирск", "630099"},
	} {
		e := findFirst(t, postalCodeDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
		}
	}
}

func TestPostalCodeNoFalsePositive(t *testing.T) {
	for _, in := range []string{"Номер заявки 123456789", "Сумма 150000 рублей"} {
		es := postalCodeDetector().Find(in)
		if len(es) != 0 {
			t.Fatalf("for %q expected no postal_code, got %+v", in, es)
		}
	}
}

func TestCountry(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Страна: Россия", "Россия"},
		{"Страна: Новая Зеландия", "Новая Зеландия"},
		{"Страна выдачи паспорта: Узбекистан", "Узбекистан"},
		{"Страна проживания: Казахстан", "Казахстан"},
		{"Страна гражданства: Беларусь", "Беларусь"},
	} {
		e := findFirst(t, countryDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
		}
	}
}

func TestCity(t *testing.T) {
	e := findFirst(t, cityDetector(), "Город: Казань")
	if e.Value != "Казань" {
		t.Fatalf(gotQFmt, e.Value)
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
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
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
	for _, tc := range []struct{ in, want string }{
		{"Адрес: г. Москва, ул. Ленина, д. 5, кв. 12", "г. Москва, ул. Ленина, д. 5, кв. 12"},
		{"Адрес регистрации: Россия, г. Химки, ул. Мира, д. 3", "Россия, г. Химки, ул. Мира, д. 3"},
		{"Адрес доставки: г. Казань, ул. Баумана, д. 2", "г. Казань, ул. Баумана, д. 2"},
	} {
		e := findFirst(t, addressDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
		}
	}
}

func TestCitizenship(t *testing.T) {
	e := findFirst(t, citizenshipDetector(), "Гражданство: Российская Федерация")
	if e.Value != "Российская Федерация" {
		t.Fatalf(gotQFmt, e.Value)
	}
}

func TestBirthPlace(t *testing.T) {
	e := findFirst(t, birthPlaceDetector(), "Место рождения: г. Казань")
	if e.Value != "г. Казань" {
		t.Fatalf(gotQFmt, e.Value)
	}
}

func TestIssuingAuthority(t *testing.T) {
	e := findFirst(t, issuingAuthorityDetector(), "Паспорт выдан ОВД района Арбат;")
	if e.Value != "ОВД района Арбат" {
		t.Fatalf(gotQFmt, e.Value)
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
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
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
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
		}
	}
}

func TestFullNameGivenFirst(t *testing.T) {
	e := findFirst(t, fullNameGivenFirstDetector(), "Иван Иванович Иванов подписал документ.")
	if e.Value != "Иван Иванович Иванов" {
		t.Fatalf(gotQFmt, e.Value)
	}
}

func TestFullNamePair(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Иван Петров прислал письмо", "Иван Петров"},
		{"Пишет вам Тимур Абдуллаев по поводу заявки", "Тимур Абдуллаев"},
	} {
		e := findFirst(t, namePairDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
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
	if hasFullNameContaining(es, pushkin) {
		t.Fatalf(publicFigFmt, es)
	}

	es = findAll(t, "Александр Сергеевич Пушкин — поэт.")
	if hasFullNameContaining(es, pushkin) {
		t.Fatalf(publicFigFmt, es)
	}

	es = findAll(t, "Клиент Александр Пушкин")
	if !hasFullNameContaining(es, pushkin) {
		t.Fatalf("client with public figure name should match, got %+v", es)
	}
}

func TestCardholderName(t *testing.T) {
	e := findFirst(t, cardholderNameDetector(), "Cardholder: IVAN IVANOV")
	if e.Value != "IVAN IVANOV" {
		t.Fatalf(gotQFmt, e.Value)
	}
}

func TestAddressDativeCase(t *testing.T) {
	e := findFirst(t, addressDetector(), "Выезд специалиста по адресу: Новосибирск, Гоголя 10-3.")
	if e.Value != "Новосибирск, Гоголя 10-3." {
		t.Fatalf(gotQFmt, e.Value)
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

func TestFullNameCapitalization(t *testing.T) {
	// Слова имени должны начинаться с заглавной буквы.
	es := findAll(t, "Также клиент сообщил пин-код 5551")
	if hasType(es, FullName) {
		t.Fatalf("lowercase words should not be full_name, got %+v", es)
	}

	for _, tc := range []struct{ in, want string }{
		{"У клиента Константин Викторович Титов не проходит", "Константин Викторович Титов"},
		{"Прошу перевести деньги на счёт Татьяны Романовны Кузнецовой", "Татьяны Романовны Кузнецовой"},
		{"У клиента ПАВЛОВ АРТЁМ ИВАНОВИЧ не проходит", "ПАВЛОВ АРТЁМ ИВАНОВИЧ"},
	} {
		es := findAll(t, tc.in)
		if !hasValue(es, tc.want) {
			t.Fatalf("for %q expected full_name %q, got %+v", tc.in, tc.want, es)
		}
	}
}

func TestSurnameInitials(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Сформируй письмо для Шевченко Л.О.: напомни", "Шевченко Л.О."},
		{"Виноградов П. П.", "Виноградов П. П."},
		{"У клиента БАРАНОВ Н.М. не проходит", "БАРАНОВ Н.М."},
		{"Ковалёв Г. Д.", "Ковалёв Г. Д."},
	} {
		e := findFirst(t, surnameInitialsDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
		}
	}
}

func TestSurnameInitialsReverse(t *testing.T) {
	e := findFirst(t, surnameInitialsDetector(), "Л.О. Шевченко подписал документ")
	if e.Value != "Л.О. Шевченко" {
		t.Fatalf(gotQFmt, e.Value)
	}
}

func TestSurnameYova(t *testing.T) {
	e := findFirst(t, namePairDetector(), "Киселёва Наталья")
	if e.Value != "Киселёва Наталья" {
		t.Fatalf(gotQFmt, e.Value)
	}
}

func TestPublicFigureGagarin(t *testing.T) {
	es := findAll(t, "Юрий Гагарин совершил первый полёт в космос")
	if hasFullNameContaining(es, "гагарин") {
		t.Fatalf(publicFigFmt, es)
	}
}

func TestCardholderLatinUppercase(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"CVV 376, держатель ARTEM PAVLOV. Также", "ARTEM PAVLOV"},
		{"OLEG ALEKSEEV", "OLEG ALEKSEEV"},
	} {
		e := findFirst(t, cardholderNameDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
		}
	}
}

func TestCitizenshipNew(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"являюсь гражданином Республики Беларусь", "Республики Беларусь"},
		{"являюсь гражданином Узбекистана", "Узбекистана"},
		{"Гражданство: Республики Беларусь код подразделения 909-534 Операция", "Республики Беларусь"},
		{"гражданство РФ", "РФ"},
	} {
		e := findFirst(t, citizenshipDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
		}
	}
}

func TestCVVBackLabels(t *testing.T) {
	e := findFirst(t, cvvDetector(), "код на обороте карты 811")
	if e.Value != "811" {
		t.Fatalf(gotQFmt, e.Value)
	}
}

func TestPassportTwoTwoSix(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Паспорт 28 24 568674, прошу", "28 24 568674"},
		{passport226, passport226},
		{"паспорт гражданина РФ 47 08 620831", "47 08 620831"},
	} {
		e := findFirst(t, passportNumberDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
		}
	}
}

func TestDriverLicenseVUNo(t *testing.T) {
	e := findFirst(t, driverLicenseDetector(), "в/у № 77 01 123456")
	if e.Value != driver77 {
		t.Fatalf(gotQFmt, e.Value)
	}
}

func TestBirthDateISO(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"дата рождения 2000-05-05", "2000-05-05"},
		{"1978-02-09", "1978-02-09"},
		{"родился «07» октября 1988 года", "«07» октября 1988"},
		{"родился 1950-06-02 года", "1950-06-02"},
	} {
		e := findFirst(t, birthDateDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
		}
	}
}

func TestPhoneTollFree(t *testing.T) {
	es := phoneDetector().Find("Горячая линия банка: 8 800 200-00-00")
	if len(es) != 0 {
		t.Fatalf("toll-free number should not match phone, got %+v", es)
	}
}

func TestBirthPlaceAbbrev(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"место рождения гор. Тюмень. Паспорт", "гор. Тюмень"},
		{"место рождения пос. Солнечный Московской обл.. Паспорт", "пос. Солнечный Московской обл."},
	} {
		e := findFirst(t, birthPlaceDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
		}
	}
}

func TestIssuingAuthorityBare(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Отделом УФМС России по Омской области", "Отделом УФМС России по Омской области"},
		{"ГУ МВД России по г. Нижний Новгород", "ГУ МВД России по г. Нижний Новгород"},
	} {
		e := findFirst(t, issuingAuthorityDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
		}
	}
}

func TestIssuingAuthorityTrimDate(t *testing.T) {
	e := findFirst(t, issuingAuthorityDetector(), "выдан ГУ МВД России по г. Тюмень 2023.04.02, код подразделения 201-391")
	if e.Value != "ГУ МВД России по г. Тюмень" {
		t.Fatalf(gotQFmt, e.Value)
	}
}

func TestAddressTrim(t *testing.T) {
	e := findFirst(t, addressDetector(), "по адресу г. Волгоград, ул. Октябрьская, д. 72, кв. 271, курьер позвонит на 89235724492")
	if e.Value != "г. Волгоград, ул. Октябрьская, д. 72, кв. 271" {
		t.Fatalf(gotQFmt, e.Value)
	}
}

func TestPostalCodeG(t *testing.T) {
	e := findFirst(t, postalCodeDetector(), "260251, г. Екатеринбург, ул. Садовая")
	if e.Value != "260251" {
		t.Fatalf(gotQFmt, e.Value)
	}
}

func TestStreetPostfix(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Тюмень, Строителей улица, дом 131", "Строителей"},
		{"пр-т Пушкина", "Пушкина"},
	} {
		e := findFirst(t, streetDetector(), tc.in)
		if e.Value != tc.want {
			t.Fatalf(forGotWantFmt, tc.in, e.Value, tc.want)
		}
	}
}