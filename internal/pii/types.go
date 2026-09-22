package pii

// Type — строковый идентификатор типа персональных данных.
type Type string

const (
	FullName             Type = "full_name"
	CardholderName       Type = "cardholder_name"
	BirthDate            Type = "birth_date"
	BirthPlace           Type = "birth_place"
	PassportNumber       Type = "passport_number"
	Citizenship          Type = "citizenship"
	IssuingAuthority     Type = "issuing_authority"
	DepartmentCode       Type = "department_code"
	PassportIssueDate    Type = "passport_issue_date"
	DriverLicenseNumber  Type = "driver_license_number"
	Address              Type = "address"
	PostalCode           Type = "postal_code"
	City                 Type = "city"
	Street               Type = "street"
	HouseFlat            Type = "house_flat"
	Email                Type = "email"
	Phone                Type = "phone"
	Inn                  Type = "inn"
	CardNumber           Type = "card_number"
	CVV                  Type = "cvv"
	PIN                  Type = "pin"
	Country              Type = "country"
)

// AllTypes перечисляет все типы персональных данных и используется
// для валидации конфигурации систем-потребителей.
var AllTypes = []Type{
	FullName,
	CardholderName,
	BirthDate,
	BirthPlace,
	PassportNumber,
	Citizenship,
	IssuingAuthority,
	DepartmentCode,
	PassportIssueDate,
	DriverLicenseNumber,
	Address,
	PostalCode,
	City,
	Street,
	HouseFlat,
	Email,
	Phone,
	Inn,
	CardNumber,
	CVV,
	PIN,
	Country,
}

// Entity описывает найденный фрагмент персональных данных в тексте.
type Entity struct {
	Type       Type
	Start, End int
	Value      string
	Confidence float64
}

// Detector находит персональные данные определённого типа в тексте.
type Detector interface {
	Type() Type
	Find(text string) []Entity
}