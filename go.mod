module github.com/digitorus/pdfsign

go 1.17

replace (
	github.com/digitorus/pkcs7 v0.0.0-20230220124406-51331ccfc40f => github.com/YapealAG/adapted-digitorus-pkcs7 v0.0.3
	github.com/digitorus/timestamp v0.0.0-20230220124323-d542479a2425 => github.com/YapealAG/adapted-digitorus-timestamp v0.0.1
	golang.org/x/crypto v0.9.0 => github.com/YapealAG/adapted-go-crypto v0.0.1
)

require (
	github.com/digitorus/pdf v0.1.2
	github.com/digitorus/pkcs7 v0.0.0-20230220124406-51331ccfc40f
	github.com/digitorus/timestamp v0.0.0-20230220124323-d542479a2425
	github.com/mattetti/filebuffer v1.0.1
	github.com/stretchr/testify v1.8.3
	golang.org/x/crypto v0.9.0
	golang.org/x/text v0.9.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
