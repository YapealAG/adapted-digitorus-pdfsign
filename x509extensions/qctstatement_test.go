package x509extension

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// pkix.Extension
type Ext struct {
	Id       []int8
	Critical bool
	Value    string
}

var Sample = Ext{
	Id:       []int8{1, 3, 6, 1, 5, 5, 7, 1, 3},
	Critical: false,
	Value:    "MGowCAYGBACORgEBMAgGBgQAjkYBBDATBgYEAI5GAQYwCQYHBACORgEGATA/BgYEAI5GAQUwNTAzFi1odHRwczovL3d3dy5zd2lzc2RpZ2ljZXJ0LmNoL2RpYW1hbnQ0ZXUtbi5wZGYTAmVu",
}

func TestQCStatement(t *testing.T) {
	RawBytes, _ := base64.StdEncoding.DecodeString(Sample.Value)

	// var rawValue asn1.RawValue

	fmt.Printf("hex %v\n", hex.EncodeToString(RawBytes))

	// rest_1, _ := asn1.Unmarshal(RawBytes, &rawValue)

	// fmt.Printf("Class %v Tag %v len Rest %v \n", rawValue.Class, rawValue.Tag, len(rest_1))
	// fmt.Printf("hex %v\n", hex.EncodeToString(rawValue.Bytes))

	// rest_2, _ := asn1.Unmarshal(rawValue.Bytes, &rawValue)
	// fmt.Printf("Class %v Tag %v len Rest %v \n", rawValue.Class, rawValue.Tag, len(rest_2))
	// fmt.Printf("hex %v\n", hex.EncodeToString(rawValue.Bytes))

	// rest_3, _ := asn1.Unmarshal(rawValue.Bytes, &rawValue)
	// fmt.Printf("Class %v Tag %v len Rest %v \n", rawValue.Class, rawValue.Tag, len(rest_3))
	// fmt.Printf("hex %v\n", hex.EncodeToString(rawValue.Bytes))

	// rest_4, _ := asn1.Unmarshal(rest_2, &rawValue)
	// fmt.Printf("Class %v Tag %v len Rest %v \n", rawValue.Class, rawValue.Tag, len(rest_4))
	// fmt.Printf("hex %v\n", hex.EncodeToString(rawValue.Bytes))

	// rest_5, _ := asn1.Unmarshal(rawValue.Bytes, &rawValue)
	// fmt.Printf("Class %v Tag %v len Rest %v \n", rawValue.Class, rawValue.Tag, len(rest_5))
	// fmt.Printf("hex %v\n", hex.EncodeToString(rawValue.Bytes))

	// rest_6, _ := asn1.Unmarshal(rest_4, &rawValue)
	// fmt.Printf("Class %v Tag %v len Rest %v \n", rawValue.Class, rawValue.Tag, len(rest_6))
	// fmt.Printf("hex %v\n", hex.EncodeToString(rawValue.Bytes))

	// rest_7, _ := asn1.Unmarshal(rawValue.Bytes, &rawValue)
	// fmt.Printf("Class %v Tag %v len Rest %v \n", rawValue.Class, rawValue.Tag, len(rest_7))
	// fmt.Printf("hex %v\n", hex.EncodeToString(rawValue.Bytes))

	rawStatements := QCStatementsASN{}
	rest, err := asn1.Unmarshal(RawBytes, &rawStatements.QCStatements)
	assert.NoError(t, err, "statements")
	assert.EqualValues(t, len(rest), 0, "rest")

	qcStatements := QCStatements{}
	err = qcStatements.Parse(&rawStatements)
	assert.NoError(t, err, "parse")

	fmt.Printf("res %v", qcStatements)
}
