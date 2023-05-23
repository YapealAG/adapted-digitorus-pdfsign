package x509extension

import (
	"encoding/asn1"
	"errors"
)

// ETSI OIDS from https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.02.03_20/en_31941205v020203a.pdf
// origin https://github.com/zmap/zcrypto/blob/master/x509/x509.go

var (
	oidEtsiQcsQcCompliance      = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1}
	oidEtsiQcsQcLimitValue      = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 2}
	oidEtsiQcsQcRetentionPeriod = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 3}
	oidEtsiQcsQcSSCD            = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 4}
	oidEtsiQcsQcEuPDS           = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 5}
	oidEtsiQcsQcType            = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6}
	oidEtsiQcsQcCCLegislation   = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 7}
	oidEtsiQcsQctEsign          = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 1} // qualifed
	oidEtsiQcsQctEseal          = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 2} // qualified seal
	oidEtsiQcsQctWeb            = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 3} // web
)

type QCStatements struct {
	StatementIDs     []string            `json:"ids,omitempty"`
	ParsedStatements *ParsedQCStatements `json:"parsed,omitempty"`
}

type ParsedQCStatements struct {
	ETSICompliance  []bool          `json:"etsi_compliance,omitempty"`
	SSCD            []bool          `json:"sscd,omitempty"`
	Types           []QCType        `json:"types,omitempty"`
	Limit           []MonetaryValue `json:"limit,omitempty"`
	PDSLocations    []PDSLocations  `json:"pds_locations,omitempty"`
	RetentionPeriod []int           `json:"retention_period,omitempty"`
	Legislation     []Legislation   `json:"legislation,omitempty"`
}

type MonetaryValue struct {
	Currency       string `json:"currency,omitempty"`
	CurrencyNumber int    `json:"currency_number,omitempty"`
	Amount         int    `json:"amount,omitempty"`
	Exponent       int    `json:"exponent,omitempty"`
}

type monetaryValueASNString struct {
	Currency string `asn1:"printable"`
	Amount   int
	Exponent int
}

type monetaryValueASNNumber struct {
	Currency int
	Amount   int
	Exponent int
}

type PDSLocations struct {
	Locations []PDSLocation `json:"locations,omitempty"`
}

type PDSLocation struct {
	URL      string `json:"url,omitempty" asn1:"ia5"`
	Language string `json:"language,omitempty" asn1:"printable"`
}

type QCType struct {
	TypeIdentifiers []asn1.ObjectIdentifier
}

type Legislation struct {
	CountryCodes []string `json:"country_codes,omitempty"`
}

type QCStatementASN struct {
	StatementID   asn1.ObjectIdentifier
	StatementInfo asn1.RawValue `asn1:"optional"`
}

type QCStatementsASN struct {
	QCStatements []QCStatementASN
}

func ParseStatements(
	rawBytes []byte,
) (
	qcStatements QCStatements,
	err error,
) {
	rawStatements := QCStatementsASN{}
	_, err = asn1.Unmarshal(rawBytes, &rawStatements.QCStatements)
	if err != nil {
		return
	}
	err = qcStatements.Parse(&rawStatements)
	return
}

func (q *QCStatements) Parse(in *QCStatementsASN) error {
	q.StatementIDs = make([]string, len(in.QCStatements))
	known := ParsedQCStatements{}
	for i, s := range in.QCStatements {
		val := in.QCStatements[i].StatementInfo.FullBytes
		q.StatementIDs[i] = s.StatementID.String()
		if s.StatementID.Equal(oidEtsiQcsQcCompliance) {
			known.ETSICompliance = append(known.ETSICompliance, true)
			if val != nil {
				return errors.New("EtsiQcsQcCompliance QCStatement must not contain a statementInfo")
			}
		} else if s.StatementID.Equal(oidEtsiQcsQcLimitValue) {
			// TODO
			mvs := monetaryValueASNString{}
			mvn := monetaryValueASNNumber{}
			out := MonetaryValue{}
			if _, err := asn1.Unmarshal(val, &mvs); err == nil {
				out.Currency = mvs.Currency
				out.Amount = mvs.Amount
				out.Exponent = mvs.Exponent
			} else if _, err := asn1.Unmarshal(val, &mvn); err == nil {
				out.CurrencyNumber = mvn.Currency
				out.Amount = mvn.Amount
				out.Exponent = mvn.Exponent
			} else {
				return err
			}
			known.Limit = append(known.Limit, out)
		} else if s.StatementID.Equal(oidEtsiQcsQcRetentionPeriod) {
			var retentionPeriod int
			if _, err := asn1.Unmarshal(val, &retentionPeriod); err != nil {
				return err
			}
			known.RetentionPeriod = append(known.RetentionPeriod, retentionPeriod)
		} else if s.StatementID.Equal(oidEtsiQcsQcSSCD) {
			known.SSCD = append(known.SSCD, true)
			if val != nil {
				return errors.New("EtsiQcsQcSSCD QCStatement must not contain a statementInfo")
			}
		} else if s.StatementID.Equal(oidEtsiQcsQcEuPDS) {
			locations := make([]PDSLocation, 0)
			if _, err := asn1.Unmarshal(val, &locations); err != nil {
				return err
			}
			known.PDSLocations = append(known.PDSLocations, PDSLocations{
				Locations: locations,
			})
		} else if s.StatementID.Equal(oidEtsiQcsQcType) {
			typeIds := make([]asn1.ObjectIdentifier, 0)
			if _, err := asn1.Unmarshal(val, &typeIds); err != nil {
				return err
			}
			known.Types = append(known.Types, QCType{
				TypeIdentifiers: typeIds,
			})
		} else if s.StatementID.Equal(oidEtsiQcsQcCCLegislation) {
			countryCodes := make([]string, 0)
			if _, err := asn1.Unmarshal(val, &countryCodes); err != nil {
				return err
			}
			known.Legislation = append(known.Legislation, Legislation{
				CountryCodes: countryCodes,
			})
		}
	}
	q.ParsedStatements = &known
	return nil
}
