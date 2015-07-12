// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mocks

import (
	"database/sql"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net"
	"time"

	// Load SQLite3 for test purposes
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/mattn/go-sqlite3"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/core"
)

// MockCADatabase is a mock
type MockCADatabase struct {
	db    *gorp.DbMap
	count int64
}

// NewMockCertificateAuthorityDatabase is a mock
func NewMockCertificateAuthorityDatabase() (mock *MockCADatabase, err error) {
	db, err := sql.Open("sqlite3", ":memory:")
	dbmap := &gorp.DbMap{Db: db, Dialect: gorp.SqliteDialect{}}
	mock = &MockCADatabase{db: dbmap, count: 1}
	return mock, err
}

// Begin is a mock
func (cadb *MockCADatabase) Begin() (*gorp.Transaction, error) {
	return cadb.db.Begin()
}

// IncrementAndGetSerial is a mock
func (cadb *MockCADatabase) IncrementAndGetSerial(*gorp.Transaction) (int64, error) {
	cadb.count = cadb.count + 1
	return cadb.count, nil
}

// CreateTablesIfNotExists is a mock
func (cadb *MockCADatabase) CreateTablesIfNotExists() error {
	return nil
}

// MockDNS is a mock
type MockDNS struct {
}

// ExchangeOne is a mock
func (mock *MockDNS) ExchangeOne(m *dns.Msg) (rsp *dns.Msg, rtt time.Duration, err error) {
	return m, 0, nil
}

// LookupTXT is a mock
func (mock *MockDNS) LookupTXT(hostname string) ([]string, time.Duration, error) {
	if hostname == "_acme-challenge.dnssec-failed.org" {
		return nil, 0, core.DNSSECError{}
	}
	return []string{"hostname"}, 0, nil
}

// LookupDNSSEC is a mock
func (mock *MockDNS) LookupDNSSEC(m *dns.Msg) (*dns.Msg, time.Duration, error) {
	return m, 0, nil
}

// LookupHost is a mock
func (mock *MockDNS) LookupHost(hostname string) ([]net.IP, time.Duration, error) {
	return nil, 0, nil
}

// LookupCNAME is a mock
func (mock *MockDNS) LookupCNAME(domain string) (string, error) {
	return "hostname", nil
}

// LookupCAA is a mock
func (mock *MockDNS) LookupCAA(domain string, alias bool) ([]*dns.CAA, error) {
	var results []*dns.CAA
	var record dns.CAA
	switch domain {
	case "reserved.com":
		record.Tag = "issue"
		record.Value = "symantec.com"
		results = append(results, &record)
	case "critical.com":
		record.Flag = 1
		record.Tag = "issue"
		record.Value = "symantec.com"
		results = append(results, &record)
	case "present.com":
		record.Tag = "issue"
		record.Value = "letsencrypt.org"
		results = append(results, &record)
	case "dnssec-failed.org":
		return results, core.DNSSECError{}
	}
	return results, nil
}

type MockSA struct {
	// empty
}

const (
	test1KeyPublicJSON = `
{
	"kty":"RSA",
	"n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ",
	"e":"AAEAAQ"
}`
	test2KeyPublicJSON = `{
		"kty":"RSA",
		"n":"qnARLrT7Xz4gRcKyLdydmCr-ey9OuPImX4X40thk3on26FkMznR3fRjs66eLK7mmPcBZ6uOJseURU6wAaZNmemoYx1dMvqvWWIyiQleHSD7Q8vBrhR6uIoO4jAzJZR-ChzZuSDt7iHN-3xUVspu5XGwXU_MVJZshTwp4TaFx5elHIT_ObnTvTOU3Xhish07AbgZKmWsVbXh5s-CrIicU4OexJPgunWZ_YJJueOKmTvnLlTV4MzKR2oZlBKZ27S0-SfdV_QDx_ydle5oMAyKVtlAV35cyPMIsYNwgUGBCdY_2Uzi5eX0lTc7MPRwz6qR1kip-i59VcGcUQgqHV6Fyqw",
		"e":"AAEAAQ"
	}`
	agreementURL = "http://example.invalid/terms"
)

func (sa *MockSA) GetRegistration(id int64) (core.Registration, error) {
	if id == 100 {
		// Tag meaning "Missing"
		return core.Registration{}, errors.New("missing")
	}
	if id == 101 {
		// Tag meaning "Malformed"
		return core.Registration{}, nil
	}

	keyJSON := []byte(test1KeyPublicJSON)
	var parsedKey jose.JsonWebKey
	parsedKey.UnmarshalJSON(keyJSON)

	return core.Registration{ID: id, Key: parsedKey, Agreement: agreementURL}, nil
}

func (sa *MockSA) GetRegistrationByKey(jwk jose.JsonWebKey) (core.Registration, error) {
	var test1KeyPublic jose.JsonWebKey
	var test2KeyPublic jose.JsonWebKey
	test1KeyPublic.UnmarshalJSON([]byte(test1KeyPublicJSON))
	test2KeyPublic.UnmarshalJSON([]byte(test2KeyPublicJSON))

	if core.KeyDigestEquals(jwk, test1KeyPublic) {
		return core.Registration{ID: 1, Key: jwk, Agreement: agreementURL}, nil
	}

	if core.KeyDigestEquals(jwk, test2KeyPublic) {
		// No key found
		return core.Registration{ID: 2}, sql.ErrNoRows
	}

	// Return a fake registration
	return core.Registration{ID: 1, Agreement: agreementURL}, nil
}

func (sa *MockSA) GetAuthorization(id string) (core.Authorization, error) {
	if id == "valid" {
		exp := time.Now().AddDate(100, 0, 0)
		return core.Authorization{Status: core.StatusValid, RegistrationID: 1, Expires: &exp, Identifier: core.AcmeIdentifier{Type: "dns", Value: "not-an-example.com"}}, nil
	}
	return core.Authorization{}, nil
}

func (sa *MockSA) GetCertificate(serial string) (core.Certificate, error) {
	// Serial ee == 238.crt
	if serial == "000000000000000000000000000000ee" {
		certPemBytes, _ := ioutil.ReadFile("test/238.crt")
		certBlock, _ := pem.Decode(certPemBytes)
		return core.Certificate{
			RegistrationID: 1,
			DER:            certBlock.Bytes,
		}, nil
	} else if serial == "000000000000000000000000000000b2" {
		certPemBytes, _ := ioutil.ReadFile("test/178.crt")
		certBlock, _ := pem.Decode(certPemBytes)
		return core.Certificate{
			RegistrationID: 1,
			DER:            certBlock.Bytes,
		}, nil
	} else {
		return core.Certificate{}, errors.New("No cert")
	}
}

func (sa *MockSA) GetCertificateByShortSerial(string) (core.Certificate, error) {
	return core.Certificate{}, nil
}

func (sa *MockSA) GetCertificateStatus(serial string) (core.CertificateStatus, error) {
	// Serial ee == 238.crt
	if serial == "000000000000000000000000000000ee" {
		return core.CertificateStatus{
			Status: core.OCSPStatusGood,
		}, nil
	} else if serial == "000000000000000000000000000000b2" {
		return core.CertificateStatus{
			Status: core.OCSPStatusRevoked,
		}, nil
	} else {
		return core.CertificateStatus{}, errors.New("No cert status")
	}
}

func (sa *MockSA) AlreadyDeniedCSR([]string) (bool, error) {
	return false, nil
}

func (sa *MockSA) AddCertificate(certDER []byte, regID int64) (digest string, err error) {
	return
}

func (sa *MockSA) FinalizeAuthorization(authz core.Authorization) (err error) {
	return
}

func (sa *MockSA) MarkCertificateRevoked(serial string, ocspResponse []byte, reasonCode int) (err error) {
	return
}

func (sa *MockSA) UpdateOCSP(serial string, ocspResponse []byte) (err error) {
	return
}

func (sa *MockSA) NewPendingAuthorization(authz core.Authorization) (output core.Authorization, err error) {
	return
}

func (sa *MockSA) NewRegistration(reg core.Registration) (regR core.Registration, err error) {
	return
}

func (sa *MockSA) UpdatePendingAuthorization(authz core.Authorization) (err error) {
	return
}

func (sa *MockSA) UpdateRegistration(reg core.Registration) (err error) {
	return
}

func (sa *MockSA) GetSCTReciepts(serial string) (scts []*core.SignedCertificateTimestamp, err error) {
	return
}

func (sa *MockSA) GetSCTReciept(serial string, logID []byte) (sct *core.SignedCertificateTimestamp, err error) {
	return
}

func (sa *MockSA) AddSCTReciept(sct core.SignedCertificateTimestamp) (err error) {
	return
}
