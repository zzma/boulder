package sa

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/zzma/boulder/core"
	corepb "github.com/zzma/boulder/core/proto"
	berrors "github.com/zzma/boulder/errors"
	"github.com/zzma/boulder/features"
	bgrpc "github.com/zzma/boulder/grpc"
	"github.com/zzma/boulder/identifier"
	blog "github.com/zzma/boulder/log"
	"github.com/zzma/boulder/metrics"
	"github.com/zzma/boulder/probs"
	"github.com/zzma/boulder/revocation"
	sapb "github.com/zzma/boulder/sa/proto"
	"github.com/zzma/boulder/sa/satest"
	"github.com/zzma/boulder/test"
	"github.com/zzma/boulder/test/vars"
	gorp "gopkg.in/go-gorp/gorp.v2"
	jose "gopkg.in/square/go-jose.v2"
)

var log = blog.UseMock()
var ctx = context.Background()

// initSA constructs a SQLStorageAuthority and a clean up function
// that should be defer'ed to the end of the test.
func initSA(t *testing.T) (*SQLStorageAuthority, clock.FakeClock, func()) {
	features.Reset()

	dbMap, err := NewDbMap(vars.DBConnSA, 0)
	if err != nil {
		t.Fatalf("Failed to create dbMap: %s", err)
	}

	fc := clock.NewFake()
	fc.Set(time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC))

	sa, err := NewSQLStorageAuthority(dbMap, fc, log, metrics.NewNoopScope(), 1)
	if err != nil {
		t.Fatalf("Failed to create SA: %s", err)
	}

	cleanUp := test.ResetSATestDatabase(t)
	return sa, fc, cleanUp
}

var (
	anotherKey = `{
	"kty":"RSA",
	"n": "vd7rZIoTLEe-z1_8G1FcXSw9CQFEJgV4g9V277sER7yx5Qjz_Pkf2YVth6wwwFJEmzc0hoKY-MMYFNwBE4hQHw",
	"e":"AQAB"
}`
)

func TestAddRegistration(t *testing.T) {
	sa, clk, cleanUp := initSA(t)
	defer cleanUp()

	jwk := satest.GoodJWK()

	contact := "mailto:foo@example.com"
	contacts := &[]string{contact}
	reg, err := sa.NewRegistration(ctx, core.Registration{
		Key:       jwk,
		Contact:   contacts,
		InitialIP: net.ParseIP("43.34.43.34"),
	})
	if err != nil {
		t.Fatalf("Couldn't create new registration: %s", err)
	}
	test.Assert(t, reg.ID != 0, "ID shouldn't be 0")
	test.AssertDeepEquals(t, reg.Contact, contacts)

	_, err = sa.GetRegistration(ctx, 0)
	test.AssertError(t, err, "Registration object for ID 0 was returned")

	dbReg, err := sa.GetRegistration(ctx, reg.ID)
	test.AssertNotError(t, err, fmt.Sprintf("Couldn't get registration with ID %v", reg.ID))

	expectedReg := core.Registration{
		ID:        reg.ID,
		Key:       jwk,
		InitialIP: net.ParseIP("43.34.43.34"),
		CreatedAt: clk.Now(),
	}
	test.AssertEquals(t, dbReg.ID, expectedReg.ID)
	test.Assert(t, core.KeyDigestEquals(dbReg.Key, expectedReg.Key), "Stored key != expected")

	newReg := core.Registration{
		ID:        reg.ID,
		Key:       jwk,
		Contact:   &[]string{"test.com"},
		InitialIP: net.ParseIP("72.72.72.72"),
		Agreement: "yes",
	}
	err = sa.UpdateRegistration(ctx, newReg)
	test.AssertNotError(t, err, fmt.Sprintf("Couldn't get registration with ID %v", reg.ID))
	dbReg, err = sa.GetRegistrationByKey(ctx, jwk)
	test.AssertNotError(t, err, "Couldn't get registration by key")

	test.AssertEquals(t, dbReg.ID, newReg.ID)
	test.AssertEquals(t, dbReg.Agreement, newReg.Agreement)

	var anotherJWK jose.JSONWebKey
	err = json.Unmarshal([]byte(anotherKey), &anotherJWK)
	test.AssertNotError(t, err, "couldn't unmarshal anotherJWK")
	_, err = sa.GetRegistrationByKey(ctx, &anotherJWK)
	test.AssertError(t, err, "Registration object for invalid key was returned")
}

func TestNoSuchRegistrationErrors(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	_, err := sa.GetRegistration(ctx, 100)
	if !berrors.Is(err, berrors.NotFound) {
		t.Errorf("GetRegistration: expected a berrors.NotFound type error, got %T type error (%s)", err, err)
	}

	jwk := satest.GoodJWK()
	_, err = sa.GetRegistrationByKey(ctx, jwk)
	if !berrors.Is(err, berrors.NotFound) {
		t.Errorf("GetRegistrationByKey: expected a berrors.NotFound type error, got %T type error (%s)", err, err)
	}

	err = sa.UpdateRegistration(ctx, core.Registration{ID: 100, Key: jwk})
	if !berrors.Is(err, berrors.NotFound) {
		t.Errorf("UpdateRegistration: expected a berrors.NotFound type error, got %T type error (%v)", err, err)
	}
}

func TestCountPendingAuthorizations(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	expires := fc.Now().Add(time.Hour)
	pendingAuthz := core.Authorization{
		RegistrationID: reg.ID,
		Expires:        &expires,
	}

	pendingAuthz, err := sa.NewPendingAuthorization(ctx, pendingAuthz)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	count, err := sa.CountPendingAuthorizations(ctx, reg.ID)
	test.AssertNotError(t, err, "Couldn't count pending authorizations")
	test.AssertEquals(t, count, 0)

	pendingAuthz.Status = core.StatusPending
	pendingAuthz, err = sa.NewPendingAuthorization(ctx, pendingAuthz)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	count, err = sa.CountPendingAuthorizations(ctx, reg.ID)
	test.AssertNotError(t, err, "Couldn't count pending authorizations")
	test.AssertEquals(t, count, 1)

	fc.Add(2 * time.Hour)
	count, err = sa.CountPendingAuthorizations(ctx, reg.ID)
	test.AssertNotError(t, err, "Couldn't count pending authorizations")
	test.AssertEquals(t, count, 0)
}

func TestAddAuthorization(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	PA := core.Authorization{RegistrationID: reg.ID}

	PA, err := sa.NewPendingAuthorization(ctx, PA)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, PA.ID != "", "ID shouldn't be blank")

	dbPa, err := sa.GetAuthorization(ctx, PA.ID)
	test.AssertNotError(t, err, "Couldn't get pending authorization with ID "+PA.ID)
	test.AssertMarshaledEquals(t, PA, dbPa)

	expectedPa := core.Authorization{ID: PA.ID}
	test.AssertMarshaledEquals(t, dbPa.ID, expectedPa.ID)

	exp := time.Now().AddDate(0, 0, 1)
	identifier := identifier.ACMEIdentifier{Type: identifier.DNS, Value: "wut.com"}
	newPa := core.Authorization{ID: PA.ID, Identifier: identifier, RegistrationID: reg.ID, Status: core.StatusPending, Expires: &exp}

	newPa.Status = core.StatusValid
	err = sa.FinalizeAuthorization(ctx, newPa)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+PA.ID)

	dbPa, err = sa.GetAuthorization(ctx, PA.ID)
	test.AssertNotError(t, err, "Couldn't get authorization with ID "+PA.ID)
}

func TestRecyclePendingDisabled(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	pendingAuthz, err := sa.NewPendingAuthorization(ctx, core.Authorization{RegistrationID: reg.ID})

	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, pendingAuthz.ID != "", "ID shouldn't be blank")

	pendingAuthz2, err := sa.NewPendingAuthorization(ctx, core.Authorization{RegistrationID: reg.ID})

	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.AssertNotEquals(t, pendingAuthz.ID, pendingAuthz2.ID)
}

func TestRecyclePendingEnabled(t *testing.T) {

	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	expires := fc.Now()
	authz := core.Authorization{
		RegistrationID: reg.ID,
		Identifier: identifier.ACMEIdentifier{
			Type:  "dns",
			Value: "example.letsencrypt.org",
		},
		Challenges: []core.Challenge{
			core.Challenge{
				URI:    "https://acme-example.letsencrypt.org/challenge123",
				Type:   "http-01",
				Status: "pending",
				Token:  "abc",
			},
		},
		Expires: &expires,
	}

	// Add expired authz
	_, err := sa.NewPendingAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Couldn't create new expired pending authorization")

	// Add expected authz
	fc.Add(3 * time.Hour)
	expires = fc.Now().Add(2 * time.Hour) // magic pointer
	pendingAuthzA, err := sa.NewPendingAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, pendingAuthzA.ID != "", "ID shouldn't be blank")
	// Add extra authz for kicks
	pendingAuthzB, err := sa.NewPendingAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, pendingAuthzB.ID != "", "ID shouldn't be blank")
}

func CreateDomainAuth(t *testing.T, domainName string, sa *SQLStorageAuthority) (authz core.Authorization) {
	return CreateDomainAuthWithRegID(t, domainName, sa, 42)
}

func CreateDomainAuthWithRegID(t *testing.T, domainName string, sa *SQLStorageAuthority, regID int64) (authz core.Authorization) {
	exp := sa.clk.Now().AddDate(0, 0, 1) // expire in 1 day

	// create pending auth
	authz, err := sa.NewPendingAuthorization(ctx, core.Authorization{
		Status:         core.StatusPending,
		Expires:        &exp,
		Identifier:     identifier.ACMEIdentifier{Type: identifier.DNS, Value: domainName},
		RegistrationID: regID,
		Challenges:     []core.Challenge{{Type: "simpleHttp", Status: core.StatusValid, URI: domainName, Token: "THISWOULDNTBEAGOODTOKEN"}},
	})
	if err != nil {
		t.Fatalf("Couldn't create new pending authorization: %s", err)
	}
	test.Assert(t, authz.ID != "", "ID shouldn't be blank")

	return
}

// Ensure we get only valid authorization with correct RegID
func TestGetValidAuthorizationsBasic(t *testing.T) {
	sa, clk, cleanUp := initSA(t)
	defer cleanUp()

	// Attempt to get unauthorized domain.
	authzMap, err := sa.GetValidAuthorizations(ctx, 0, []string{"example.org"}, clk.Now())
	// Should get no results, but not error.
	test.AssertNotError(t, err, "Error getting valid authorizations")
	test.AssertEquals(t, len(authzMap), 0)

	reg := satest.CreateWorkingRegistration(t, sa)

	// authorize "example.org"
	authz := CreateDomainAuthWithRegID(t, "example.org", sa, reg.ID)

	// finalize auth
	authz.Status = core.StatusValid
	err = sa.FinalizeAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+authz.ID)

	// attempt to get authorized domain with wrong RegID
	authzMap, err = sa.GetValidAuthorizations(ctx, 0, []string{"example.org"}, clk.Now())
	test.AssertNotError(t, err, "Error getting valid authorizations")
	test.AssertEquals(t, len(authzMap), 0)

	// get authorized domain
	authzMap, err = sa.GetValidAuthorizations(ctx, reg.ID, []string{"example.org"}, clk.Now())
	test.AssertNotError(t, err, "Should have found a valid auth for example.org and regID 42")
	test.AssertEquals(t, len(authzMap), 1)
	result := authzMap["example.org"]
	test.AssertEquals(t, result.Status, core.StatusValid)
	test.AssertEquals(t, result.Identifier.Type, identifier.DNS)
	test.AssertEquals(t, result.Identifier.Value, "example.org")
	test.AssertEquals(t, result.RegistrationID, reg.ID)
}

func TestCountInvalidAuthorizations(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)

	key2 := new(jose.JSONWebKey)
	key2.Key = &rsa.PublicKey{N: big.NewInt(1), E: 3}
	reg2, err := sa.NewRegistration(context.Background(), core.Registration{
		Key:       key2,
		InitialIP: net.ParseIP("88.77.66.11"),
		CreatedAt: time.Date(2003, 5, 10, 0, 0, 0, 0, time.UTC),
		Status:    core.StatusValid,
	})
	test.AssertNotError(t, err, "making registration")

	baseTime := time.Date(2017, 3, 4, 5, 0, 0, 0, time.UTC)
	latest := baseTime.Add(3 * time.Hour)

	makeInvalidAuthz := func(regID int64, domain string, offset time.Duration) {
		authz := CreateDomainAuthWithRegID(t, domain, sa, regID)
		exp := baseTime.Add(offset)
		authz.Expires = &exp
		authz.Status = "invalid"
		err := sa.FinalizeAuthorization(ctx, authz)
		test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+authz.ID)
	}

	// We're going to count authzs for reg.ID and example.net, expiring between
	// baseTime and baseTime + 3 hours, so add two examples that should be counted
	// (1 hour from now and 2 hours from now), plus three that shouldn't be
	// counted (too far future, wrong domain name, and wrong ID).
	hostname := "example.net"
	makeInvalidAuthz(reg.ID, hostname, time.Hour)
	makeInvalidAuthz(reg.ID, hostname, 2*time.Hour)
	makeInvalidAuthz(reg.ID, hostname, 24*time.Hour)
	makeInvalidAuthz(reg.ID, "example.com", time.Hour)
	makeInvalidAuthz(reg2.ID, hostname, time.Hour)

	earliestNanos := baseTime.UnixNano()
	latestNanos := latest.UnixNano()

	count, err := sa.CountInvalidAuthorizations(context.Background(), &sapb.CountInvalidAuthorizationsRequest{
		RegistrationID: &reg.ID,
		Hostname:       &hostname,
		Range: &sapb.Range{
			Earliest: &earliestNanos,
			Latest:   &latestNanos,
		},
	})
	test.AssertNotError(t, err, "counting invalid authorizations")

	if *count.Count != 2 {
		t.Errorf("expected to count 2 invalid authorizations, counted %d instead", *count.Count)
	}
}

// Ensure we get the latest valid authorization for an ident
func TestGetValidAuthorizationsDuplicate(t *testing.T) {
	sa, clk, cleanUp := initSA(t)
	defer cleanUp()

	domain := "example.org"
	var err error

	reg := satest.CreateWorkingRegistration(t, sa)

	makeAuthz := func(daysToExpiry int, status core.AcmeStatus) core.Authorization {
		authz := CreateDomainAuthWithRegID(t, domain, sa, reg.ID)
		exp := clk.Now().AddDate(0, 0, daysToExpiry)
		authz.Expires = &exp
		authz.Status = status
		err = sa.FinalizeAuthorization(ctx, authz)
		test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+authz.ID)
		return authz
	}

	// create invalid authz
	makeAuthz(10, core.StatusInvalid)

	// should not get the auth
	authzMap, err := sa.GetValidAuthorizations(ctx, reg.ID, []string{domain}, clk.Now())
	test.AssertEquals(t, len(authzMap), 0)

	// create valid auth
	makeAuthz(1, core.StatusValid)

	// should get the valid auth even if it's expire date is lower than the invalid one
	authzMap, err = sa.GetValidAuthorizations(ctx, reg.ID, []string{domain}, clk.Now())
	test.AssertNotError(t, err, "Should have found a valid auth for "+domain)
	test.AssertEquals(t, len(authzMap), 1)
	result1 := authzMap[domain]
	test.AssertEquals(t, result1.Status, core.StatusValid)
	test.AssertEquals(t, result1.Identifier.Type, identifier.DNS)
	test.AssertEquals(t, result1.Identifier.Value, domain)
	test.AssertEquals(t, result1.RegistrationID, reg.ID)

	// create a newer auth
	newAuthz := makeAuthz(2, core.StatusValid)

	authzMap, err = sa.GetValidAuthorizations(ctx, reg.ID, []string{domain}, clk.Now())
	test.AssertNotError(t, err, "Should have found a valid auth for "+domain)
	test.AssertEquals(t, len(authzMap), 1)
	result2 := authzMap[domain]
	test.AssertEquals(t, result2.Status, core.StatusValid)
	test.AssertEquals(t, result2.Identifier.Type, identifier.DNS)
	test.AssertEquals(t, result2.Identifier.Value, domain)
	test.AssertEquals(t, result2.RegistrationID, reg.ID)
	// make sure we got the latest auth
	test.AssertEquals(t, result2.ID, newAuthz.ID)
}

// Fetch multiple authzs at once. Check that
func TestGetValidAuthorizationsMultiple(t *testing.T) {
	sa, clk, cleanUp := initSA(t)
	defer cleanUp()
	var err error

	reg := satest.CreateWorkingRegistration(t, sa)

	makeAuthz := func(daysToExpiry int, status core.AcmeStatus, domain string) core.Authorization {
		authz := CreateDomainAuthWithRegID(t, domain, sa, reg.ID)
		exp := clk.Now().AddDate(0, 0, daysToExpiry)
		authz.Expires = &exp
		authz.Status = status
		err = sa.FinalizeAuthorization(ctx, authz)
		test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+authz.ID)
		return authz
	}
	makeAuthz(1, core.StatusValid, "blog.example.com")
	makeAuthz(2, core.StatusInvalid, "blog.example.com")
	makeAuthz(5, core.StatusValid, "www.example.com")
	wwwAuthz := makeAuthz(6, core.StatusValid, "www.example.com")

	authzMap, err := sa.GetValidAuthorizations(ctx, reg.ID,
		[]string{"blog.example.com", "www.example.com", "absent.example.com"}, clk.Now())
	test.AssertNotError(t, err, "Couldn't get authorizations")
	test.AssertEquals(t, len(authzMap), 2)
	blogResult := authzMap["blog.example.com"]
	if blogResult == nil {
		t.Errorf("Didn't find blog.example.com in result")
	}
	if blogResult.Status == core.StatusInvalid {
		t.Errorf("Got invalid blogResult")
	}
	wwwResult := authzMap["www.example.com"]
	if wwwResult == nil {
		t.Errorf("Didn't find www.example.com in result")
	}
	test.AssertEquals(t, wwwResult.ID, wwwAuthz.ID)
}

func TestAddCertificate(t *testing.T) {
	sa, clk, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)

	// An example cert taken from EFF's website
	certDER, err := ioutil.ReadFile("www.eff.org.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")

	// Calling AddCertificate with a non-nil issued should succeed
	issued := sa.clk.Now()
	digest, err := sa.AddCertificate(ctx, certDER, reg.ID, nil, &issued)
	test.AssertNotError(t, err, "Couldn't add www.eff.org.der")
	test.AssertEquals(t, digest, "qWoItDZmR4P9eFbeYgXXP3SR4ApnkQj8x4LsB_ORKBo")

	retrievedCert, err := sa.GetCertificate(ctx, "000000000000000000000000000000021bd4")
	test.AssertNotError(t, err, "Couldn't get www.eff.org.der by full serial")
	test.AssertByteEquals(t, certDER, retrievedCert.DER)
	// Because nil was provided as the Issued time we expect the cert was stored
	// with an issued time equal to now
	test.AssertEquals(t, retrievedCert.Issued, clk.Now())

	certificateStatus, err := sa.GetCertificateStatus(ctx, "000000000000000000000000000000021bd4")
	test.AssertNotError(t, err, "Couldn't get status for www.eff.org.der")
	test.Assert(t, certificateStatus.Status == core.OCSPStatusGood, "OCSP Status should be good")
	test.Assert(t, certificateStatus.OCSPLastUpdated.IsZero(), "OCSPLastUpdated should be nil")
	test.AssertEquals(t, certificateStatus.NotAfter, retrievedCert.Expires)

	// Test cert generated locally by Boulder / CFSSL, names [example.com,
	// www.example.com, admin.example.com]
	certDER2, err := ioutil.ReadFile("test-cert.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")
	serial := "ffdd9b8a82126d96f61d378d5ba99a0474f0"

	// Add the certificate with a specific issued time instead of nil
	issuedTime := time.Date(2018, 4, 1, 7, 0, 0, 0, time.UTC)
	digest2, err := sa.AddCertificate(ctx, certDER2, reg.ID, nil, &issuedTime)
	test.AssertNotError(t, err, "Couldn't add test-cert.der")
	test.AssertEquals(t, digest2, "vrlPN5wIPME1D2PPsCy-fGnTWh8dMyyYQcXPRkjHAQI")

	retrievedCert2, err := sa.GetCertificate(ctx, serial)
	test.AssertNotError(t, err, "Couldn't get test-cert.der")
	test.AssertByteEquals(t, certDER2, retrievedCert2.DER)
	// The cert should have been added with the specific issued time we provided
	// as the issued field.
	test.AssertEquals(t, retrievedCert2.Issued, issuedTime)

	certificateStatus2, err := sa.GetCertificateStatus(ctx, serial)
	test.AssertNotError(t, err, "Couldn't get status for test-cert.der")
	test.Assert(t, certificateStatus2.Status == core.OCSPStatusGood, "OCSP Status should be good")
	test.Assert(t, certificateStatus2.OCSPLastUpdated.IsZero(), "OCSPLastUpdated should be nil")

	// Test adding OCSP response with cert
	certDER3, err := ioutil.ReadFile("test-cert2.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")
	serial = "ffa0160630d618b2eb5c0510824b14274856"
	ocspResp := []byte{0, 0, 1}
	_, err = sa.AddCertificate(ctx, certDER3, reg.ID, ocspResp, &issuedTime)
	test.AssertNotError(t, err, "Couldn't add test-cert2.der")

	certificateStatus3, err := sa.GetCertificateStatus(ctx, serial)
	test.AssertNotError(t, err, "Couldn't get status for test-cert2.der")
	test.Assert(
		t,
		bytes.Compare(certificateStatus3.OCSPResponse, ocspResp) == 0,
		fmt.Sprintf("OCSP responses don't match, expected: %x, got %x", certificateStatus3.OCSPResponse, ocspResp),
	)
	test.Assert(
		t,
		clk.Now().Equal(certificateStatus3.OCSPLastUpdated),
		fmt.Sprintf("OCSPLastUpdated doesn't match, expected %s, got %s", clk.Now(), certificateStatus3.OCSPLastUpdated),
	)
}

func TestCountCertificatesByNames(t *testing.T) {
	sa, clk, cleanUp := initSA(t)
	defer cleanUp()

	// Test cert generated locally by Boulder / CFSSL, names [example.com,
	// www.example.com, admin.example.com]
	certDER, err := ioutil.ReadFile("test-cert.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")

	cert, err := x509.ParseCertificate(certDER)
	test.AssertNotError(t, err, "Couldn't parse example cert DER")

	// Set the test clock's time to the time from the test certificate, plus an
	// hour to account for rounding.
	clk.Add(time.Hour - clk.Now().Sub(cert.NotBefore))
	now := clk.Now()
	yesterday := clk.Now().Add(-24 * time.Hour)
	twoDaysAgo := clk.Now().Add(-48 * time.Hour)
	tomorrow := clk.Now().Add(24 * time.Hour)

	// Count for a name that doesn't have any certs
	counts, err := sa.CountCertificatesByNames(ctx, []string{"example.com"}, yesterday, now)
	test.AssertNotError(t, err, "Error counting certs.")
	test.AssertEquals(t, len(counts), 1)
	test.AssertEquals(t, *counts[0].Name, "example.com")
	test.AssertEquals(t, *counts[0].Count, int64(0))

	// Add the test cert and query for its names.
	reg := satest.CreateWorkingRegistration(t, sa)
	issued := sa.clk.Now()
	_, err = sa.AddCertificate(ctx, certDER, reg.ID, nil, &issued)
	test.AssertNotError(t, err, "Couldn't add test-cert.der")

	// Time range including now should find the cert
	counts, err = sa.CountCertificatesByNames(ctx, []string{"example.com"}, yesterday, now)
	test.AssertNotError(t, err, "sa.CountCertificatesByName failed")
	test.AssertEquals(t, len(counts), 1)
	test.AssertEquals(t, *counts[0].Name, "example.com")
	test.AssertEquals(t, *counts[0].Count, int64(1))

	// Time range between two days ago and yesterday should not.
	counts, err = sa.CountCertificatesByNames(ctx, []string{"example.com"}, twoDaysAgo, yesterday)
	test.AssertNotError(t, err, "Error counting certs.")
	test.AssertEquals(t, len(counts), 1)
	test.AssertEquals(t, *counts[0].Name, "example.com")
	test.AssertEquals(t, *counts[0].Count, int64(0))

	// Time range between now and tomorrow also should not (time ranges are
	// inclusive at the tail end, but not the beginning end).
	counts, err = sa.CountCertificatesByNames(ctx, []string{"example.com"}, now, tomorrow)
	test.AssertNotError(t, err, "Error counting certs.")
	test.AssertEquals(t, len(counts), 1)
	test.AssertEquals(t, *counts[0].Name, "example.com")
	test.AssertEquals(t, *counts[0].Count, int64(0))

	// Add a second test cert (for example.co.bn) and query for multiple names.
	names := []string{"example.com", "foo.com", "example.co.bn"}

	// Override countCertificatesByName with an implementation of certCountFunc
	// that will block forever if it's called in serial, but will succeed if
	// called in parallel.
	var interlocker sync.WaitGroup
	interlocker.Add(len(names))
	sa.parallelismPerRPC = len(names)
	oldCertCountFunc := sa.countCertificatesByName
	sa.countCertificatesByName = func(sel dbSelector, domain string, earliest, latest time.Time) (int, error) {
		interlocker.Done()
		interlocker.Wait()
		return oldCertCountFunc(sel, domain, earliest, latest)
	}

	certDER2, err := ioutil.ReadFile("test-cert2.der")
	test.AssertNotError(t, err, "Couldn't read test-cert2.der")
	_, err = sa.AddCertificate(ctx, certDER2, reg.ID, nil, &issued)
	test.AssertNotError(t, err, "Couldn't add test-cert2.der")
	counts, err = sa.CountCertificatesByNames(ctx, names, yesterday, now.Add(10000*time.Hour))
	test.AssertNotError(t, err, "Error counting certs.")
	test.AssertEquals(t, len(counts), 3)

	expected := map[string]int{
		"example.co.bn": 1,
		"foo.com":       0,
		"example.com":   1,
	}
	for _, entry := range counts {
		domain := *entry.Name
		actualCount := *entry.Count
		expectedCount := int64(expected[domain])
		test.AssertEquals(t, actualCount, expectedCount)
	}
}

func TestCountRegistrationsByIP(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	contact := "mailto:foo@example.com"

	// Create one IPv4 registration
	_, err := sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(1), E: 1}},
		Contact:   &[]string{contact},
		InitialIP: net.ParseIP("43.34.43.34"),
	})
	// Create two IPv6 registrations, both within the same /48
	test.AssertNotError(t, err, "Couldn't insert registration")
	_, err = sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(2), E: 1}},
		Contact:   &[]string{contact},
		InitialIP: net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9652"),
	})
	test.AssertNotError(t, err, "Couldn't insert registration")
	_, err = sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(3), E: 1}},
		Contact:   &[]string{contact},
		InitialIP: net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9653"),
	})
	test.AssertNotError(t, err, "Couldn't insert registration")

	earliest := fc.Now().Add(-time.Hour * 24)
	latest := fc.Now()

	// There should be 0 registrations for an IPv4 address we didn't add
	// a registration for
	count, err := sa.CountRegistrationsByIP(ctx, net.ParseIP("1.1.1.1"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 0)
	// There should be 1 registration for the IPv4 address we did add
	// a registration for
	count, err = sa.CountRegistrationsByIP(ctx, net.ParseIP("43.34.43.34"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 1)
	// There should be 1 registration for the first IPv6 address we added
	// a registration for
	count, err = sa.CountRegistrationsByIP(ctx, net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9652"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 1)
	// There should be 1 registration for the second IPv6 address we added
	// a registration for as well
	count, err = sa.CountRegistrationsByIP(ctx, net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9653"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 1)
	// There should be 0 registrations for an IPv6 address in the same /48 as the
	// two IPv6 addresses with registrations
	count, err = sa.CountRegistrationsByIP(ctx, net.ParseIP("2001:cdba:1234:0000:0000:0000:0000:0000"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 0)
}

func TestCountRegistrationsByIPRange(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	contact := "mailto:foo@example.com"

	// Create one IPv4 registration
	_, err := sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(1), E: 1}},
		Contact:   &[]string{contact},
		InitialIP: net.ParseIP("43.34.43.34"),
	})
	// Create two IPv6 registrations, both within the same /48
	test.AssertNotError(t, err, "Couldn't insert registration")
	_, err = sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(2), E: 1}},
		Contact:   &[]string{contact},
		InitialIP: net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9652"),
	})
	test.AssertNotError(t, err, "Couldn't insert registration")
	_, err = sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(3), E: 1}},
		Contact:   &[]string{contact},
		InitialIP: net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9653"),
	})
	test.AssertNotError(t, err, "Couldn't insert registration")

	earliest := fc.Now().Add(-time.Hour * 24)
	latest := fc.Now()

	// There should be 0 registrations in the range for an IPv4 address we didn't
	// add a registration for
	count, err := sa.CountRegistrationsByIPRange(ctx, net.ParseIP("1.1.1.1"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 0)
	// There should be 1 registration in the range for the IPv4 address we did
	// add a registration for
	count, err = sa.CountRegistrationsByIPRange(ctx, net.ParseIP("43.34.43.34"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 1)
	// There should be 2 registrations in the range for the first IPv6 address we added
	// a registration for because it's in the same /48
	count, err = sa.CountRegistrationsByIPRange(ctx, net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9652"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 2)
	// There should be 2 registrations in the range for the second IPv6 address
	// we added a registration for as well, because it too is in the same /48
	count, err = sa.CountRegistrationsByIPRange(ctx, net.ParseIP("2001:cdba:1234:5678:9101:1121:3257:9653"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 2)
	// There should also be 2 registrations in the range for an arbitrary IPv6 address in
	// the same /48 as the registrations we added
	count, err = sa.CountRegistrationsByIPRange(ctx, net.ParseIP("2001:cdba:1234:0000:0000:0000:0000:0000"), earliest, latest)
	test.AssertNotError(t, err, "Failed to count registrations")
	test.AssertEquals(t, count, 2)
}

func TestFQDNSets(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	tx, err := sa.dbMap.Begin()
	test.AssertNotError(t, err, "Failed to open transaction")
	names := []string{"a.example.com", "B.example.com"}
	expires := fc.Now().Add(time.Hour * 2).UTC()
	issued := fc.Now()
	err = addFQDNSet(tx, names, "serial", issued, expires)
	test.AssertNotError(t, err, "Failed to add name set")
	test.AssertNotError(t, tx.Commit(), "Failed to commit transaction")

	// only one valid
	threeHours := time.Hour * 3
	count, err := sa.CountFQDNSets(ctx, threeHours, names)
	test.AssertNotError(t, err, "Failed to count name sets")
	test.AssertEquals(t, count, int64(1))

	// check hash isn't affected by changing name order/casing
	count, err = sa.CountFQDNSets(ctx, threeHours, []string{"b.example.com", "A.example.COM"})
	test.AssertNotError(t, err, "Failed to count name sets")
	test.AssertEquals(t, count, int64(1))

	// add another valid set
	tx, err = sa.dbMap.Begin()
	test.AssertNotError(t, err, "Failed to open transaction")
	err = addFQDNSet(tx, names, "anotherSerial", issued, expires)
	test.AssertNotError(t, err, "Failed to add name set")
	test.AssertNotError(t, tx.Commit(), "Failed to commit transaction")

	// only two valid
	count, err = sa.CountFQDNSets(ctx, threeHours, names)
	test.AssertNotError(t, err, "Failed to count name sets")
	test.AssertEquals(t, count, int64(2))

	// add an expired set
	tx, err = sa.dbMap.Begin()
	test.AssertNotError(t, err, "Failed to open transaction")
	err = addFQDNSet(
		tx,
		names,
		"yetAnotherSerial",
		issued.Add(-threeHours),
		expires.Add(-threeHours),
	)
	test.AssertNotError(t, err, "Failed to add name set")
	test.AssertNotError(t, tx.Commit(), "Failed to commit transaction")

	// only two valid
	count, err = sa.CountFQDNSets(ctx, threeHours, names)
	test.AssertNotError(t, err, "Failed to count name sets")
	test.AssertEquals(t, count, int64(2))
}

func TestFQDNSetsExists(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	names := []string{"a.example.com", "B.example.com"}
	exists, err := sa.FQDNSetExists(ctx, names)
	test.AssertNotError(t, err, "Failed to check FQDN set existence")
	test.Assert(t, !exists, "FQDN set shouldn't exist")

	tx, err := sa.dbMap.Begin()
	test.AssertNotError(t, err, "Failed to open transaction")
	expires := fc.Now().Add(time.Hour * 2).UTC()
	issued := fc.Now()
	err = addFQDNSet(tx, names, "serial", issued, expires)
	test.AssertNotError(t, err, "Failed to add name set")
	test.AssertNotError(t, tx.Commit(), "Failed to commit transaction")

	exists, err = sa.FQDNSetExists(ctx, names)
	test.AssertNotError(t, err, "Failed to check FQDN set existence")
	test.Assert(t, exists, "FQDN set does exist")
}

type execRecorder struct {
	query string
	args  []interface{}
}

func (e *execRecorder) Exec(query string, args ...interface{}) (sql.Result, error) {
	e.query = query
	e.args = args
	return nil, nil
}

func TestAddIssuedNames(t *testing.T) {
	serial := big.NewInt(1)
	expectedSerial := "000000000000000000000000000000000001"
	notBefore := time.Date(2018, 2, 14, 12, 0, 0, 0, time.UTC)
	placeholdersPerName := "(?, ?, ?, ?)"
	baseQuery := "INSERT INTO issuedNames (reversedName, serial, notBefore, renewal) VALUES"

	testCases := []struct {
		Name         string
		IssuedNames  []string
		SerialNumber *big.Int
		NotBefore    time.Time
		Renewal      bool
		ExpectedArgs []interface{}
	}{
		{
			Name:         "One domain, not a renewal",
			IssuedNames:  []string{"example.co.uk"},
			SerialNumber: serial,
			NotBefore:    notBefore,
			Renewal:      false,
			ExpectedArgs: []interface{}{
				"uk.co.example",
				expectedSerial,
				notBefore,
				false,
			},
		},
		{
			Name:         "Two domains, not a renewal",
			IssuedNames:  []string{"example.co.uk", "example.xyz"},
			SerialNumber: serial,
			NotBefore:    notBefore,
			Renewal:      false,
			ExpectedArgs: []interface{}{
				"uk.co.example",
				expectedSerial,
				notBefore,
				false,
				"xyz.example",
				expectedSerial,
				notBefore,
				false,
			},
		},
		{
			Name:         "One domain, renewal",
			IssuedNames:  []string{"example.co.uk"},
			SerialNumber: serial,
			NotBefore:    notBefore,
			Renewal:      true,
			ExpectedArgs: []interface{}{
				"uk.co.example",
				expectedSerial,
				notBefore,
				true,
			},
		},
		{
			Name:         "Two domains, renewal",
			IssuedNames:  []string{"example.co.uk", "example.xyz"},
			SerialNumber: serial,
			NotBefore:    notBefore,
			Renewal:      true,
			ExpectedArgs: []interface{}{
				"uk.co.example",
				expectedSerial,
				notBefore,
				true,
				"xyz.example",
				expectedSerial,
				notBefore,
				true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			var e execRecorder
			err := addIssuedNames(
				&e,
				&x509.Certificate{
					DNSNames:     tc.IssuedNames,
					SerialNumber: tc.SerialNumber,
					NotBefore:    tc.NotBefore,
				},
				tc.Renewal)
			test.AssertNotError(t, err, "addIssuedNames failed")
			expectedPlaceholders := placeholdersPerName
			for i := 0; i < len(tc.IssuedNames)-1; i++ {
				expectedPlaceholders = fmt.Sprintf("%s, %s", expectedPlaceholders, placeholdersPerName)
			}
			expectedQuery := fmt.Sprintf("%s %s;", baseQuery, expectedPlaceholders)
			test.AssertEquals(t, e.query, expectedQuery)
			if !reflect.DeepEqual(e.args, tc.ExpectedArgs) {
				t.Errorf("Wrong args: got\n%#v, expected\n%#v", e.args, tc.ExpectedArgs)
			}
		})
	}
}

func TestPreviousCertificateExists(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)

	// An example cert taken from EFF's website
	certDER, err := ioutil.ReadFile("www.eff.org.der")
	test.AssertNotError(t, err, "reading cert DER")

	issued := sa.clk.Now()
	_, err = sa.AddCertificate(ctx, certDER, reg.ID, nil, &issued)
	test.AssertNotError(t, err, "calling AddCertificate")

	cases := []struct {
		name     string
		domain   string
		regID    int64
		expected bool
	}{
		{"matches", "www.eff.org", reg.ID, true},
		{"wrongDomain", "wwoof.org", reg.ID, false},
		{"wrongAccount", "www.eff.org", 3333, false},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			exists, err := sa.PreviousCertificateExists(context.Background(),
				&sapb.PreviousCertificateExistsRequest{
					Domain: &testCase.domain,
					RegID:  &testCase.regID,
				})
			test.AssertNotError(t, err, "calling PreviousCertificateExists")
			if *exists.Exists != testCase.expected {
				t.Errorf("wanted %v got %v", testCase.expected, *exists.Exists)
			}
		})
	}
}

func TestDeactivateAuthorization(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	PA := core.Authorization{RegistrationID: reg.ID}

	PA, err := sa.NewPendingAuthorization(ctx, PA)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, PA.ID != "", "ID shouldn't be blank")

	dbPa, err := sa.GetAuthorization(ctx, PA.ID)
	test.AssertNotError(t, err, "Couldn't get pending authorization with ID "+PA.ID)
	test.AssertMarshaledEquals(t, PA, dbPa)

	expectedPa := core.Authorization{ID: PA.ID}
	test.AssertMarshaledEquals(t, dbPa.ID, expectedPa.ID)

	exp := time.Now().AddDate(0, 0, 1)
	identifier := identifier.ACMEIdentifier{Type: identifier.DNS, Value: "wut.com"}
	newPa := core.Authorization{
		ID:             PA.ID,
		Identifier:     identifier,
		RegistrationID: reg.ID,
		Status:         core.StatusPending,
		Expires:        &exp,
	}

	newPa.Status = core.StatusValid
	err = sa.FinalizeAuthorization(ctx, newPa)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+PA.ID)

	dbPa, err = sa.GetAuthorization(ctx, PA.ID)
	test.AssertNotError(t, err, "Couldn't get authorization with ID "+PA.ID)

	err = sa.DeactivateAuthorization(ctx, dbPa.ID)
	test.AssertNotError(t, err, "Couldn't deactivate valid authorization with ID "+PA.ID)

	dbPa, err = sa.GetAuthorization(ctx, PA.ID)
	test.AssertNotError(t, err, "Couldn't get authorization with ID "+PA.ID)
	test.AssertEquals(t, dbPa.Status, core.StatusDeactivated)

	PA.Status = core.StatusPending
	PA, err = sa.NewPendingAuthorization(ctx, PA)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, PA.ID != "", "ID shouldn't be blank")

	err = sa.DeactivateAuthorization(ctx, PA.ID)
	test.AssertNotError(t, err, "Couldn't deactivate pending authorization with ID "+PA.ID)

	dbPa, err = sa.GetAuthorization(ctx, PA.ID)
	test.AssertNotError(t, err, "Couldn't get authorization with ID "+PA.ID)
	test.AssertEquals(t, dbPa.Status, core.StatusDeactivated)

	pendingObj, err := sa.dbMap.Get(&pendingauthzModel{}, PA.ID)
	test.AssertNotError(t, err, "sa.dbMap.Get failed to get pending authz")
	test.Assert(t, pendingObj == nil, "Deactivated authorization still in pending table")
}

func TestDeactivateAuthorization2(t *testing.T) {
	if !strings.HasSuffix(os.Getenv("BOULDER_CONFIG_DIR"), "config-next") {
		return
	}

	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)

	// deactivate a pending authorization
	v2 := true
	ident := "aaa"
	pending := string(core.StatusPending)
	expires := fc.Now().Add(time.Hour).UTC().UnixNano()
	challType := string(core.ChallengeTypeDNS01)
	tokenA := "YXNk"
	tokenB := "Zmdo"
	ids, err := sa.NewAuthorizations2(context.Background(), &sapb.AddPendingAuthorizationsRequest{
		Authz: []*corepb.Authorization{
			&corepb.Authorization{
				V2:             &v2,
				Identifier:     &ident,
				RegistrationID: &reg.ID,
				Status:         &pending,
				Expires:        &expires,
				Challenges: []*corepb.Challenge{
					{
						Status: &pending,
						Type:   &challType,
						Token:  &tokenA,
					},
				},
			},
			&corepb.Authorization{
				V2:             &v2,
				Identifier:     &ident,
				RegistrationID: &reg.ID,
				Status:         &pending,
				Expires:        &expires,
				Challenges: []*corepb.Challenge{
					{
						Status: &pending,
						Type:   &challType,
						Token:  &tokenB,
					},
				},
			},
		},
	})
	test.AssertNotError(t, err, "sa.NewAuthorizations2 failed")
	test.AssertEquals(t, len(ids.Ids), 2)

	_, err = sa.DeactivateAuthorization2(context.Background(), &sapb.AuthorizationID2{Id: &ids.Ids[0]})
	test.AssertNotError(t, err, "sa.DeactivateAuthorization2 failed")

	// deactivate a valid authorization
	valid := string(core.StatusValid)
	err = sa.FinalizeAuthorization2(context.Background(), &sapb.FinalizeAuthorizationRequest{
		Id:                &ids.Ids[1],
		Status:            &valid,
		Attempted:         &challType,
		ValidationRecords: []*corepb.ValidationRecord{},
		Expires:           &expires,
	})
	test.AssertNotError(t, err, "sa.FinalizeAuthorization2 failed")
	_, err = sa.DeactivateAuthorization2(context.Background(), &sapb.AuthorizationID2{Id: &ids.Ids[1]})
	test.AssertNotError(t, err, "sa.DeactivateAuthorization2 failed")
}

func TestDeactivateAccount(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)

	err := sa.DeactivateRegistration(context.Background(), reg.ID)
	test.AssertNotError(t, err, "DeactivateRegistration failed")

	dbReg, err := sa.GetRegistration(context.Background(), reg.ID)
	test.AssertNotError(t, err, "GetRegistration failed")
	test.AssertEquals(t, dbReg.Status, core.StatusDeactivated)
}

func TestReverseName(t *testing.T) {
	testCases := []struct {
		inputDomain   string
		inputReversed string
	}{
		{"", ""},
		{"...", "..."},
		{"com", "com"},
		{"example.com", "com.example"},
		{"www.example.com", "com.example.www"},
		{"world.wide.web.example.com", "com.example.web.wide.world"},
	}

	for _, tc := range testCases {
		output := ReverseName(tc.inputDomain)
		test.AssertEquals(t, output, tc.inputReversed)
	}
}

type fqdnTestcase struct {
	Serial       string
	Names        []string
	ExpectedHash setHash
	Issued       time.Time
	Expires      time.Time
}

func setupFQDNSets(t *testing.T, db *gorp.DbMap, fc clock.FakeClock) map[string]fqdnTestcase {
	namesA := []string{"a.example.com", "B.example.com"}
	namesB := []string{"example.org"}
	namesC := []string{"letsencrypt.org"}
	expectedHashA := setHash{0x92, 0xc7, 0xf2, 0x47, 0xbd, 0x1e, 0xea, 0x8d, 0x52, 0x7f, 0xb0, 0x59, 0x19, 0xe9, 0xbe, 0x81, 0x78, 0x88, 0xe6, 0xf7, 0x55, 0xf0, 0x1c, 0xc9, 0x63, 0x15, 0x5f, 0x8e, 0x52, 0xae, 0x95, 0xc1}
	expectedHashB := setHash{0xbf, 0xab, 0xc3, 0x74, 0x32, 0x95, 0x8b, 0x6, 0x33, 0x60, 0xd3, 0xad, 0x64, 0x61, 0xc9, 0xc4, 0x73, 0x5a, 0xe7, 0xf8, 0xed, 0xd4, 0x65, 0x92, 0xa5, 0xe0, 0xf0, 0x14, 0x52, 0xb2, 0xe4, 0xb5}
	expectedHashC := setHash{0xf2, 0xbb, 0x7b, 0xab, 0x8, 0x2c, 0x18, 0xee, 0x8, 0x97, 0x17, 0xbe, 0x67, 0xd7, 0x12, 0x14, 0xaa, 0x4, 0xac, 0xe2, 0x29, 0x2a, 0x67, 0x2c, 0x37, 0x2c, 0xf3, 0x33, 0xe1, 0xb0, 0xd8, 0xe7}

	now := fc.Now()

	testcases := map[string]fqdnTestcase{
		// One test case with serial "a" issued now and expiring in two hours for
		// namesA
		"a": fqdnTestcase{
			Serial:       "a",
			Names:        namesA,
			ExpectedHash: expectedHashA,
			Issued:       now,
			Expires:      now.Add(time.Hour * 2).UTC(),
		},
		// One test case with serial "b", issued one hour from now and expiring in
		// two hours, also for namesA
		"b": fqdnTestcase{
			Serial:       "b",
			Names:        namesA,
			ExpectedHash: expectedHashA,
			Issued:       now.Add(time.Hour),
			Expires:      now.Add(time.Hour * 2).UTC(),
		},
		// One test case with serial "c", issued one hour from now and expiring in
		// two hours, for namesB
		"c": fqdnTestcase{
			Serial:       "c",
			Names:        namesB,
			ExpectedHash: expectedHashB,
			Issued:       now.Add(time.Hour),
			Expires:      now.Add(time.Hour * 2).UTC(),
		},
		// One test case with serial "d", issued five hours in the past and expiring
		// in two hours from now, with namesC
		"d": fqdnTestcase{
			Serial:       "d",
			Names:        namesC,
			ExpectedHash: expectedHashC,
			Issued:       now.Add(-5 * time.Hour),
			Expires:      now.Add(time.Hour * 2).UTC(),
		},
	}

	for _, tc := range testcases {
		tx, err := db.Begin()
		test.AssertNotError(t, err, "Failed to open transaction")
		err = addFQDNSet(tx, tc.Names, tc.Serial, tc.Issued, tc.Expires)
		test.AssertNotError(t, err, fmt.Sprintf("Failed to add fqdnSet for %#v", tc))
		test.AssertNotError(t, tx.Commit(), "Failed to commit transaction")
	}

	return testcases
}

func TestGetFQDNSetsBySerials(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	// Add the test fqdn sets
	testcases := setupFQDNSets(t, sa.dbMap, fc)

	// Asking for the fqdnSets for no serials should produce an error since this
	// is not expected in normal conditions
	fqdnSets, err := sa.getFQDNSetsBySerials(sa.dbMap, []string{})
	test.AssertError(t, err, "No error calling getFQDNSetsBySerials for empty serials")
	test.AssertEquals(t, len(fqdnSets), 0)

	// Asking for the fqdnSets for serials that don't exist should return nothing
	fqdnSets, err = sa.getFQDNSetsBySerials(sa.dbMap, []string{"this", "doesn't", "exist"})
	test.AssertNotError(t, err, "Error calling getFQDNSetsBySerials for non-existent serials")
	test.AssertEquals(t, len(fqdnSets), 0)

	// Asking for the fqdnSets for serial "a" should return the expectedHashA hash
	fqdnSets, err = sa.getFQDNSetsBySerials(sa.dbMap, []string{"a"})
	test.AssertNotError(t, err, "Error calling getFQDNSetsBySerials for serial \"a\"")
	test.AssertEquals(t, len(fqdnSets), 1)
	test.AssertEquals(t, string(fqdnSets[0]), string(testcases["a"].ExpectedHash))

	// Asking for the fqdnSets for serial "b" should return the expectedHashA hash
	// because cert "b" has namesA subjects
	fqdnSets, err = sa.getFQDNSetsBySerials(sa.dbMap, []string{"b"})
	test.AssertNotError(t, err, "Error calling getFQDNSetsBySerials for serial \"b\"")
	test.AssertEquals(t, len(fqdnSets), 1)
	test.AssertEquals(t, string(fqdnSets[0]), string(testcases["b"].ExpectedHash))

	// Asking for the fqdnSets for serial "d" should return the expectedHashC hash
	// because cert "d" has namesC subjects
	fqdnSets, err = sa.getFQDNSetsBySerials(sa.dbMap, []string{"d"})
	test.AssertNotError(t, err, "Error calling getFQDNSetsBySerials for serial \"d\"")
	test.AssertEquals(t, len(fqdnSets), 1)
	test.AssertEquals(t, string(fqdnSets[0]), string(testcases["d"].ExpectedHash))

	// Asking for the fqdnSets for serial "c" should return the expectedHashB hash
	// because cert "c" has namesB subjects
	fqdnSets, err = sa.getFQDNSetsBySerials(sa.dbMap, []string{"c"})
	test.AssertNotError(t, err, "Error calling getFQDNSetsBySerials for serial \"c\"")
	test.AssertEquals(t, len(fqdnSets), 1)
	test.AssertEquals(t, string(fqdnSets[0]), string(testcases["c"].ExpectedHash))

	// Asking for the fqdnSets for serial "a", "b", "c" and "made up" should return
	// the three expected hashes - two expectedHashA (for "a" and "b"), one
	// expectedHashB (for "c")
	expectedHashes := map[string]int{
		string(testcases["a"].ExpectedHash): 2,
		string(testcases["c"].ExpectedHash): 1,
	}
	fqdnSets, err = sa.getFQDNSetsBySerials(sa.dbMap, []string{"a", "b", "c", "made up"})
	test.AssertNotError(t, err, "Error calling getFQDNSetsBySerials for serial \"a\", \"b\", \"c\", \"made up\"")

	for _, setHash := range fqdnSets {
		setHashKey := string(setHash)
		if _, present := expectedHashes[setHashKey]; !present {
			t.Errorf("Unexpected setHash in results: %#v", setHash)
		}
		expectedHashes[setHashKey]--
		if expectedHashes[setHashKey] <= 0 {
			delete(expectedHashes, setHashKey)
		}
	}
	if len(expectedHashes) != 0 {
		t.Errorf("Some expected setHashes were not observed: %#v", expectedHashes)
	}
}

func TestGetNewIssuancesByFQDNSet(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	// Add the test fqdn sets
	testcases := setupFQDNSets(t, sa.dbMap, fc)

	// Use one hour ago as the earliest cut off
	earliest := fc.Now().Add(-time.Hour)

	// Calling getNewIssuancesByFQDNSet with an empty FQDNSet should error
	count, err := sa.getNewIssuancesByFQDNSet(sa.dbMap, nil, earliest)
	test.AssertError(t, err, "No error calling getNewIssuancesByFQDNSet for empty fqdn set")
	test.AssertEquals(t, count, -1)

	// Calling getNewIssuancesByFQDNSet with FQDNSet hashes that don't exist
	// should return 0
	count, err = sa.getNewIssuancesByFQDNSet(sa.dbMap, []setHash{setHash{0xC0, 0xFF, 0xEE}, setHash{0x13, 0x37}}, earliest)
	test.AssertNotError(t, err, "Error calling getNewIssuancesByFQDNSet for non-existent set hashes")
	test.AssertEquals(t, count, 0)

	// Calling getNewIssuancesByFQDNSet with the "a" expected hash should return
	// 1, since both testcase "b" was a renewal of testcase "a"
	count, err = sa.getNewIssuancesByFQDNSet(sa.dbMap, []setHash{testcases["a"].ExpectedHash}, earliest)
	test.AssertNotError(t, err, "Error calling getNewIssuancesByFQDNSet for testcase a")
	test.AssertEquals(t, count, 1)

	// Calling getNewIssuancesByFQDNSet with the "c" expected hash should return
	// 1, since there is only one issuance for this sethash
	count, err = sa.getNewIssuancesByFQDNSet(sa.dbMap, []setHash{testcases["c"].ExpectedHash}, earliest)
	test.AssertNotError(t, err, "Error calling getNewIssuancesByFQDNSet for testcase c")
	test.AssertEquals(t, count, 1)

	// Calling getNewIssuancesByFQDNSet with the "c" and "d" expected hashes should return
	// only 1, since there is only one issuance for the provided set hashes that
	// is within the earliest window. The issuance for "d" was too far in the past
	// to be counted
	count, err = sa.getNewIssuancesByFQDNSet(sa.dbMap, []setHash{testcases["c"].ExpectedHash, testcases["d"].ExpectedHash}, earliest)
	test.AssertNotError(t, err, "Error calling getNewIssuancesByFQDNSet for testcase c and d")
	test.AssertEquals(t, count, 1)

	// But by moving the earliest point behind the "d" issuance, we should now get a count of 2
	count, err = sa.getNewIssuancesByFQDNSet(sa.dbMap, []setHash{testcases["c"].ExpectedHash, testcases["d"].ExpectedHash}, earliest.Add(-6*time.Hour))
	test.AssertNotError(t, err, "Error calling getNewIssuancesByFQDNSet for testcase c and d with adjusted earliest")
	test.AssertEquals(t, count, 2)
}

func TestNewOrder(t *testing.T) {
	sa, _, cleanup := initSA(t)
	defer cleanup()

	// Create a test registration to reference
	reg, err := sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(1), E: 1}},
		InitialIP: net.ParseIP("42.42.42.42"),
	})
	test.AssertNotError(t, err, "Couldn't create test registration")

	i := int64(1)
	status := string(core.StatusPending)

	order, err := sa.NewOrder(context.Background(), &corepb.Order{
		RegistrationID: &reg.ID,
		Expires:        &i,
		Names:          []string{"example.com", "just.another.example.com"},
		Authorizations: []string{"a", "b", "c"},
		Status:         &status,
	})
	test.AssertNotError(t, err, "sa.NewOrder failed")
	test.AssertEquals(t, *order.Id, int64(1))

	var authzIDs []string
	_, err = sa.dbMap.Select(&authzIDs, "SELECT authzID FROM orderToAuthz WHERE orderID = ?;", *order.Id)
	test.AssertNotError(t, err, "Failed to count orderToAuthz entries")
	test.AssertEquals(t, len(authzIDs), 3)
	test.AssertDeepEquals(t, authzIDs, []string{"a", "b", "c"})

	names, err := sa.namesForOrder(context.Background(), *order.Id)
	test.AssertNotError(t, err, "namesForOrder errored")
	test.AssertEquals(t, len(names), 2)
	test.AssertDeepEquals(t, names, []string{"com.example", "com.example.another.just"})

	if !strings.HasSuffix(os.Getenv("BOULDER_CONFIG_DIR"), "config-next") {
		return
	}

	order, err = sa.NewOrder(context.Background(), &corepb.Order{
		RegistrationID:   &reg.ID,
		Expires:          &i,
		Names:            []string{"example.com", "just.another.example.com"},
		Authorizations:   []string{"a", "b", "c"},
		V2Authorizations: []int64{1},
		Status:           &status,
	})
	test.AssertNotError(t, err, "sa.NewOrder failed")
	test.AssertEquals(t, *order.Id, int64(2))

	authzIDs = []string{}
	_, err = sa.dbMap.Select(&authzIDs, "SELECT authzID FROM orderToAuthz WHERE orderID = ?;", *order.Id)
	test.AssertNotError(t, err, "Failed to count orderToAuthz entries")
	test.AssertEquals(t, len(authzIDs), 3)
	test.AssertDeepEquals(t, authzIDs, []string{"a", "b", "c"})
	var v2AuthzsIDs []string
	_, err = sa.dbMap.Select(&v2AuthzsIDs, "SELECT authzID FROM orderToAuthz2 WHERE orderID = ?;", *order.Id)
	test.AssertNotError(t, err, "Failed to count orderToAuthz entries")
	test.AssertEquals(t, len(v2AuthzsIDs), 1)
	test.AssertDeepEquals(t, v2AuthzsIDs, []string{"1"})

	names, err = sa.namesForOrder(context.Background(), *order.Id)
	test.AssertNotError(t, err, "namesForOrder errored")
	test.AssertEquals(t, len(names), 2)
	test.AssertDeepEquals(t, names, []string{"com.example", "com.example.another.just"})
}

func TestSetOrderProcessing(t *testing.T) {
	sa, fc, cleanup := initSA(t)
	defer cleanup()

	// Create a test registration to reference
	reg, err := sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(1), E: 1}},
		InitialIP: net.ParseIP("42.42.42.42"),
	})
	test.AssertNotError(t, err, "Couldn't create test registration")

	// Add one pending authz
	authzExpires := fc.Now().Add(time.Hour)
	newAuthz := core.Authorization{
		Identifier:     identifier.ACMEIdentifier{Type: identifier.DNS, Value: "example.com"},
		RegistrationID: reg.ID,
		Status:         core.StatusPending,
		Expires:        &authzExpires,
	}
	authz, err := sa.NewPendingAuthorization(ctx, newAuthz)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")

	// Update the pending authz to be valid
	authz.Status = core.StatusValid
	err = sa.FinalizeAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Couldn't finalize pending authz to valid")

	orderExpiry := sa.clk.Now().Add(365 * 24 * time.Hour).UnixNano()
	order := &corepb.Order{
		RegistrationID: &reg.ID,
		Expires:        &orderExpiry,
		Names:          []string{"example.com"},
		Authorizations: []string{authz.ID},
	}

	// Add a new order in pending status with no certificate serial
	order, err = sa.NewOrder(context.Background(), order)
	test.AssertNotError(t, err, "NewOrder failed")

	// Set the order to be processing
	err = sa.SetOrderProcessing(context.Background(), order)
	test.AssertNotError(t, err, "SetOrderProcessing failed")

	// Read the order by ID from the DB to check the status was correctly updated
	// to processing
	updatedOrder, err := sa.GetOrder(
		context.Background(),
		&sapb.OrderRequest{Id: order.Id})
	test.AssertNotError(t, err, "GetOrder failed")
	test.AssertEquals(t, *updatedOrder.Status, string(core.StatusProcessing))
	test.AssertEquals(t, *updatedOrder.BeganProcessing, true)
}

func TestFinalizeOrder(t *testing.T) {
	sa, fc, cleanup := initSA(t)
	defer cleanup()

	// Create a test registration to reference
	reg, err := sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(1), E: 1}},
		InitialIP: net.ParseIP("42.42.42.42"),
	})
	test.AssertNotError(t, err, "Couldn't create test registration")

	// Add one pending authz
	authzExpires := fc.Now().Add(time.Hour)
	newAuthz := core.Authorization{
		Identifier:     identifier.ACMEIdentifier{Type: identifier.DNS, Value: "example.com"},
		RegistrationID: reg.ID,
		Status:         core.StatusPending,
		Expires:        &authzExpires,
	}
	authz, err := sa.NewPendingAuthorization(ctx, newAuthz)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")

	// Set the authz to valid
	authz.Status = core.StatusValid
	err = sa.FinalizeAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization")

	orderExpiry := sa.clk.Now().Add(365 * 24 * time.Hour).UnixNano()
	order := &corepb.Order{
		RegistrationID: &reg.ID,
		Expires:        &orderExpiry,
		Names:          []string{"example.com"},
		Authorizations: []string{authz.ID},
	}

	// Add a new order with an empty certificate serial
	order, err = sa.NewOrder(context.Background(), order)
	test.AssertNotError(t, err, "NewOrder failed")

	// Set the order to processing so it can be finalized
	err = sa.SetOrderProcessing(ctx, order)
	test.AssertNotError(t, err, "SetOrderProcessing failed")

	// Finalize the order with a certificate serial
	serial := "eat.serial.for.breakfast"
	order.CertificateSerial = &serial
	err = sa.FinalizeOrder(context.Background(), order)
	test.AssertNotError(t, err, "FinalizeOrder failed")

	// Read the order by ID from the DB to check the certificate serial and status
	// was correctly updated
	updatedOrder, err := sa.GetOrder(
		context.Background(),
		&sapb.OrderRequest{Id: order.Id})
	test.AssertNotError(t, err, "GetOrder failed")
	test.AssertEquals(t, *updatedOrder.CertificateSerial, serial)
	test.AssertEquals(t, *updatedOrder.Status, string(core.StatusValid))
}

func TestOrder(t *testing.T) {
	sa, fc, cleanup := initSA(t)
	defer cleanup()

	// Create a test registration to reference
	reg, err := sa.NewRegistration(ctx, core.Registration{
		Key:       &jose.JSONWebKey{Key: &rsa.PublicKey{N: big.NewInt(1), E: 1}},
		InitialIP: net.ParseIP("42.42.42.42"),
	})
	test.AssertNotError(t, err, "Couldn't create test registration")

	authzExpires := fc.Now().Add(time.Hour)
	newAuthz := core.Authorization{
		Identifier:     identifier.ACMEIdentifier{Type: identifier.DNS, Value: "example.com"},
		RegistrationID: reg.ID,
		Status:         core.StatusPending,
		Expires:        &authzExpires,
	}
	authz, err := sa.NewPendingAuthorization(ctx, newAuthz)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")

	// Set the order to expire in two hours
	expires := fc.Now().Add(2 * time.Hour).UnixNano()
	empty := ""

	inputOrder := &corepb.Order{
		RegistrationID: &reg.ID,
		Expires:        &expires,
		Names:          []string{"example.com"},
		Authorizations: []string{authz.ID},
	}

	// Create the order
	order, err := sa.NewOrder(context.Background(), inputOrder)
	test.AssertNotError(t, err, "sa.NewOrder failed")

	pendingStatus := string(core.StatusPending)
	falseBool := false
	one := int64(1)
	nowTS := sa.clk.Now().UnixNano()
	// The Order from GetOrder should match the following expected order
	expectedOrder := &corepb.Order{
		// The registration ID, authorizations, expiry, and names should match the
		// input to NewOrder
		RegistrationID: inputOrder.RegistrationID,
		Authorizations: inputOrder.Authorizations,
		Names:          inputOrder.Names,
		Expires:        inputOrder.Expires,
		// The ID should have been set to 1 by the SA
		Id: &one,
		// The status should be pending
		Status: &pendingStatus,
		// The serial should be empty since this is a pending order
		CertificateSerial: &empty,
		// We should not be processing it
		BeganProcessing: &falseBool,
		// The created timestamp should have been set to the current time
		Created: &nowTS,
	}

	// Fetch the order by its ID and make sure it matches the expected
	storedOrder, err := sa.GetOrder(context.Background(), &sapb.OrderRequest{Id: order.Id})
	test.AssertNotError(t, err, "sa.GetOrder failed")
	test.AssertDeepEquals(t, storedOrder, expectedOrder)
}

func TestGetValidOrderAuthorizations(t *testing.T) {
	sa, _, cleanup := initSA(t)
	defer cleanup()

	// Create a throw away registration
	reg := satest.CreateWorkingRegistration(t, sa)

	// Create and finalize an authz for the throw-away reg and "example.com"
	authz := CreateDomainAuthWithRegID(t, "example.com", sa, reg.ID)
	exp := sa.clk.Now().Add(time.Hour * 24 * 7)
	authz.Expires = &exp
	authz.Status = "valid"
	err := sa.FinalizeAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Couldn't create final authz with ID "+authz.ID)

	// Now create a new order that references the above authorization
	i := time.Now().Truncate(time.Second).UnixNano()
	status := string(core.StatusPending)
	order := &corepb.Order{
		RegistrationID: &reg.ID,
		Expires:        &i,
		Names:          []string{"example.com"},
		Authorizations: []string{authz.ID},
		Status:         &status,
	}
	order, err = sa.NewOrder(context.Background(), order)
	test.AssertNotError(t, err, "AddOrder failed")

	// Now fetch the order authorizations for the order we added for the
	// throw-away reg
	authzMap, err := sa.GetValidOrderAuthorizations(
		context.Background(),
		&sapb.GetValidOrderAuthorizationsRequest{
			Id:     order.Id,
			AcctID: &reg.ID,
		})
	// It should not fail and one valid authorization for the example.com domain
	// should be present with ID and status equal to the authz we created earlier.
	test.AssertNotError(t, err, "GetValidOrderAuthorizations failed")
	test.AssertNotNil(t, authzMap, "GetValidOrderAuthorizations result was nil")
	test.AssertEquals(t, len(authzMap), 1)
	test.AssertNotNil(t, authzMap["example.com"], "Authz for example.com was nil")
	test.AssertEquals(t, authzMap["example.com"].ID, authz.ID)
	test.AssertEquals(t, string(authzMap["example.com"].Status), "valid")

	// Getting the order authorizations for an order that doesn't exist should return nothing
	missingID := int64(0xC0FFEEEEEEE)
	authzMap, err = sa.GetValidOrderAuthorizations(
		context.Background(),
		&sapb.GetValidOrderAuthorizationsRequest{
			Id:     &missingID,
			AcctID: &reg.ID,
		})
	test.AssertNotError(t, err, "GetValidOrderAuthorizations for non-existent order errored")
	test.AssertEquals(t, len(authzMap), 0)

	// Getting the order authorizations for an order that does exist, but for the
	// wrong acct ID should return nothing
	wrongAcctID := int64(0xDEADDA7ABA5E)
	authzMap, err = sa.GetValidOrderAuthorizations(
		context.Background(),
		&sapb.GetValidOrderAuthorizationsRequest{
			Id:     order.Id,
			AcctID: &wrongAcctID,
		})
	test.AssertNotError(t, err, "GetValidOrderAuthorizations for existent order, wrong acctID errored")
	test.AssertEquals(t, len(authzMap), 0)
}

// TestGetAuthorizationNoRows ensures that the GetAuthorization function returns
// the correct error when there are no results for the provided ID.
func TestGetAuthorizationNoRows(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	// An empty authz ID should result in `sql.ErrNoRows`
	_, err := sa.GetAuthorization(ctx, "")
	test.AssertError(t, err, "Didn't get an error looking up empty authz ID")
	test.Assert(t, berrors.Is(err, berrors.NotFound), "GetAuthorization did not return a berrors.NotFound error")
}

func TestGetAuthorizations(t *testing.T) {
	sa, fc, cleanup := initSA(t)
	defer cleanup()

	reg := satest.CreateWorkingRegistration(t, sa)
	exp := fc.Now().AddDate(0, 0, 10)

	identA := "aaa"
	identB := "bbb"
	identC := "ccc"
	identD := "ddd"
	idents := []string{identA, identB, identC}

	// Create an authorization template for a pending authorization with a dummy identifier
	pa := core.Authorization{
		RegistrationID: reg.ID,
		Identifier:     identifier.ACMEIdentifier{Type: identifier.DNS, Value: identA},
		Status:         core.StatusPending,
		Expires:        &exp,
	}

	// Add the template to create pending authorization A
	paA, err := sa.NewPendingAuthorization(ctx, pa)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, paA.ID != "", "ID shouldn't be blank")

	// Twiddle the template to have a different identifier
	pa.Identifier.Value = identB
	// Add the template to create pending authorization B
	paB, err := sa.NewPendingAuthorization(ctx, pa)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, paB.ID != "", "ID shouldn't be blank")

	// Set pending authorization A's status to valid, and then finalize it
	paB.Status = core.StatusValid
	err = sa.FinalizeAuthorization(ctx, paB)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+paB.ID)

	// Adjust the template to have an expiry in 1 hour from now.
	nearbyExpires := fc.Now().Add(time.Hour)
	pa.Expires = &nearbyExpires
	pa.Identifier.Value = identC
	// Add the template to create pending authorization C
	paC, err := sa.NewPendingAuthorization(ctx, pa)
	// There should be no error
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	test.Assert(t, paC.ID != "", "ID shouldn't be blank")

	// Don't require V2 authorizations because the above pending authorizations
	// aren't associated with orders, and therefore are seen as legacy V1
	// authorizations.
	requireV2Authzs := false

	// Set an expiry cut off of 1 day in the future similar to `RA.NewOrder`. This
	// should exclude pending authorization C based on its nearbyExpires expiry
	// value.
	expiryCutoff := fc.Now().AddDate(0, 0, 1).UnixNano()
	// Get authorizations for the names used above.
	authz, err := sa.GetAuthorizations(context.Background(), &sapb.GetAuthorizationsRequest{
		RegistrationID:  &reg.ID,
		Domains:         idents,
		Now:             &expiryCutoff,
		RequireV2Authzs: &requireV2Authzs,
	})
	// It should not fail
	test.AssertNotError(t, err, "sa.GetAuthorizations failed")
	// We should get back two authorizations since one of the three authorizations
	// created above expires too soon.
	test.AssertEquals(t, len(authz.Authz), 2)

	// Get authorizations for the names used above, and one name that doesn't exist
	authz, err = sa.GetAuthorizations(context.Background(), &sapb.GetAuthorizationsRequest{
		RegistrationID:  &reg.ID,
		Domains:         append(idents, identD),
		Now:             &expiryCutoff,
		RequireV2Authzs: &requireV2Authzs,
	})
	// It should not fail
	test.AssertNotError(t, err, "sa.GetAuthorizations failed")
	// It should still return only two authorizations
	test.AssertEquals(t, len(authz.Authz), 2)

	// Get authorizations for the names used above, but this time enforce that no
	// V2 authorizations are returned.
	requireV2Authzs = true
	authz, err = sa.GetAuthorizations(context.Background(), &sapb.GetAuthorizationsRequest{
		RegistrationID:  &reg.ID,
		Domains:         idents,
		Now:             &expiryCutoff,
		RequireV2Authzs: &requireV2Authzs,
	})
	// It should not fail
	test.AssertNotError(t, err, "sa.GetAuthorizations failed")
	// It should return no authorizations
	test.AssertEquals(t, len(authz.Authz), 0)

	// Create a new pending order that references one of the pending authorizations
	orderExpiry := exp.Unix()
	_, err = sa.NewOrder(ctx, &corepb.Order{
		RegistrationID: &reg.ID,
		Expires:        &orderExpiry,
		Names:          []string{identA},
		Authorizations: []string{paA.ID},
	})
	// It should not fail
	test.AssertNotError(t, err, "Couldn't create new pending order")

	// Calling get authorizations for the names used above with requireV2Authzs true should now find an authz
	requireV2Authzs = true
	authz, err = sa.GetAuthorizations(context.Background(), &sapb.GetAuthorizationsRequest{
		RegistrationID:  &reg.ID,
		Domains:         idents,
		Now:             &expiryCutoff,
		RequireV2Authzs: &requireV2Authzs,
	})
	// It should not fail
	test.AssertNotError(t, err, "sa.GetAuthorizations failed")
	// It should find the one authz we associated with an order above
	test.AssertEquals(t, len(authz.Authz), 1)
	test.AssertEquals(t, *authz.Authz[0].Authz.Id, paA.ID)
}

// TODO: needs to test also getting old style authorizations
func TestGetAuthorizations2(t *testing.T) {
	if !strings.HasSuffix(os.Getenv("BOULDER_CONFIG_DIR"), "config-next") {
		return
	}

	sa, fc, cleanup := initSA(t)
	defer cleanup()

	reg := satest.CreateWorkingRegistration(t, sa)
	exp := fc.Now().AddDate(0, 0, 10).UTC()

	identA := "aaa"
	identB := "bbb"
	identC := "ccc"
	identD := "ddd"
	idents := []string{identA, identB, identC}

	// Create an authorization template for a pending authorization with a dummy identifier
	pa := core.Authorization{
		RegistrationID: reg.ID,
		Identifier:     identifier.ACMEIdentifier{Type: identifier.DNS, Value: identA},
		Status:         core.StatusPending,
		Expires:        &exp,
		Challenges: []core.Challenge{
			{
				Token:  "YXNk",
				Type:   core.ChallengeTypeDNS01,
				Status: core.StatusPending,
			},
		},
	}
	v2 := true

	authzPBA, err := bgrpc.AuthzToPB(pa)
	test.AssertNotError(t, err, "bgrpc.AuthzToPB failed")
	authzPBA.V2 = &v2
	pa.Identifier.Value = identB
	pa.Challenges[0].Token = "Zmdo"
	authzPBB, err := bgrpc.AuthzToPB(pa)
	test.AssertNotError(t, err, "bgrpc.AuthzToPB failed")
	authzPBB.V2 = &v2
	nearbyExpires := fc.Now().UTC().Add(time.Hour)
	pa.Expires = &nearbyExpires
	pa.Identifier.Value = identC
	pa.Challenges[0].Token = "enhj"
	authzPBC, err := bgrpc.AuthzToPB(pa)
	test.AssertNotError(t, err, "bgrpc.AuthzToPB failed")
	authzPBC.V2 = &v2

	// Create pending authorizations
	ids, err := sa.NewAuthorizations2(context.Background(), &sapb.AddPendingAuthorizationsRequest{
		Authz: []*corepb.Authorization{authzPBA, authzPBB, authzPBC},
	})
	test.AssertNotError(t, err, "sa.NewAuthorizations2 failed")
	test.AssertEquals(t, len(ids.Ids), 3)

	// Set pending authorization A's status to valid
	valid := string(core.StatusValid)
	expires := exp.UnixNano()
	attempted := string(core.ChallengeTypeDNS01)
	err = sa.FinalizeAuthorization2(ctx, &sapb.FinalizeAuthorizationRequest{
		Id:                &ids.Ids[0],
		Status:            &valid,
		Expires:           &expires,
		ValidationRecords: []*corepb.ValidationRecord{},
		Attempted:         &attempted,
	})
	test.AssertNotError(t, err, fmt.Sprintf("Couldn't finalize pending authorization with ID %d", ids.Ids[0]))

	// Associate authorizations with an order so that GetAuthorizations2 thinks
	// they are WFE2 authorizations.
	err = sa.dbMap.Insert(&orderToAuthz2Model{
		OrderID: 1,
		AuthzID: ids.Ids[0],
	})
	test.AssertNotError(t, err, "sa.dbMap.Insert failed")
	err = sa.dbMap.Insert(&orderToAuthz2Model{
		OrderID: 1,
		AuthzID: ids.Ids[1],
	})
	test.AssertNotError(t, err, "sa.dbMap.Insert failed")
	err = sa.dbMap.Insert(&orderToAuthz2Model{
		OrderID: 1,
		AuthzID: ids.Ids[2],
	})
	test.AssertNotError(t, err, "sa.dbMap.Insert failed")

	// Set an expiry cut off of 1 day in the future similar to `RA.NewOrder`. This
	// should exclude pending authorization C based on its nearbyExpires expiry
	// value.
	expiryCutoff := fc.Now().AddDate(0, 0, 1).UnixNano()
	// Get authorizations for the names used above.
	authz, err := sa.GetAuthorizations2(context.Background(), &sapb.GetAuthorizationsRequest{
		RegistrationID: &reg.ID,
		Domains:        idents,
		Now:            &expiryCutoff,
	})
	// It should not fail
	test.AssertNotError(t, err, "sa.GetAuthorizations2 failed")
	// We should get back two authorizations since one of the three authorizations
	// created above expires too soon.
	test.AssertEquals(t, len(authz.Authz), 2)

	// Get authorizations for the names used above, and one name that doesn't exist
	authz, err = sa.GetAuthorizations2(context.Background(), &sapb.GetAuthorizationsRequest{
		RegistrationID: &reg.ID,
		Domains:        append(idents, identD),
		Now:            &expiryCutoff,
	})
	// It should not fail
	test.AssertNotError(t, err, "sa.GetAuthorizations2 failed")
	// It should still return only two authorizations
	test.AssertEquals(t, len(authz.Authz), 2)
}

func TestAddPendingAuthorizations(t *testing.T) {
	sa, fc, cleanup := initSA(t)
	defer cleanup()

	reg := satest.CreateWorkingRegistration(t, sa)
	expires := fc.Now().Add(time.Hour).UnixNano()
	identA := `a`
	identB := `a`
	status := string(core.StatusPending)
	empty := ""
	authz := []*corepb.Authorization{
		&corepb.Authorization{
			Id:             &empty,
			Identifier:     &identA,
			RegistrationID: &reg.ID,
			Status:         &status,
			Expires:        &expires,
		},
		&corepb.Authorization{
			Id:             &empty,
			Identifier:     &identB,
			RegistrationID: &reg.ID,
			Status:         &status,
			Expires:        &expires,
		},
	}

	ids, err := sa.AddPendingAuthorizations(context.Background(), &sapb.AddPendingAuthorizationsRequest{Authz: authz})
	test.AssertNotError(t, err, "sa.AddPendingAuthorizations failed")
	test.AssertEquals(t, len(ids.Ids), 2)

	for _, id := range ids.Ids {
		_, err := sa.GetAuthorization(context.Background(), id)
		test.AssertNotError(t, err, "sa.GetAuthorization failed")
	}
}

func TestCountOrders(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	now := sa.clk.Now()
	expires := now.Add(24 * time.Hour)

	earliest := now.Add(-time.Hour)
	latest := now.Add(time.Second)

	// Counting new orders for a reg ID that doesn't exist should return 0
	count, err := sa.CountOrders(ctx, 12345, earliest, latest)
	test.AssertNotError(t, err, "Couldn't count new orders for fake reg ID")
	test.AssertEquals(t, count, 0)

	// Add a pending authorization
	authz, err := sa.NewPendingAuthorization(ctx, core.Authorization{RegistrationID: reg.ID, Identifier: identifier.DNSIdentifier("example.com"), Status: core.StatusPending, Expires: &expires})
	test.AssertNotError(t, err, "Couldn't create new pending authorization")

	// Add one pending order
	expiresNano := expires.UnixNano()
	order, err := sa.NewOrder(ctx, &corepb.Order{
		RegistrationID: &reg.ID,
		Expires:        &expiresNano,
		Names:          []string{"example.com"},
		Authorizations: []string{authz.ID},
	})
	test.AssertNotError(t, err, "Couldn't create new pending order")

	// Counting new orders for the reg ID should now yield 1
	count, err = sa.CountOrders(ctx, reg.ID, earliest, latest)
	test.AssertNotError(t, err, "Couldn't count new orders for reg ID")
	test.AssertEquals(t, count, 1)

	// Moving the count window to after the order was created should return the
	// count to 0
	earliest = time.Unix(0, *order.Created).Add(time.Minute)
	latest = earliest.Add(time.Hour)
	count, err = sa.CountOrders(ctx, reg.ID, earliest, latest)
	test.AssertNotError(t, err, "Couldn't count new orders for reg ID")
	test.AssertEquals(t, count, 0)
}

func TestFasterGetOrderForNames(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	domain := "example.com"
	expires := fc.Now().Add(time.Hour)

	reg, err := sa.NewRegistration(ctx, core.Registration{
		Key:       satest.GoodJWK(),
		InitialIP: net.ParseIP("42.42.42.42"),
	})
	test.AssertNotError(t, err, "Couldn't create test registration")

	authz, err := sa.NewPendingAuthorization(ctx, core.Authorization{
		Identifier:     identifier.DNSIdentifier(domain),
		RegistrationID: reg.ID,
		Status:         core.StatusPending,
		Expires:        &expires,
	})
	test.AssertNotError(t, err, "creating authorization")

	expiresNano := expires.UnixNano()
	_, err = sa.NewOrder(ctx, &corepb.Order{
		RegistrationID: &reg.ID,
		Expires:        &expiresNano,
		Authorizations: []string{authz.ID},
		Names:          []string{domain},
	})
	test.AssertNotError(t, err, "sa.NewOrder failed")

	_, err = sa.NewOrder(ctx, &corepb.Order{
		RegistrationID: &reg.ID,
		Expires:        &expiresNano,
		Authorizations: []string{authz.ID},
		Names:          []string{domain},
	})
	test.AssertNotError(t, err, "sa.NewOrder failed")

	_, err = sa.GetOrderForNames(ctx, &sapb.GetOrderForNamesRequest{
		AcctID: &reg.ID,
		Names:  []string{domain},
	})
	test.AssertNotError(t, err, "sa.GetOrderForNames failed")
}

func TestGetOrderForNames(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	// Give the order we create a short lifetime
	orderLifetime := time.Hour
	expires := fc.Now().Add(orderLifetime).UnixNano()

	// Create two test registrations to associate with orders
	regA, err := sa.NewRegistration(ctx, core.Registration{
		Key:       satest.GoodJWK(),
		InitialIP: net.ParseIP("42.42.42.42"),
	})
	test.AssertNotError(t, err, "Couldn't create test registration")

	// Add one pending authz for the first name for regA
	authzExpires := fc.Now().Add(time.Hour)
	newAuthzA := core.Authorization{
		Identifier:     identifier.ACMEIdentifier{Type: identifier.DNS, Value: "example.com"},
		RegistrationID: regA.ID,
		Status:         core.StatusPending,
		Expires:        &authzExpires,
	}
	pendingAuthzA, err := sa.NewPendingAuthorization(ctx, newAuthzA)
	test.AssertNotError(t, err, "Couldn't create new pending authorization for regA")

	// Add one pending authz for the second name for regA
	newAuthzB := core.Authorization{
		Identifier:     identifier.ACMEIdentifier{Type: identifier.DNS, Value: "just.another.example.com"},
		RegistrationID: regA.ID,
		Status:         core.StatusPending,
		Expires:        &authzExpires,
	}
	pendingAuthzB, err := sa.NewPendingAuthorization(ctx, newAuthzB)
	test.AssertNotError(t, err, "Couldn't create new pending authorization for regA")

	ctx := context.Background()
	names := []string{"example.com", "just.another.example.com"}

	// Call GetOrderForNames for a set of names we haven't created an order for
	// yet
	result, err := sa.GetOrderForNames(ctx, &sapb.GetOrderForNamesRequest{
		AcctID: &regA.ID,
		Names:  names,
	})
	// We expect the result to return an error
	test.AssertError(t, err, "sa.GetOrderForNames did not return an error for an empty result")
	// The error should be a notfound error
	test.AssertEquals(t, berrors.Is(err, berrors.NotFound), true)
	// The result should be nil
	test.Assert(t, result == nil, "sa.GetOrderForNames for non-existent order returned non-nil result")

	// Add a new order for a set of names
	order, err := sa.NewOrder(ctx, &corepb.Order{
		RegistrationID: &regA.ID,
		Expires:        &expires,
		Authorizations: []string{pendingAuthzA.ID, pendingAuthzB.ID},
		Names:          names,
	})
	// It shouldn't error
	test.AssertNotError(t, err, "sa.NewOrder failed")
	// The order ID shouldn't be nil
	test.AssertNotNil(t, *order.Id, "NewOrder returned with a nil Id")

	// Call GetOrderForNames with the same account ID and set of names as the
	// above NewOrder call
	result, err = sa.GetOrderForNames(ctx, &sapb.GetOrderForNamesRequest{
		AcctID: &regA.ID,
		Names:  names,
	})
	// It shouldn't error
	test.AssertNotError(t, err, "sa.GetOrderForNames failed")
	// The order returned should have the same ID as the order we created above
	test.AssertNotNil(t, result, "Returned order was nil")
	test.AssertEquals(t, *result.Id, *order.Id)

	// Call GetOrderForNames with a different account ID from the NewOrder call
	regB := int64(1337)
	result, err = sa.GetOrderForNames(ctx, &sapb.GetOrderForNamesRequest{
		AcctID: &regB,
		Names:  names,
	})
	// It should error
	test.AssertError(t, err, "sa.GetOrderForNames did not return an error for an empty result")
	// The error should be a notfound error
	test.AssertEquals(t, berrors.Is(err, berrors.NotFound), true)
	// The result should be nil
	test.Assert(t, result == nil, "sa.GetOrderForNames for diff AcctID returned non-nil result")

	// Advance the clock beyond the initial order's lifetime
	fc.Add(2 * orderLifetime)

	// Call GetOrderForNames again with the same account ID and set of names as
	// the initial NewOrder call
	result, err = sa.GetOrderForNames(ctx, &sapb.GetOrderForNamesRequest{
		AcctID: &regA.ID,
		Names:  names,
	})
	// It should error since there is no result
	test.AssertError(t, err, "sa.GetOrderForNames did not return an error for an empty result")
	// The error should be a notfound error
	test.AssertEquals(t, berrors.Is(err, berrors.NotFound), true)
	// The result should be nil because the initial order expired & we don't want
	// to return expired orders
	test.Assert(t, result == nil, "sa.GetOrderForNames returned non-nil result for expired order case")

	// Create two valid authorizations (by first creating pending authorizations)
	authzExpires = fc.Now().Add(time.Hour)
	validAuthzA, err := sa.NewPendingAuthorization(ctx, core.Authorization{
		Identifier:     identifier.ACMEIdentifier{Type: identifier.DNS, Value: "zombo.com"},
		RegistrationID: regA.ID,
		Status:         core.StatusPending,
		Expires:        &authzExpires,
	})
	test.AssertNotError(t, err, "unexpected error creating pending authorization")
	validAuthzB, err := sa.NewPendingAuthorization(ctx, core.Authorization{
		Identifier:     identifier.ACMEIdentifier{Type: identifier.DNS, Value: "welcome.to.zombo.com"},
		RegistrationID: regA.ID,
		Status:         core.StatusPending,
		Expires:        &authzExpires,
	})
	test.AssertNotError(t, err, "unexpected error creating pending authorization")
	// Update both pending authz to be valid
	validAuthzA.Status = core.StatusValid
	err = sa.FinalizeAuthorization(ctx, validAuthzA)
	test.AssertNotError(t, err, "unexpected error finalizing pending authorization")
	validAuthzB.Status = core.StatusValid
	err = sa.FinalizeAuthorization(ctx, validAuthzB)
	test.AssertNotError(t, err, "unexpected error finalizing pending authorization")

	// Add a fresh order that uses the authorizations created above
	expires = fc.Now().Add(orderLifetime).UnixNano()
	names = []string{"zombo.com", "welcome.to.zombo.com"}
	order, err = sa.NewOrder(ctx, &corepb.Order{
		RegistrationID: &regA.ID,
		Expires:        &expires,
		Authorizations: []string{validAuthzA.ID, validAuthzB.ID},
		Names:          names,
	})
	// It shouldn't error
	test.AssertNotError(t, err, "sa.NewOrder failed")
	// The order ID shouldn't be nil
	test.AssertNotNil(t, *order.Id, "NewOrder returned with a nil Id")

	// Call GetOrderForNames with the same account ID and set of names as
	// the earlier NewOrder call
	result, err = sa.GetOrderForNames(ctx, &sapb.GetOrderForNamesRequest{
		AcctID: &regA.ID,
		Names:  names,
	})
	// It should not error since a ready order can be reused.
	test.AssertNotError(t, err, "sa.GetOrderForNames returned an unexpected error for ready order reuse")
	// The order returned should have the same ID as the order we created above
	test.AssertEquals(t, result != nil, true)
	test.AssertEquals(t, *result.Id, *order.Id)

	// Set the order processing so it can be finalized
	err = sa.SetOrderProcessing(ctx, order)
	test.AssertNotError(t, err, "sa.SetOrderProcessing failed")

	// Finalize the order
	serial := "cinnamon toast crunch"
	order.CertificateSerial = &serial
	err = sa.FinalizeOrder(ctx, order)
	test.AssertNotError(t, err, "sa.FinalizeOrder failed")

	// Call GetOrderForNames with the same account ID and set of names as
	// the earlier NewOrder call
	result, err = sa.GetOrderForNames(ctx, &sapb.GetOrderForNamesRequest{
		AcctID: &regA.ID,
		Names:  names,
	})
	// It should error since a valid order should not be reused.
	test.AssertError(t, err, "sa.GetOrderForNames did not return an error for an empty result")
	// The error should be a notfound error
	test.AssertEquals(t, berrors.Is(err, berrors.NotFound), true)
	// The result should be nil because the one matching order has been finalized
	// already
	test.Assert(t, result == nil, "sa.GetOrderForNames returned non-nil result for finalized order case")
}

func TestStatusForOrder(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	ctx := context.Background()
	expires := fc.Now().Add(time.Hour)
	expiresNano := expires.UnixNano()
	alreadyExpired := expires.Add(-2 * time.Hour)

	// Create a registration to work with
	reg := satest.CreateWorkingRegistration(t, sa)

	// Create a pending authz
	newAuthz := core.Authorization{
		RegistrationID: reg.ID,
		Expires:        &expires,
		Status:         core.StatusPending,
		Identifier:     identifier.ACMEIdentifier{Type: identifier.DNS, Value: "pending.your.order.is.up"},
	}
	pendingAuthz, err := sa.NewPendingAuthorization(ctx, newAuthz)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")

	// Create an expired authz
	newExpiredAuthz := core.Authorization{
		RegistrationID: newAuthz.RegistrationID,
		Expires:        &alreadyExpired,
		Status:         newAuthz.Status,
		Identifier:     identifier.ACMEIdentifier{Type: identifier.DNS, Value: "expired.your.order.is.up"},
	}
	expiredAuthz, err := sa.NewPendingAuthorization(ctx, newExpiredAuthz)
	test.AssertNotError(t, err, "Couldn't create new expired pending authorization")

	// Create an invalid authz
	invalidAuthz, err := sa.NewPendingAuthorization(ctx, newAuthz)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	invalidAuthz.Status = core.StatusInvalid
	invalidAuthz.Identifier.Value = "invalid.your.order.is.up"
	err = sa.FinalizeAuthorization(ctx, invalidAuthz)
	test.AssertNotError(t, err, "Couldn't finalize pending authz to invalid")

	// Create a deactivated authz
	deactivatedAuthz, err := sa.NewPendingAuthorization(ctx, newAuthz)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")
	deactivatedAuthz.Status = core.StatusDeactivated
	deactivatedAuthz.Identifier.Value = "deactivated.your.order.is.up"
	err = sa.FinalizeAuthorization(ctx, deactivatedAuthz)
	test.AssertNotError(t, err, "Couldn't finalize pending authz to deactivated")

	// Create a valid authz
	validAuthz, err := sa.NewPendingAuthorization(ctx, newAuthz)
	test.AssertNotError(t, err, "sa.NewPendingAuthorization failed")
	validAuthz.Status = core.StatusValid
	validAuthz.Identifier.Value = "valid.your.order.is.up"
	err = sa.FinalizeAuthorization(ctx, validAuthz)
	test.AssertNotError(t, err, "Couldn't finalize pending authz to valid")

	testCases := []struct {
		Name             string
		AuthorizationIDs []string
		OrderNames       []string
		OrderExpires     int64
		ExpectedStatus   string
		SetProcessing    bool
		Finalize         bool
	}{
		{
			Name:             "Order with an invalid authz",
			OrderNames:       []string{"pending.your.order.is.up", "invalid.your.order.is.up", "deactivated.your.order.is.up", "valid.your.order.is.up"},
			AuthorizationIDs: []string{pendingAuthz.ID, invalidAuthz.ID, deactivatedAuthz.ID, validAuthz.ID},
			ExpectedStatus:   string(core.StatusInvalid),
		},
		{
			Name:             "Order with an expired authz",
			OrderNames:       []string{"pending.your.order.is.up", "expired.your.order.is.up", "deactivated.your.order.is.up", "valid.your.order.is.up"},
			AuthorizationIDs: []string{pendingAuthz.ID, expiredAuthz.ID, deactivatedAuthz.ID, validAuthz.ID},
			ExpectedStatus:   string(core.StatusInvalid),
		},
		{
			Name:             "Order with a deactivated authz",
			OrderNames:       []string{"pending.your.order.is.up", "deactivated.your.order.is.up", "valid.your.order.is.up"},
			AuthorizationIDs: []string{pendingAuthz.ID, deactivatedAuthz.ID, validAuthz.ID},
			ExpectedStatus:   string(core.StatusDeactivated),
		},
		{
			Name:             "Order that has expired and references a purged expired authz",
			OrderExpires:     alreadyExpired.UnixNano(),
			OrderNames:       []string{"missing.your.order.is.up"},
			AuthorizationIDs: []string{"this does not exist"},
			ExpectedStatus:   string(core.StatusInvalid),
		},
		{
			Name:             "Order with a pending authz",
			OrderNames:       []string{"valid.your.order.is.up", "pending.your.order.is.up"},
			AuthorizationIDs: []string{validAuthz.ID, pendingAuthz.ID},
			ExpectedStatus:   string(core.StatusPending),
		},
		{
			Name:             "Order with only valid authzs, not yet processed or finalized",
			OrderNames:       []string{"valid.your.order.is.up"},
			AuthorizationIDs: []string{validAuthz.ID},
			ExpectedStatus:   string(core.StatusReady),
		},
		{
			Name:             "Order with only valid authzs, set processing",
			OrderNames:       []string{"valid.your.order.is.up"},
			AuthorizationIDs: []string{validAuthz.ID},
			SetProcessing:    true,
			ExpectedStatus:   string(core.StatusProcessing),
		},
		{
			Name:             "Order with only valid authzs, not yet processed or finalized, OrderReadyStatus feature flag",
			OrderNames:       []string{"valid.your.order.is.up"},
			AuthorizationIDs: []string{validAuthz.ID},
			ExpectedStatus:   string(core.StatusReady),
		},
		{
			Name:             "Order with only valid authzs, set processing",
			OrderNames:       []string{"valid.your.order.is.up"},
			AuthorizationIDs: []string{validAuthz.ID},
			SetProcessing:    true,
			ExpectedStatus:   string(core.StatusProcessing),
		},
		{
			Name:             "Order with only valid authzs, set processing and finalized",
			OrderNames:       []string{"valid.your.order.is.up"},
			AuthorizationIDs: []string{validAuthz.ID},
			SetProcessing:    true,
			Finalize:         true,
			ExpectedStatus:   string(core.StatusValid),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Add a new order with the testcase authz IDs
			processing := false
			// If the testcase doesn't specify an order expiry use a default timestamp
			// in the near future.
			orderExpiry := tc.OrderExpires
			if orderExpiry == 0 {
				orderExpiry = expiresNano
			}
			newOrder, err := sa.NewOrder(ctx, &corepb.Order{
				RegistrationID:  &reg.ID,
				Expires:         &orderExpiry,
				Authorizations:  tc.AuthorizationIDs,
				Names:           tc.OrderNames,
				BeganProcessing: &processing,
			})
			test.AssertNotError(t, err, "NewOrder errored unexpectedly")
			// If requested, set the order to processing
			if tc.SetProcessing {
				err := sa.SetOrderProcessing(ctx, newOrder)
				test.AssertNotError(t, err, "Error setting order to processing status")
			}
			// If requested, finalize the order
			if tc.Finalize {
				cereal := "lucky charms"
				newOrder.CertificateSerial = &cereal
				err := sa.FinalizeOrder(ctx, newOrder)
				test.AssertNotError(t, err, "Error finalizing order")
			}
			// Fetch the order by ID to get its calculated status
			storedOrder, err := sa.GetOrder(ctx, &sapb.OrderRequest{Id: newOrder.Id})
			test.AssertNotError(t, err, "GetOrder failed")
			// The status shouldn't be nil
			test.AssertNotNil(t, storedOrder.Status, "Order status was nil")
			// The status should match expected
			test.AssertEquals(t, *storedOrder.Status, tc.ExpectedStatus)
		})
	}

}

// Check that getAuthorizations is fast enough; that is, it shouldn't retrieve
// challenges for authorizations it won't return (which has been a cause of
// slowness when there are many authorizations for the same domain name).
func TestGetAuthorizationsFast(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	ctx := context.Background()
	reg := satest.CreateWorkingRegistration(t, sa)

	expires := fc.Now().Add(time.Hour)

	makeAuthz := func(s string) {
		_, err := sa.NewPendingAuthorization(ctx, core.Authorization{
			RegistrationID: reg.ID,
			Expires:        &expires,
			Status:         core.StatusPending,
			Identifier: identifier.ACMEIdentifier{
				Type:  identifier.DNS,
				Value: s,
			},
		})
		test.AssertNotError(t, err, "making pending authz")
	}

	for i := 0; i < 10; i++ {
		makeAuthz("example.com")
		makeAuthz("www.example.com")
		expires = expires.Add(time.Hour)
	}

	// Mock out getChallenges so we can count how many times it's called.
	var challengeFetchCount int
	sa.getChallenges = func(sel dbSelector, s string) ([]core.Challenge, error) {
		challengeFetchCount++
		return nil, nil
	}

	results, err := sa.getAuthorizations(ctx, pendingAuthorizationTable,
		string(core.StatusPending), reg.ID, []string{"example.com", "www.example.com"},
		fc.Now(), false)
	test.AssertNotError(t, err, "getting authorizations")
	if len(results) != 2 {
		t.Fatalf("Wrong number of results. Expected 2, got %d", len(results))
	}
	if results["example.com"] == nil || results["www.example.com"] == nil {
		t.Fatalf("Nil result for expected domain: %#v", results)
	}
	// We expect getChallenges to be called exactly once for each domain.
	if challengeFetchCount != 2 {
		t.Errorf("Wrong challenge fetch count: expected 2, got %d", challengeFetchCount)
	}
}

func TestUpdateChallengesPendingOnly(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	expires := fc.Now().Add(time.Hour)
	ctx := context.Background()

	// Create a registration to work with
	reg := satest.CreateWorkingRegistration(t, sa)

	// Create a pending authz
	input := core.Authorization{
		RegistrationID: reg.ID,
		Expires:        &expires,
		Status:         core.StatusPending,
		Identifier:     identifier.ACMEIdentifier{Type: identifier.DNS, Value: "example.com"},
		Challenges: []core.Challenge{
			core.Challenge{
				Type:   "http-01",
				Status: "pending",
			},
		},
	}
	authz, err := sa.NewPendingAuthorization(ctx, input)
	test.AssertNotError(t, err, "Couldn't create new pending authorization")

	authz.Status = core.StatusValid
	authz.Challenges[0].Status = core.StatusValid
	err = sa.FinalizeAuthorization(ctx, authz)
	test.AssertNotError(t, err, "Couldn't finalize pending authorization with ID "+authz.ID)

	tx, err := sa.dbMap.Begin()
	test.AssertNotError(t, err, "beginning transaction")

	// We shouldn't be able to change a challenge status back to pending once it's
	// been set to "valid". This update should succeed, but have no effect.
	authz.Challenges[0].Status = core.StatusPending
	err = updateChallenges(tx, authz.ID, authz.Challenges)
	test.AssertNotError(t, err, "updating challenges")
	err = tx.Commit()
	test.AssertNotError(t, err, "committing")

	result, err := sa.GetAuthorization(ctx, authz.ID)
	test.AssertNotError(t, err, "fetching")

	if result.Challenges[0].Status != core.StatusValid {
		t.Errorf("challenge status was updated when it should not have been allowed to be changed.")
	}
}

func TestRevokeCertificate(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	// Add a cert to the DB to test with.
	certDER, err := ioutil.ReadFile("www.eff.org.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")
	issued := sa.clk.Now()
	_, err = sa.AddCertificate(ctx, certDER, reg.ID, nil, &issued)
	test.AssertNotError(t, err, "Couldn't add www.eff.org.der")

	serial := "000000000000000000000000000000021bd4"

	status, err := sa.GetCertificateStatus(ctx, serial)
	test.AssertNotError(t, err, "GetCertificateStatus failed")
	test.AssertEquals(t, status.Status, core.OCSPStatusGood)

	fc.Add(1 * time.Hour)

	now := fc.Now()
	dateUnix := now.UnixNano()
	reason := int64(1)
	response := []byte{1, 2, 3}
	err = sa.RevokeCertificate(context.Background(), &sapb.RevokeCertificateRequest{
		Serial:   &serial,
		Date:     &dateUnix,
		Reason:   &reason,
		Response: response,
	})
	test.AssertNotError(t, err, "RevokeCertificate failed")

	status, err = sa.GetCertificateStatus(ctx, serial)
	test.AssertNotError(t, err, "GetCertificateStatus failed")
	test.AssertEquals(t, status.Status, core.OCSPStatusRevoked)
	test.AssertEquals(t, status.RevokedReason, revocation.Reason(reason))
	test.AssertEquals(t, status.RevokedDate, now)
	test.AssertEquals(t, status.OCSPLastUpdated, now)
	test.AssertDeepEquals(t, status.OCSPResponse, response)

	err = sa.RevokeCertificate(context.Background(), &sapb.RevokeCertificateRequest{
		Serial:   &serial,
		Date:     &dateUnix,
		Reason:   &reason,
		Response: response,
	})
	test.AssertError(t, err, "RevokeCertificate should've failed when certificate already revoked")
}

func TestAddCertificateRenewalBit(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)

	// An example cert taken from EFF's website
	certDER, err := ioutil.ReadFile("www.eff.org.der")
	test.AssertNotError(t, err, "Unexpected error reading www.eff.org.der test file")
	cert, err := x509.ParseCertificate(certDER)
	test.AssertNotError(t, err, "Unexpected error parsing www.eff.org.der test file")
	names := cert.DNSNames

	expires := fc.Now().Add(time.Hour * 2).UTC()
	issued := fc.Now()
	serial := "thrilla"

	// Add a FQDN set for the names so that it will be considered a renewal
	tx, err := sa.dbMap.Begin()
	test.AssertNotError(t, err, "Failed to open transaction")
	err = addFQDNSet(tx, names, serial, issued, expires)
	test.AssertNotError(t, err, "Failed to add name set")
	test.AssertNotError(t, tx.Commit(), "Failed to commit transaction")

	// Add the certificate with the same names.
	_, err = sa.AddCertificate(ctx, certDER, reg.ID, nil, &issued)
	test.AssertNotError(t, err, "Failed to add certificate")

	assertIsRenewal := func(t *testing.T, name string, expected bool) {
		var count int
		err := sa.dbMap.SelectOne(
			&count,
			`SELECT COUNT(1) FROM issuedNames
		WHERE reversedName = ?
		AND renewal = ?`,
			ReverseName(name),
			expected,
		)
		test.AssertNotError(t, err, "Unexpected error from SelectOne on issuedNames")
		test.AssertEquals(t, count, 1)
	}

	// All of the names should have a issuedNames row marking it as a renewal.
	for _, name := range names {
		assertIsRenewal(t, name, true)
	}

	// Add a certificate with different names.
	certDER, err = ioutil.ReadFile("test-cert.der")
	test.AssertNotError(t, err, "Unexpected error reading test-cert.der test file")
	cert, err = x509.ParseCertificate(certDER)
	test.AssertNotError(t, err, "Unexpected error parsing test-cert.der test file")
	names = cert.DNSNames

	_, err = sa.AddCertificate(ctx, certDER, reg.ID, nil, &issued)
	test.AssertNotError(t, err, "Failed to add certificate")

	// None of the names should have a issuedNames row marking it as a renewal.
	for _, name := range names {
		assertIsRenewal(t, name, false)
	}
}

func TestCountCertificatesRenewalBit(t *testing.T) {
	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	// Create a test registration
	reg := satest.CreateWorkingRegistration(t, sa)

	// Create a small throw away key for the test certificates.
	testKey, err := rsa.GenerateKey(rand.Reader, 512)
	test.AssertNotError(t, err, "error generating test key")

	// Create an initial test certificate for a set of domain names, issued an
	// hour ago.
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1337),
		DNSNames:              []string{"www.not-example.com", "not-example.com", "admin.not-example.com"},
		NotBefore:             fc.Now().Add(-time.Hour),
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	certADER, err := x509.CreateCertificate(rand.Reader, template, template, testKey.Public(), testKey)
	test.AssertNotError(t, err, "Failed to create test cert A")
	certA, _ := x509.ParseCertificate(certADER)

	// Update the template with a new serial number and a not before of now and
	// create a second test cert for the same names. This will be a renewal.
	template.SerialNumber = big.NewInt(7331)
	template.NotBefore = fc.Now()
	certBDER, err := x509.CreateCertificate(rand.Reader, template, template, testKey.Public(), testKey)
	test.AssertNotError(t, err, "Failed to create test cert B")
	certB, _ := x509.ParseCertificate(certBDER)

	// Update the template with a third serial number and a partially overlapping
	// set of names. This will not be a renewal but will help test the exact name
	// counts.
	template.SerialNumber = big.NewInt(0xC0FFEE)
	template.DNSNames = []string{"www.not-example.com"}
	certCDER, err := x509.CreateCertificate(rand.Reader, template, template, testKey.Public(), testKey)
	test.AssertNotError(t, err, "Failed to create test cert C")

	countName := func(t *testing.T, name string) int64 {
		counts, err := sa.CountCertificatesByNames(
			context.Background(),
			[]string{name},
			fc.Now().Add(-5*time.Hour),
			fc.Now().Add(5*time.Hour))
		test.AssertNotError(t, err, "Unexpected err from CountCertificatesByNames")
		for _, elem := range counts {
			if *elem.Name == name {
				return *elem.Count
			}
		}
		return 0
	}

	// Add the first certificate - it won't be considered a renewal.
	issued := certA.NotBefore
	_, err = sa.AddCertificate(ctx, certADER, reg.ID, nil, &issued)
	test.AssertNotError(t, err, "Failed to add CertA test certificate")

	// The count for the base domain should be 1 - just certA has been added.
	test.AssertEquals(t, countName(t, "not-example.com"), int64(1))

	// Add the second certificate - it should be considered a renewal
	issued = certB.NotBefore
	_, err = sa.AddCertificate(ctx, certBDER, reg.ID, nil, &issued)
	test.AssertNotError(t, err, "Failed to add CertB test certificate")

	// The count for the base domain should still be 1, just certA. CertB should
	// be ignored.
	test.AssertEquals(t, countName(t, "not-example.com"), int64(1))

	// Add the third certificate - it should not be considered a renewal
	_, err = sa.AddCertificate(ctx, certCDER, reg.ID, nil, &issued)
	test.AssertNotError(t, err, "Failed to add CertC test certificate")

	// The count for the base domain should be 2 now: certA and certC.
	// CertB should be ignored.
	test.AssertEquals(t, countName(t, "not-example.com"), int64(2))
}

func TestNewAuthorizations2(t *testing.T) {
	if !strings.HasSuffix(os.Getenv("BOULDER_CONFIG_DIR"), "config-next") {
		return
	}

	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	v2 := true
	ident := "aaa"
	pending := string(core.StatusPending)
	expires := fc.Now().Add(time.Hour).UTC().UnixNano()
	challType := string(core.ChallengeTypeDNS01)
	tokenA := "YXNkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	apbA := &corepb.Authorization{
		V2:             &v2,
		Identifier:     &ident,
		RegistrationID: &reg.ID,
		Status:         &pending,
		Expires:        &expires,
		Challenges: []*corepb.Challenge{
			{
				Status: &pending,
				Type:   &challType,
				Token:  &tokenA,
			},
		},
	}
	tokenB := "ZmdoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	apbB := &corepb.Authorization{
		V2:             &v2,
		Identifier:     &ident,
		RegistrationID: &reg.ID,
		Status:         &pending,
		Expires:        &expires,
		Challenges: []*corepb.Challenge{
			{
				Status: &pending,
				Type:   &challType,
				Token:  &tokenB,
			},
		},
	}
	req := &sapb.AddPendingAuthorizationsRequest{Authz: []*corepb.Authorization{apbA, apbB}}
	ids, err := sa.NewAuthorizations2(context.Background(), req)
	test.AssertNotError(t, err, "sa.NewAuthorizations failed")
	test.AssertEquals(t, len(ids.Ids), 2)
	for i, id := range ids.Ids {
		dbVer, err := sa.GetAuthorization2(context.Background(), &sapb.AuthorizationID2{Id: &id})
		test.AssertNotError(t, err, "sa.GetAuthorization failed")
		// Everything but ID should match
		req.Authz[i].Id = dbVer.Id
		req.Authz[i].Combinations = dbVer.Combinations
		test.AssertDeepEquals(t, req.Authz[i], dbVer)
	}
}

func TestFinalizeAuthorization2(t *testing.T) {
	if !strings.HasSuffix(os.Getenv("BOULDER_CONFIG_DIR"), "config-next") {
		return
	}

	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	v2 := true
	ident := "aaa"
	pending := string(core.StatusPending)
	expires := fc.Now().Add(time.Hour).UTC().UnixNano()
	challType := string(core.ChallengeTypeDNS01)
	token := "YXNkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	apb := &corepb.Authorization{
		V2:             &v2,
		Identifier:     &ident,
		RegistrationID: &reg.ID,
		Status:         &pending,
		Expires:        &expires,
		Challenges: []*corepb.Challenge{
			{
				Status: &pending,
				Type:   &challType,
				Token:  &token,
			},
		},
	}
	ids, err := sa.NewAuthorizations2(context.Background(), &sapb.AddPendingAuthorizationsRequest{Authz: []*corepb.Authorization{apb}})
	test.AssertNotError(t, err, "sa.NewAuthorization failed")

	valid := string(core.StatusValid)
	expires = fc.Now().Add(time.Hour * 2).UTC().UnixNano()
	port := "123"
	url := "http://asd"
	ip, _ := net.ParseIP("1.1.1.1").MarshalText()
	err = sa.FinalizeAuthorization2(context.Background(), &sapb.FinalizeAuthorizationRequest{
		Id: &ids.Ids[0],
		ValidationRecords: []*corepb.ValidationRecord{
			{
				Hostname:    &ident,
				Port:        &port,
				Url:         &url,
				AddressUsed: ip,
			},
		},
		Status:    &valid,
		Expires:   &expires,
		Attempted: &challType,
	})
	test.AssertNotError(t, err, "sa.FinalizeAuthorization2 failed")

	dbVer, err := sa.GetAuthorization2(context.Background(), &sapb.AuthorizationID2{Id: &ids.Ids[0]})
	test.AssertNotError(t, err, "sa.GetAuthorization2 failed")
	test.AssertEquals(t, *dbVer.Status, string(core.StatusValid))
	test.AssertEquals(t, time.Unix(0, *dbVer.Expires).UTC(), fc.Now().Add(time.Hour*2).UTC())
	test.AssertEquals(t, *dbVer.Challenges[0].Status, string(core.StatusValid))
	test.AssertEquals(t, len(dbVer.Challenges[0].Validationrecords), 1)

	token = "ZmdoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	ids, err = sa.NewAuthorizations2(context.Background(), &sapb.AddPendingAuthorizationsRequest{Authz: []*corepb.Authorization{apb}})
	test.AssertNotError(t, err, "sa.NewAuthorization failed")
	invalid := string(core.StatusInvalid)
	prob, _ := bgrpc.ProblemDetailsToPB(probs.ConnectionFailure("it went bad captain"))
	err = sa.FinalizeAuthorization2(context.Background(), &sapb.FinalizeAuthorizationRequest{
		Id: &ids.Ids[0],
		ValidationRecords: []*corepb.ValidationRecord{
			{
				Hostname:    &ident,
				Port:        &port,
				Url:         &url,
				AddressUsed: ip,
			},
		},
		ValidationError: prob,
		Status:          &invalid,
		Attempted:       &challType,
		Expires:         &expires,
	})
	test.AssertNotError(t, err, "sa.FinalizeAuthorization2 failed")

	dbVer, err = sa.GetAuthorization2(context.Background(), &sapb.AuthorizationID2{Id: &ids.Ids[0]})
	test.AssertNotError(t, err, "sa.GetAuthorization2 failed")
	test.AssertEquals(t, *dbVer.Status, string(core.StatusInvalid))
	test.AssertEquals(t, *dbVer.Challenges[0].Status, string(core.StatusInvalid))
	test.AssertEquals(t, len(dbVer.Challenges[0].Validationrecords), 1)
	test.AssertDeepEquals(t, dbVer.Challenges[0].Error, prob)
}

func TestGetPendingAuthorization2(t *testing.T) {
	if !strings.HasSuffix(os.Getenv("BOULDER_CONFIG_DIR"), "config-next") {
		return
	}

	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	v2 := true
	ident := "aaa"
	pending := string(core.StatusPending)
	expiresA := fc.Now().Add(time.Hour).UTC().UnixNano()
	expiresB := fc.Now().Add(time.Hour * 3).UTC().UnixNano()
	challType := string(core.ChallengeTypeDNS01)
	tokenA := "YXNkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tokenB := "ZmdoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	ids, err := sa.NewAuthorizations2(context.Background(), &sapb.AddPendingAuthorizationsRequest{
		Authz: []*corepb.Authorization{
			&corepb.Authorization{
				V2:             &v2,
				Identifier:     &ident,
				RegistrationID: &reg.ID,
				Status:         &pending,
				Expires:        &expiresA,
				Challenges: []*corepb.Challenge{
					{
						Status: &pending,
						Type:   &challType,
						Token:  &tokenA,
					},
				},
			},
			&corepb.Authorization{
				V2:             &v2,
				Identifier:     &ident,
				RegistrationID: &reg.ID,
				Status:         &pending,
				Expires:        &expiresB,
				Challenges: []*corepb.Challenge{
					{
						Status: &pending,
						Type:   &challType,
						Token:  &tokenB,
					},
				},
			},
		},
	})
	test.AssertNotError(t, err, "sa.NewAuthorizations2 failed")
	test.AssertEquals(t, len(ids.Ids), 2)

	validUntil := fc.Now().Add(time.Hour * 2).UTC().UnixNano()
	dbVer, err := sa.GetPendingAuthorization2(context.Background(), &sapb.GetPendingAuthorizationRequest{
		RegistrationID:  &reg.ID,
		IdentifierValue: &ident,
		ValidUntil:      &validUntil,
	})
	test.AssertNotError(t, err, "sa.GetPendingAuthorization2 failed")
	test.AssertEquals(t, fmt.Sprintf("%d", ids.Ids[1]), *dbVer.Id)

	validUntil = fc.Now().UTC().UnixNano()
	dbVer, err = sa.GetPendingAuthorization2(context.Background(), &sapb.GetPendingAuthorizationRequest{
		RegistrationID:  &reg.ID,
		IdentifierValue: &ident,
		ValidUntil:      &validUntil,
	})
	test.AssertNotError(t, err, "sa.GetPendingAuthorization2 failed")
	test.AssertEquals(t, fmt.Sprintf("%d", ids.Ids[0]), *dbVer.Id)

	// Test Getting an old style authorization if there isn't a good new one
	fc.Add(time.Hour * 5)
	exp := fc.Now().Add(time.Hour * 2).UTC()
	oldPA, err := sa.NewPendingAuthorization(context.Background(), core.Authorization{
		Status:         core.StatusPending,
		Expires:        &exp,
		RegistrationID: reg.ID,
		Identifier: identifier.ACMEIdentifier{
			Type:  identifier.DNS,
			Value: ident,
		},
	})
	test.AssertNotError(t, err, "sa.NewPendingAuthorization failed")

	validUntil = fc.Now().UTC().UnixNano()
	identType := string(identifier.DNS)
	dbVer, err = sa.GetPendingAuthorization2(context.Background(), &sapb.GetPendingAuthorizationRequest{
		RegistrationID:  &reg.ID,
		IdentifierValue: &ident,
		IdentifierType:  &identType,
		ValidUntil:      &validUntil,
	})

	test.AssertNotError(t, err, "sa.GetPendingAuthorization2 failed")
	test.AssertEquals(t, oldPA.ID, *dbVer.Id)
}

func TestCountPendingAuthorizations2(t *testing.T) {
	if !strings.HasSuffix(os.Getenv("BOULDER_CONFIG_DIR"), "config-next") {
		return
	}

	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	v2 := true
	ident := "aaa"
	pending := string(core.StatusPending)
	expiresA := fc.Now().Add(time.Hour).UTC().UnixNano()
	expiresB := fc.Now().Add(time.Hour * 3).UTC().UnixNano()
	challType := string(core.ChallengeTypeDNS01)
	tokenA := "YXNkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tokenB := "ZmdoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	ids, err := sa.NewAuthorizations2(context.Background(), &sapb.AddPendingAuthorizationsRequest{
		Authz: []*corepb.Authorization{
			&corepb.Authorization{
				V2:             &v2,
				Identifier:     &ident,
				RegistrationID: &reg.ID,
				Status:         &pending,
				Expires:        &expiresA,
				Challenges: []*corepb.Challenge{
					{
						Status: &pending,
						Type:   &challType,
						Token:  &tokenA,
					},
				},
			},
			&corepb.Authorization{
				V2:             &v2,
				Identifier:     &ident,
				RegistrationID: &reg.ID,
				Status:         &pending,
				Expires:        &expiresB,
				Challenges: []*corepb.Challenge{
					{
						Status: &pending,
						Type:   &challType,
						Token:  &tokenB,
					},
				},
			},
		},
	})
	test.AssertNotError(t, err, "sa.NewAuthorizations2 failed")
	test.AssertEquals(t, len(ids.Ids), 2)

	// Registration has two new style pending authorizations
	count, err := sa.CountPendingAuthorizations2(context.Background(), &sapb.RegistrationID{
		Id: &reg.ID,
	})
	test.AssertNotError(t, err, "sa.CountPendingAuthorizations2 failed")
	test.AssertEquals(t, *count.Count, int64(2))

	// Registration has two new style pending authorizations, one of which has expired
	fc.Add(time.Hour * 2)
	count, err = sa.CountPendingAuthorizations2(context.Background(), &sapb.RegistrationID{
		Id: &reg.ID,
	})
	test.AssertNotError(t, err, "sa.CountPendingAuthorizations2 failed")
	test.AssertEquals(t, *count.Count, int64(1))

	// Registration has two  new style pending authorizations, one of which has expired
	// and one old style pending authorization
	pExp := fc.Now().Add(time.Hour)
	_, err = sa.NewPendingAuthorization(ctx, core.Authorization{
		RegistrationID: reg.ID,
		Expires:        &pExp,
		Status:         core.StatusPending,
	})
	test.AssertNotError(t, err, "sa.NewPendingAuthorization failed")
	count, err = sa.CountPendingAuthorizations2(context.Background(), &sapb.RegistrationID{
		Id: &reg.ID,
	})
	test.AssertNotError(t, err, "sa.CountPendingAuthorizations2 failed")
	test.AssertEquals(t, *count.Count, int64(2))

	// Registration with no authorizations should be 0
	noReg := int64(20)
	count, err = sa.CountPendingAuthorizations2(context.Background(), &sapb.RegistrationID{
		Id: &noReg,
	})
	test.AssertNotError(t, err, "sa.CountPendingAuthorizations2 failed")
	test.AssertEquals(t, *count.Count, int64(0))
}

func TestGetValidOrderAuthorizations2(t *testing.T) {
	if !strings.HasSuffix(os.Getenv("BOULDER_CONFIG_DIR"), "config-next") {
		return
	}

	sa, fc, cleanup := initSA(t)
	defer cleanup()

	// Create a new valid authorization and an old valid authorization
	reg := satest.CreateWorkingRegistration(t, sa)
	oldAuthz := CreateDomainAuthWithRegID(t, "a.example.com", sa, reg.ID)
	exp := fc.Now().Add(time.Hour * 24 * 7)
	oldAuthz.Expires = &exp
	oldAuthz.Status = core.StatusValid
	err := sa.FinalizeAuthorization(ctx, oldAuthz)
	test.AssertNotError(t, err, "sa.FinalizeAuthorization failed")

	v2 := true
	ident := "b.example.com"
	pending := string(core.StatusPending)
	expires := exp.UTC().UnixNano()
	challType := string(core.ChallengeTypeDNS01)
	token := "YXNkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	ids, err := sa.NewAuthorizations2(context.Background(), &sapb.AddPendingAuthorizationsRequest{
		Authz: []*corepb.Authorization{
			&corepb.Authorization{
				V2:             &v2,
				Identifier:     &ident,
				RegistrationID: &reg.ID,
				Status:         &pending,
				Expires:        &expires,
				Challenges: []*corepb.Challenge{
					{
						Status: &pending,
						Type:   &challType,
						Token:  &token,
					},
				},
			},
		},
	})
	test.AssertNotError(t, err, "sa.NewAuthorizations2 failed")
	valid := string(core.StatusValid)
	err = sa.FinalizeAuthorization2(context.Background(), &sapb.FinalizeAuthorizationRequest{
		Id:                &ids.Ids[0],
		Status:            &valid,
		Attempted:         &challType,
		ValidationRecords: []*corepb.ValidationRecord{},
		Expires:           &expires,
	})
	test.AssertNotError(t, err, "sa.FinalizeAuthorization2 failed")

	i := fc.Now().Truncate(time.Second).UnixNano()
	status := string(core.StatusPending)
	order := &corepb.Order{
		RegistrationID:   &reg.ID,
		Expires:          &i,
		Names:            []string{"a.example.com", "b.example.com"},
		Authorizations:   []string{oldAuthz.ID},
		V2Authorizations: []int64{ids.Ids[0]},
		Status:           &status,
	}
	order, err = sa.NewOrder(context.Background(), order)
	test.AssertNotError(t, err, "AddOrder failed")

	authzMap, err := sa.GetValidOrderAuthorizations2(
		context.Background(),
		&sapb.GetValidOrderAuthorizationsRequest{
			Id:     order.Id,
			AcctID: &reg.ID,
		})
	test.AssertNotError(t, err, "sa.GetValidOrderAuthorizations failed")
	test.AssertNotNil(t, authzMap, "sa.GetValidOrderAuthorizations result was nil")
	test.AssertEquals(t, len(authzMap.Authz), 2)

	// Getting the order authorizations for an order that doesn't exist should return nothing
	missingID := int64(0xC0FFEEEEEEE)
	authzMap, err = sa.GetValidOrderAuthorizations2(
		context.Background(),
		&sapb.GetValidOrderAuthorizationsRequest{
			Id:     &missingID,
			AcctID: &reg.ID,
		})
	test.AssertNotError(t, err, "sa.GetValidOrderAuthorizations failed")
	test.AssertEquals(t, len(authzMap.Authz), 0)

	// Getting the order authorizations for an order that does exist, but for the
	// wrong acct ID should return nothing
	wrongAcctID := int64(0xDEADDA7ABA5E)
	authzMap, err = sa.GetValidOrderAuthorizations2(
		context.Background(),
		&sapb.GetValidOrderAuthorizationsRequest{
			Id:     order.Id,
			AcctID: &wrongAcctID,
		})
	test.AssertNotError(t, err, "sa.GetValidOrderAuthorizations failed")
	test.AssertEquals(t, len(authzMap.Authz), 0)
}

func TestCountInvalidAuthorizations2(t *testing.T) {
	if !strings.HasSuffix(os.Getenv("BOULDER_CONFIG_DIR"), "config-next") {
		return
	}

	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	// Create three authorizations, one new pending, one new invalid, and one
	// old invalid
	fc.Add(time.Hour)
	reg := satest.CreateWorkingRegistration(t, sa)
	v2 := true
	ident := "aaa"
	pending := string(core.StatusPending)
	expiresA := fc.Now().Add(time.Hour).UTC().UnixNano()
	expiresB := fc.Now().Add(time.Hour * 3).UTC().UnixNano()
	challType := string(core.ChallengeTypeDNS01)
	tokenA := "YXNkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tokenB := "ZmdoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	ids, err := sa.NewAuthorizations2(context.Background(), &sapb.AddPendingAuthorizationsRequest{
		Authz: []*corepb.Authorization{
			&corepb.Authorization{
				V2:             &v2,
				Identifier:     &ident,
				RegistrationID: &reg.ID,
				Status:         &pending,
				Expires:        &expiresA,
				Challenges: []*corepb.Challenge{
					{
						Status: &pending,
						Type:   &challType,
						Token:  &tokenA,
					},
				},
			},
			&corepb.Authorization{
				V2:             &v2,
				Identifier:     &ident,
				RegistrationID: &reg.ID,
				Status:         &pending,
				Expires:        &expiresB,
				Challenges: []*corepb.Challenge{
					{
						Status: &pending,
						Type:   &challType,
						Token:  &tokenB,
					},
				},
			},
		},
	})
	test.AssertNotError(t, err, "sa.NewAuthorizations2 failed")
	test.AssertEquals(t, len(ids.Ids), 2)

	invalid := string(core.StatusInvalid)
	prob, _ := bgrpc.ProblemDetailsToPB(probs.ConnectionFailure("it went bad captain"))
	err = sa.FinalizeAuthorization2(context.Background(), &sapb.FinalizeAuthorizationRequest{
		Id:                &ids.Ids[1],
		Status:            &invalid,
		Attempted:         &challType,
		ValidationRecords: []*corepb.ValidationRecord{},
		Expires:           &expiresB,
		ValidationError:   prob,
	})
	test.AssertNotError(t, err, "sa.FinalizeAuthorization2 failed")
	exp := fc.Now().Add(time.Hour)
	oldPA, err := sa.NewPendingAuthorization(ctx, core.Authorization{
		RegistrationID: reg.ID,
		Expires:        &exp,
		Status:         core.StatusPending,
		Identifier: identifier.ACMEIdentifier{
			Type:  identifier.DNS,
			Value: ident,
		},
	})
	test.AssertNotError(t, err, "sa.NewPendingAuthorization failed")
	oldPA.Status = core.StatusInvalid
	err = sa.FinalizeAuthorization(context.Background(), oldPA)
	test.AssertNotError(t, err, "sa.FinalizeAuthorization failed")

	earliest, latest := fc.Now().Add(-time.Hour).UTC().UnixNano(), fc.Now().Add(time.Hour*5).UTC().UnixNano()
	count, err := sa.CountInvalidAuthorizations2(context.Background(), &sapb.CountInvalidAuthorizationsRequest{
		RegistrationID: &reg.ID,
		Hostname:       &ident,
		Range: &sapb.Range{
			Earliest: &earliest,
			Latest:   &latest,
		},
	})
	test.AssertNotError(t, err, "sa.CountInvalidAuthorizations2 failed")
	test.AssertEquals(t, *count.Count, int64(2))
}

func TestGetValidAuthorizations2(t *testing.T) {
	if !strings.HasSuffix(os.Getenv("BOULDER_CONFIG_DIR"), "config-next") {
		return
	}

	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	// Create a valid old style authorization and a valid
	// new style authorization
	reg := satest.CreateWorkingRegistration(t, sa)
	exp := fc.Now().Add(time.Hour).UTC()
	oldPA, err := sa.NewPendingAuthorization(ctx, core.Authorization{
		RegistrationID: reg.ID,
		Expires:        &exp,
		Status:         core.StatusPending,
		Identifier: identifier.ACMEIdentifier{
			Type:  identifier.DNS,
			Value: "bbb",
		},
	})
	test.AssertNotError(t, err, "sa.NewPendingAuthorization failed")
	oldPA.Status = core.StatusValid
	err = sa.FinalizeAuthorization(context.Background(), oldPA)
	test.AssertNotError(t, err, "sa.FinalizeAuthorization failed")
	v2 := true
	ident := "aaa"
	pending := string(core.StatusPending)
	expires := fc.Now().Add(time.Hour).UTC().UnixNano()
	challType := string(core.ChallengeTypeDNS01)
	token := "YXNk"
	ids, err := sa.NewAuthorizations2(context.Background(), &sapb.AddPendingAuthorizationsRequest{
		Authz: []*corepb.Authorization{
			&corepb.Authorization{
				V2:             &v2,
				Identifier:     &ident,
				RegistrationID: &reg.ID,
				Status:         &pending,
				Expires:        &expires,
				Challenges: []*corepb.Challenge{
					{
						Status: &pending,
						Type:   &challType,
						Token:  &token,
					},
				},
			},
		},
	})
	test.AssertNotError(t, err, "sa.NewAuthorizations2 failed")
	test.AssertEquals(t, len(ids.Ids), 1)
	valid := string(core.StatusValid)
	err = sa.FinalizeAuthorization2(context.Background(), &sapb.FinalizeAuthorizationRequest{
		Id:                &ids.Ids[0],
		Status:            &valid,
		Attempted:         &challType,
		ValidationRecords: []*corepb.ValidationRecord{},
		Expires:           &expires,
	})
	test.AssertNotError(t, err, "sa.FinalizeAuthorization2 failed")

	now := fc.Now().UTC().UnixNano()
	authzs, err := sa.GetValidAuthorizations2(context.Background(), &sapb.GetValidAuthorizationsRequest{
		Domains: []string{
			"aaa",
			"bbb",
		},
		RegistrationID: &reg.ID,
		Now:            &now,
	})
	test.AssertNotError(t, err, "sa.GetValidAuthorizations2 failed")
	test.AssertEquals(t, len(authzs.Authz), 2)
	test.AssertEquals(t, *authzs.Authz[0].Domain, "aaa")
	test.AssertEquals(t, *authzs.Authz[0].Authz.Id, fmt.Sprintf("%d", ids.Ids[0]))
	test.AssertEquals(t, *authzs.Authz[1].Domain, "bbb")
	test.AssertEquals(t, *authzs.Authz[1].Authz.Id, oldPA.ID)
}

func TestDisableAuthz2Orders(t *testing.T) {
	if !strings.HasSuffix(os.Getenv("BOULDER_CONFIG_DIR"), "config-next") {
		return
	}

	sa, fc, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	exp := fc.Now().Add(time.Hour).UnixNano()
	v2 := true
	ident := "aaa"
	pending := string(core.StatusPending)
	expires := fc.Now().Add(time.Hour).UTC().UnixNano()
	challType := string(core.ChallengeTypeDNS01)
	token := "YXNkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	ids, err := sa.NewAuthorizations2(context.Background(), &sapb.AddPendingAuthorizationsRequest{Authz: []*corepb.Authorization{&corepb.Authorization{
		V2:             &v2,
		Identifier:     &ident,
		RegistrationID: &reg.ID,
		Status:         &pending,
		Expires:        &expires,
		Challenges: []*corepb.Challenge{
			{
				Status: &pending,
				Type:   &challType,
				Token:  &token,
			},
		},
	}}})
	test.AssertNotError(t, err, "sa.NewAuthorization failed")
	status := string(core.StatusValid)
	order, err := sa.NewOrder(context.Background(), &corepb.Order{
		RegistrationID:   &reg.ID,
		Expires:          &exp,
		Names:            []string{"aaa"},
		V2Authorizations: []int64{ids.Ids[0]},
		Status:           &status,
	})
	test.AssertNotError(t, err, "sa.NewOrder failed")

	useV2Authz := true
	_, err = sa.GetOrder(context.Background(), &sapb.OrderRequest{
		Id:                  order.Id,
		UseV2Authorizations: &useV2Authz,
	})
	test.AssertNotError(t, err, "GetOrder failed")

	_ = features.Set(map[string]bool{"DisableAuthz2Orders": true})
	useV2Authz = false
	_, err = sa.GetOrder(context.Background(), &sapb.OrderRequest{
		Id:                  order.Id,
		UseV2Authorizations: &useV2Authz,
	})
	test.AssertError(t, err, "GetOrder didn't fail with DisableAuthz2Orders enabled")
	test.Assert(t, berrors.Is(err, berrors.NotFound), "GetOrder error was not NotFound")
}
