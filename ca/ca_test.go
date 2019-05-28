package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/beeker1121/goque"
	cfsslConfig "github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer"
	"github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"

	"github.com/letsencrypt/boulder/ca/config"
	caPB "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/goodkey"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/test"
)

var (
	// * Random public key
	// * CN = not-example.com
	// * DNSNames = not-example.com, www.not-example.com
	CNandSANCSR = mustRead("./testdata/cn_and_san.der.csr")

	// CSR generated by Go:
	// * Random public key
	// * C = US
	// * CN = [none]
	// * DNSNames = not-example.com
	NoCNCSR = mustRead("./testdata/no_cn.der.csr")

	// CSR generated by Go:
	// * Random public key
	// * C = US
	// * CN = [none]
	// * DNSNames = [none]
	NoNameCSR = mustRead("./testdata/no_name.der.csr")

	// CSR generated by Go:
	// * Random public key
	// * CN = CapiTalizedLetters.com
	// * DNSNames = moreCAPs.com, morecaps.com, evenMOREcaps.com, Capitalizedletters.COM
	CapitalizedCSR = mustRead("./testdata/capitalized_cn_and_san.der.csr")

	// CSR generated by Go:
	// * Random public key
	// * CN = not-example.com
	// * Includes an extensionRequest attribute for a well-formed TLS Feature extension
	MustStapleCSR = mustRead("./testdata/must_staple.der.csr")

	// CSR generated by Go:
	// * Random public key
	// * CN = not-example.com
	// * Includes extensionRequest attributes for *two* must-staple extensions
	DuplicateMustStapleCSR = mustRead("./testdata/duplicate_must_staple.der.csr")

	// CSR generated by Go:
	// * Random public key
	// * CN = not-example.com
	// * Includes an extensionRequest attribute for an empty TLS Feature extension
	TLSFeatureUnknownCSR = mustRead("./testdata/tls_feature_unknown.der.csr")

	// CSR generated by Go:
	// * Random public key
	// * CN = not-example.com
	// * Includes an extensionRequest attribute for an unknown extension with an
	//   empty value. That extension's OID, 2.25.123456789, is on the UUID arc.
	//   It isn't a real randomly-generated UUID because Go represents the
	//   components of the OID as 32-bit integers, which aren't large enough to
	//   hold a real 128-bit UUID; this doesn't matter as far as what we're
	//   testing here is concerned.
	UnsupportedExtensionCSR = mustRead("./testdata/unsupported_extension.der.csr")

	// CSR generated by Go:
	// * Random public key
	// * CN = not-example.com
	// * Includes an extensionRequest attribute for the CT poison extension
	//   with a valid NULL value.
	CTPoisonExtensionCSR = mustRead("./testdata/ct_poison_extension.der.csr")

	// CSR generated by Go:
	// * Random public key
	// * CN = not-example.com
	// * Includes an extensionRequest attribute for the CT poison extension
	//   with an invalid empty value.
	CTPoisonExtensionEmptyCSR = mustRead("./testdata/ct_poison_extension_empty.der.csr")

	// CSR generated by Go:
	// * Random ECDSA public key.
	// * CN = [none]
	// * DNSNames = example.com, example2.com
	ECDSACSR = mustRead("./testdata/ecdsa.der.csr")

	log = blog.UseMock()

	// This is never modified, but it must be a var instead of a const so we can make references to it.
	arbitraryRegID int64 = 1001

	// OIDExtensionCTPoison is defined in RFC 6962 s3.1.
	OIDExtensionCTPoison = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

	// The "certificate-for-precertificate" tests use the precertificate from a
	// previous "precertificate" test, in order to verify that the CA is
	// stateless with respect to these two operations, since a separate CA
	// object instance will be used for generating each. Consequently, the
	// "precertificate" tests must be before the "certificate-for-precertificate"
	// tests in this list, and we cannot run these sub-tests concurrently.
	//
	// In order to test the case where the same CA object is used for issuing
	// both the precertificate and the certificate, we'd need to contort
	// |TestIssueCertificate| quite a bit, and since it isn't clear that that
	// would be useful, we've avoided adding that case, at least for now.
	issuanceModes = []IssuanceMode{
		{name: "precertificate", issueCertificateForPrecertificate: false},
		{name: "certificate-for-precertificate", issueCertificateForPrecertificate: true},
	}
)

// CFSSL config
const rsaProfileName = "rsaEE"
const ecdsaProfileName = "ecdsaEE"
const caKeyFile = "../test/test-ca.key"
const caCertFile = "../test/test-ca.pem"

func mustRead(path string) []byte {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("unable to read %#v: %s", path, err))
	}
	return b
}

type testCtx struct {
	caConfig  ca_config.CAConfig
	pa        core.PolicyAuthority
	issuers   []Issuer
	keyPolicy goodkey.KeyPolicy
	fc        clock.FakeClock
	stats     metrics.Scope
	logger    blog.Logger
}

type mockSA struct {
	certificate core.Certificate
}

func (m *mockSA) AddCertificate(ctx context.Context, der []byte, _ int64, _ []byte, _ *time.Time) (string, error) {
	m.certificate.DER = der
	return "", nil
}

var caKey crypto.Signer
var caCert *x509.Certificate
var ctx = context.Background()

func init() {
	var err error
	caKey, err = helpers.ParsePrivateKeyPEM(mustRead(caKeyFile))
	if err != nil {
		panic(fmt.Sprintf("Unable to parse %s: %s", caKeyFile, err))
	}
	caCert, err = core.LoadCert(caCertFile)
	if err != nil {
		panic(fmt.Sprintf("Unable to parse %s: %s", caCertFile, err))
	}
}

func setup(t *testing.T) *testCtx {
	fc := clock.NewFake()
	fc.Add(1 * time.Hour)

	pa, err := policy.New(nil)
	test.AssertNotError(t, err, "Couldn't create PA")
	err = pa.SetHostnamePolicyFile("../test/hostname-policy.yaml")
	test.AssertNotError(t, err, "Couldn't set hostname policy")

	allowedExtensions := []cfsslConfig.OID{
		cfsslConfig.OID(oidTLSFeature),
		cfsslConfig.OID(OIDExtensionCTPoison),
	}

	// Create a CA
	caConfig := ca_config.CAConfig{
		RSAProfile:   rsaProfileName,
		ECDSAProfile: ecdsaProfileName,
		SerialPrefix: 17,
		Expiry:       "8760h",
		// TODO(briansmith): When the defaulting of Backdate is removed, this
		// will need to be uncommented. Leave it commented for now to test the
		// defaulting logic.
		// Backdate:     cmd.ConfigDuration{Duration: time.Hour},
		LifespanOCSP: cmd.ConfigDuration{Duration: 45 * time.Minute},
		MaxNames:     2,
		CFSSL: cfsslConfig.Config{
			Signing: &cfsslConfig.Signing{
				Profiles: map[string]*cfsslConfig.SigningProfile{
					rsaProfileName: {
						Usage:     []string{"digital signature", "key encipherment", "server auth"},
						IssuerURL: []string{"http://not-example.com/issuer-url"},
						OCSP:      "http://not-example.com/ocsp",
						CRL:       "http://not-example.com/crl",

						Policies: []cfsslConfig.CertificatePolicy{
							{
								ID: cfsslConfig.OID(asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}),
							},
						},
						ExpiryString: "8760h",
						Backdate:     time.Hour,
						CSRWhitelist: &cfsslConfig.CSRWhitelist{
							PublicKeyAlgorithm: true,
							PublicKey:          true,
							SignatureAlgorithm: true,
						},
						ClientProvidesSerialNumbers: true,
						AllowedExtensions:           allowedExtensions,
					},
					ecdsaProfileName: {
						Usage:     []string{"digital signature", "server auth"},
						IssuerURL: []string{"http://not-example.com/issuer-url"},
						OCSP:      "http://not-example.com/ocsp",
						CRL:       "http://not-example.com/crl",

						Policies: []cfsslConfig.CertificatePolicy{
							{
								ID: cfsslConfig.OID(asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}),
							},
						},
						ExpiryString: "8760h",
						Backdate:     time.Hour,
						CSRWhitelist: &cfsslConfig.CSRWhitelist{
							PublicKeyAlgorithm: true,
							PublicKey:          true,
							SignatureAlgorithm: true,
						},
						ClientProvidesSerialNumbers: true,
						AllowedExtensions:           allowedExtensions,
					},
				},
				Default: &cfsslConfig.SigningProfile{
					ExpiryString: "8760h",
				},
			},
		},
	}

	issuers := []Issuer{{caKey, caCert}}

	keyPolicy := goodkey.KeyPolicy{
		AllowRSA:           true,
		AllowECDSANISTP256: true,
		AllowECDSANISTP384: true,
	}

	logger := blog.NewMock()

	return &testCtx{
		caConfig,
		pa,
		issuers,
		keyPolicy,
		fc,
		metrics.NewNoopScope(),
		logger,
	}
}

func TestFailNoSerial(t *testing.T) {
	testCtx := setup(t)

	testCtx.caConfig.SerialPrefix = 0
	_, err := NewCertificateAuthorityImpl(
		testCtx.caConfig,
		nil,
		nil,
		testCtx.fc,
		testCtx.stats,
		testCtx.issuers,
		testCtx.keyPolicy,
		testCtx.logger,
		nil)
	test.AssertError(t, err, "CA should have failed with no SerialPrefix")
}

type TestCertificateIssuance struct {
	ca      *CertificateAuthorityImpl
	sa      *mockSA
	req     *x509.CertificateRequest
	mode    IssuanceMode
	certDER []byte
	cert    *x509.Certificate
}

type IssuanceMode struct {
	name                              string
	issueCertificateForPrecertificate bool
}

func TestIssuePrecertificate(t *testing.T) {
	testCases := []struct {
		name    string
		csr     []byte
		subTest func(t *testing.T, i *TestCertificateIssuance)
	}{
		{"IssuePrecertificate", CNandSANCSR, issueCertificateSubTestIssuePrecertificate},
		{"ValidityUsesCAClock", CNandSANCSR, issueCertificateSubTestValidityUsesCAClock},
		{"AllowNoCN", NoCNCSR, issueCertificateSubTestAllowNoCN},
		{"ProfileSelectionRSA", CNandSANCSR, issueCertificateSubTestProfileSelectionRSA},
		{"ProfileSelectionECDSA", ECDSACSR, issueCertificateSubTestProfileSelectionECDSA},
		{"MustStaple", MustStapleCSR, issueCertificateSubTestMustStaple},
		{"MustStapleDuplicate", DuplicateMustStapleCSR, issueCertificateSubTestMustStaple},
		{"UnknownExtension", UnsupportedExtensionCSR, issueCertificateSubTestUnknownExtension},
		{"CTPoisonExtension", CTPoisonExtensionCSR, issueCertificateSubTestCTPoisonExtension},
		{"CTPoisonExtensionEmpty", CTPoisonExtensionEmptyCSR, issueCertificateSubTestCTPoisonExtension},
	}

	for _, testCase := range testCases {
		// The loop through |issuanceModes| must be inside the loop through
		// |testCases| because the "certificate-for-precertificate" tests use
		// the precertificates previously generated from the preceding
		// "precertificate" test. See also the comment above |issuanceModes|.
		for _, mode := range issuanceModes {
			ca, sa := issueCertificateSubTestSetup(t)

			t.Run(mode.name+"-"+testCase.name, func(t *testing.T) {
				req, err := x509.ParseCertificateRequest(testCase.csr)
				test.AssertNotError(t, err, "Certificate request failed to parse")

				issueReq := &caPB.IssueCertificateRequest{Csr: testCase.csr, RegistrationID: &arbitraryRegID}

				var certDER []byte
				response, err := ca.IssuePrecertificate(ctx, issueReq)

				test.AssertNotError(t, err, "Failed to issue precertificate")
				certDER = response.DER

				cert, err := x509.ParseCertificate(certDER)
				test.AssertNotError(t, err, "Certificate failed to parse")

				poisonExtension := findExtension(cert.Extensions, OIDExtensionCTPoison)
				test.AssertEquals(t, true, poisonExtension != nil)
				if poisonExtension != nil {
					test.AssertEquals(t, poisonExtension.Critical, true)
					test.AssertDeepEquals(t, poisonExtension.Value, []byte{0x05, 0x00}) // ASN.1 DER NULL
				}

				i := TestCertificateIssuance{
					ca:      ca,
					sa:      sa,
					req:     req,
					mode:    mode,
					certDER: certDER,
					cert:    cert,
				}

				testCase.subTest(t, &i)
			})
		}
	}
}

func issueCertificateSubTestSetup(t *testing.T) (*CertificateAuthorityImpl, *mockSA) {
	testCtx := setup(t)
	sa := &mockSA{}
	ca, err := NewCertificateAuthorityImpl(
		testCtx.caConfig,
		sa,
		testCtx.pa,
		testCtx.fc,
		testCtx.stats,
		testCtx.issuers,
		testCtx.keyPolicy,
		testCtx.logger,
		nil)
	test.AssertNotError(t, err, "Failed to create CA")
	ca.forceCNFromSAN = false

	return ca, sa
}

func issueCertificateSubTestIssuePrecertificate(t *testing.T, i *TestCertificateIssuance) {
	cert := i.cert

	test.AssertEquals(t, cert.Subject.CommonName, "not-example.com")

	if len(cert.DNSNames) == 1 {
		if cert.DNSNames[0] != "not-example.com" {
			t.Errorf("Improper list of domain names %v", cert.DNSNames)
		} else {
		}
		t.Errorf("Improper list of domain names %v", cert.DNSNames)
	}

	if len(cert.Subject.Country) > 0 {
		t.Errorf("Subject contained unauthorized values: %v", cert.Subject)
	}

	serialString := core.SerialToString(cert.SerialNumber)
	if cert.Subject.SerialNumber != serialString {
		t.Errorf("SerialNumber: want %#v, got %#v", serialString, cert.Subject.SerialNumber)
	}
}

func issueCertificateSubTestValidityUsesCAClock(t *testing.T, i *TestCertificateIssuance) {
	test.AssertEquals(t, i.cert.NotBefore, i.ca.clk.Now().Add(-1*i.ca.backdate))
	test.AssertEquals(t, i.cert.NotAfter, i.cert.NotBefore.Add(i.ca.validityPeriod))
}

// Test issuing when multiple issuers are present.
func TestMultipleIssuers(t *testing.T) {
	testCtx := setup(t)
	// Load multiple issuers, and ensure the first one in the list is used.
	newIssuerCert, err := core.LoadCert("../test/test-ca2.pem")
	test.AssertNotError(t, err, "Failed to load new cert")
	newIssuers := []Issuer{
		{
			Signer: caKey,
			// newIssuerCert is first, so it will be the default.
			Cert: newIssuerCert,
		}, {
			Signer: caKey,
			Cert:   caCert,
		},
	}
	sa := &mockSA{}
	ca, err := NewCertificateAuthorityImpl(
		testCtx.caConfig,
		sa,
		testCtx.pa,
		testCtx.fc,
		testCtx.stats,
		newIssuers,
		testCtx.keyPolicy,
		testCtx.logger,
		nil)
	test.AssertNotError(t, err, "Failed to remake CA")

	issuedCert, err := ca.IssuePrecertificate(ctx, &caPB.IssueCertificateRequest{Csr: CNandSANCSR, RegistrationID: &arbitraryRegID})
	test.AssertNotError(t, err, "Failed to issue certificate")

	cert, err := x509.ParseCertificate(issuedCert.DER)
	test.AssertNotError(t, err, "Certificate failed to parse")
	// Verify cert was signed by newIssuerCert, not caCert.
	err = cert.CheckSignatureFrom(newIssuerCert)
	test.AssertNotError(t, err, "Certificate failed signature validation")
}

func TestOCSP(t *testing.T) {
	testCtx := setup(t)
	sa := &mockSA{}
	ca, err := NewCertificateAuthorityImpl(
		testCtx.caConfig,
		sa,
		testCtx.pa,
		testCtx.fc,
		testCtx.stats,
		testCtx.issuers,
		testCtx.keyPolicy,
		testCtx.logger,
		nil)
	test.AssertNotError(t, err, "Failed to create CA")

	issueReq := caPB.IssueCertificateRequest{Csr: CNandSANCSR, RegistrationID: &arbitraryRegID}

	cert, err := ca.IssuePrecertificate(ctx, &issueReq)
	test.AssertNotError(t, err, "Failed to issue")
	parsedCert, err := x509.ParseCertificate(cert.DER)
	test.AssertNotError(t, err, "Failed to parse cert")
	ocspResp, err := ca.GenerateOCSP(ctx, core.OCSPSigningRequest{
		CertDER: cert.DER,
		Status:  string(core.OCSPStatusGood),
	})
	test.AssertNotError(t, err, "Failed to generate OCSP")
	parsed, err := ocsp.ParseResponse(ocspResp, caCert)
	test.AssertNotError(t, err, "Failed to parse validate OCSP")
	test.AssertEquals(t, parsed.Status, 0)
	test.AssertEquals(t, parsed.RevocationReason, 0)
	test.AssertEquals(t, parsed.SerialNumber.Cmp(parsedCert.SerialNumber), 0)

	// Test that signatures are checked.
	_, err = ca.GenerateOCSP(ctx, core.OCSPSigningRequest{
		CertDER: append(cert.DER, byte(0)),
		Status:  string(core.OCSPStatusGood),
	})
	test.AssertError(t, err, "Generated OCSP for cert with bad signature")

	// Load multiple issuers, including the old issuer, and ensure OCSP is still
	// signed correctly.
	newIssuerCert, err := core.LoadCert("../test/test-ca2.pem")
	test.AssertNotError(t, err, "Failed to load new cert")
	newIssuers := []Issuer{
		{
			Signer: caKey,
			// newIssuerCert is first, so it will be the default.
			Cert: newIssuerCert,
		}, {
			Signer: caKey,
			Cert:   caCert,
		},
	}
	ca, err = NewCertificateAuthorityImpl(
		testCtx.caConfig,
		sa,
		testCtx.pa,
		testCtx.fc,
		testCtx.stats,
		newIssuers,
		testCtx.keyPolicy,
		testCtx.logger,
		nil)
	test.AssertNotError(t, err, "Failed to remake CA")

	// Now issue a new precert, signed by newIssuerCert
	newCert, err := ca.IssuePrecertificate(ctx, &issueReq)
	test.AssertNotError(t, err, "Failed to issue newCert")
	parsedNewCert, err := x509.ParseCertificate(newCert.DER)
	test.AssertNotError(t, err, "Failed to parse newCert")

	err = parsedNewCert.CheckSignatureFrom(newIssuerCert)
	t.Logf("check sig: %s", err)

	// ocspResp2 is a second OCSP response for `cert` (issued by caCert), and
	// should be signed by caCert.
	ocspResp2, err := ca.GenerateOCSP(ctx, core.OCSPSigningRequest{
		CertDER: append(cert.DER),
		Status:  string(core.OCSPStatusGood),
	})
	test.AssertNotError(t, err, "Failed to sign second OCSP response")
	_, err = ocsp.ParseResponse(ocspResp2, caCert)
	test.AssertNotError(t, err, "Failed to parse / validate second OCSP response")

	// newCertOcspResp is an OCSP response for `newCert` (issued by newIssuer),
	// and should be signed by newIssuer.
	newCertOcspResp, err := ca.GenerateOCSP(ctx, core.OCSPSigningRequest{
		CertDER: newCert.DER,
		Status:  string(core.OCSPStatusGood),
	})
	test.AssertNotError(t, err, "Failed to generate OCSP")
	parsedNewCertOcspResp, err := ocsp.ParseResponse(newCertOcspResp, newIssuerCert)
	test.AssertNotError(t, err, "Failed to parse / validate OCSP for newCert")
	test.AssertEquals(t, parsedNewCertOcspResp.Status, 0)
	test.AssertEquals(t, parsedNewCertOcspResp.RevocationReason, 0)
	test.AssertEquals(t, parsedNewCertOcspResp.SerialNumber.Cmp(parsedNewCert.SerialNumber), 0)
}

func TestInvalidCSRs(t *testing.T) {
	testCases := []struct {
		name         string
		csrPath      string
		check        func(t *testing.T, ca *CertificateAuthorityImpl, sa *mockSA)
		errorMessage string
	}{
		// Test that the CA rejects CSRs that have no names.
		//
		// CSR generated by Go:
		// * Random RSA public key.
		// * CN = [none]
		// * DNSNames = [none]
		{"RejectNoHostnames", "./testdata/no_names.der.csr", nil, "Issued certificate with no names"},

		// Test that the CA rejects CSRs that have too many names.
		//
		// CSR generated by Go:
		// * Random public key
		// * CN = [none]
		// * DNSNames = not-example.com, www.not-example.com, mail.example.com
		{"RejectTooManyHostnames", "./testdata/too_many_names.der.csr", nil, "Issued certificate with too many names"},

		// Test that the CA rejects CSRs that have public keys that are too short.
		//
		// CSR generated by Go:
		// * Random public key -- 512 bits long
		// * CN = (none)
		// * DNSNames = not-example.com, www.not-example.com, mail.not-example.com
		{"RejectShortKey", "./testdata/short_key.der.csr", nil, "Issued a certificate with too short a key."},

		// CSR generated by Go:
		// * Random RSA public key.
		// * CN = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com
		// * DNSNames = [none]
		{"RejectLongCommonName", "./testdata/long_cn.der.csr", nil, "Issued a certificate with a CN over 64 bytes."},

		// CSR generated by OpenSSL:
		// Edited signature to become invalid.
		{"RejectWrongSignature", "./testdata/invalid_signature.der.csr", nil, "Issued a certificate based on a CSR with an invalid signature."},

		// CSR generated by Go:
		// * Random public key
		// * CN = not-example.com
		// * Includes an extensionRequest attribute for an empty TLS Feature extension
		{"TLSFeatureUnknown", "./testdata/tls_feature_unknown.der.csr", issueCertificateSubTestTLSFeatureUnknown, "Issued a certificate based on a CSR with an empty TLS feature extension."},
	}

	for _, testCase := range testCases {
		testCtx := setup(t)
		sa := &mockSA{}
		ca, err := NewCertificateAuthorityImpl(
			testCtx.caConfig,
			sa,
			testCtx.pa,
			testCtx.fc,
			testCtx.stats,
			testCtx.issuers,
			testCtx.keyPolicy,
			testCtx.logger,
			nil)
		test.AssertNotError(t, err, "Failed to create CA")

		t.Run(testCase.name, func(t *testing.T) {
			serializedCSR := mustRead(testCase.csrPath)
			issueReq := &caPB.IssueCertificateRequest{Csr: serializedCSR, RegistrationID: &arbitraryRegID}
			_, err = ca.IssuePrecertificate(ctx, issueReq)

			test.Assert(t, berrors.Is(err, berrors.Malformed), "Incorrect error type returned")
			test.AssertEquals(t, signatureCountByPurpose("cert", ca.signatureCount), 0)

			test.AssertError(t, err, testCase.errorMessage)
			if testCase.check != nil {
				testCase.check(t, ca, sa)
			}
		})
	}
}

func TestRejectValidityTooLong(t *testing.T) {
	testCtx := setup(t)
	sa := &mockSA{}
	ca, err := NewCertificateAuthorityImpl(
		testCtx.caConfig,
		sa,
		testCtx.pa,
		testCtx.fc,
		testCtx.stats,
		testCtx.issuers,
		testCtx.keyPolicy,
		testCtx.logger,
		nil)
	test.AssertNotError(t, err, "Failed to create CA")

	// This time is a few minutes before the notAfter in testdata/ca_cert.pem
	future, err := time.Parse(time.RFC3339, "2025-02-10T00:30:00Z")

	test.AssertNotError(t, err, "Failed to parse time")
	testCtx.fc.Set(future)
	// Test that the CA rejects CSRs that would expire after the intermediate cert
	_, err = ca.IssuePrecertificate(ctx, &caPB.IssueCertificateRequest{Csr: NoCNCSR, RegistrationID: &arbitraryRegID})
	test.AssertError(t, err, "Cannot issue a certificate that expires after the intermediate certificate")
	test.Assert(t, berrors.Is(err, berrors.InternalServer), "Incorrect error type returned")
}

func TestSingleAIAEnforcement(t *testing.T) {
	pa, err := policy.New(nil)
	test.AssertNotError(t, err, "Couldn't create PA")

	_, err = NewCertificateAuthorityImpl(
		ca_config.CAConfig{
			SerialPrefix: 1,
			LifespanOCSP: cmd.ConfigDuration{Duration: time.Second},
			CFSSL: cfsslConfig.Config{
				Signing: &cfsslConfig.Signing{
					Profiles: map[string]*cfsslConfig.SigningProfile{
						rsaProfileName: {
							IssuerURL: []string{"http://not-example.com/issuer-url", "bad"},
							Usage:     []string{"digital signature", "key encipherment", "server auth"},
							OCSP:      "http://not-example.com/ocsp",
							CRL:       "http://not-example.com/crl",
							Policies: []cfsslConfig.CertificatePolicy{
								{
									ID: cfsslConfig.OID(asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}),
								},
							},
							ExpiryString: "8760h",
							Backdate:     time.Hour,
							CSRWhitelist: &cfsslConfig.CSRWhitelist{
								PublicKeyAlgorithm: true,
								PublicKey:          true,
								SignatureAlgorithm: true,
							},
							ClientProvidesSerialNumbers: true,
						},
					},
				},
			},
		},
		&mockSA{},
		pa,
		clock.New(),
		metrics.NewNoopScope(),
		nil,
		goodkey.KeyPolicy{},
		&blog.Mock{},
		nil,
	)
	test.AssertError(t, err, "NewCertificateAuthorityImpl allowed a profile with multiple issuer_urls")
	test.AssertEquals(t, err.Error(), "only one issuer_url supported")
}

func issueCertificateSubTestAllowNoCN(t *testing.T, i *TestCertificateIssuance) {
	cert := i.cert

	if cert.Subject.CommonName != "" {
		t.Errorf("want no CommonName, got %#v", cert.Subject.CommonName)
	}
	serial := core.SerialToString(cert.SerialNumber)
	if cert.Subject.SerialNumber != serial {
		t.Errorf("SerialNumber: want %#v, got %#v", serial, cert.Subject.SerialNumber)
	}

	expected := []string{}
	for _, name := range i.req.DNSNames {
		expected = append(expected, name)
	}
	sort.Strings(expected)
	actual := []string{}
	for _, name := range cert.DNSNames {
		actual = append(actual, name)
	}
	sort.Strings(actual)
	test.AssertDeepEquals(t, actual, expected)
}

func issueCertificateSubTestProfileSelectionRSA(t *testing.T, i *TestCertificateIssuance) {
	// Certificates for RSA keys should be marked as usable for signatures and encryption.
	expectedKeyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	t.Logf("expected key usage %v, got %v", expectedKeyUsage, i.cert.KeyUsage)
	test.AssertEquals(t, i.cert.KeyUsage, expectedKeyUsage)
}

func issueCertificateSubTestProfileSelectionECDSA(t *testing.T, i *TestCertificateIssuance) {
	// Certificates for ECDSA keys should be marked as usable for only signatures.
	expectedKeyUsage := x509.KeyUsageDigitalSignature
	t.Logf("expected key usage %v, got %v", expectedKeyUsage, i.cert.KeyUsage)
	test.AssertEquals(t, i.cert.KeyUsage, expectedKeyUsage)
}

func countMustStaple(t *testing.T, cert *x509.Certificate) (count int) {
	oidTLSFeature := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidTLSFeature) {
			test.Assert(t, !ext.Critical, "Extension was marked critical")
			test.AssertByteEquals(t, ext.Value, mustStapleFeatureValue)
			count++
		}
	}
	return count
}

func issueCertificateSubTestMustStaple(t *testing.T, i *TestCertificateIssuance) {
	// a TLS feature extension should put a must-staple extension into the cert. Even
	// if there are multiple TLS Feature extensions, only one extension should be included.
	test.AssertEquals(t, test.CountCounterVec(csrExtensionCategory, csrExtensionTLSFeature, i.ca.csrExtensionCount), 1)
	test.AssertEquals(t, test.CountCounterVec(csrExtensionCategory, csrExtensionTLSFeatureInvalid, i.ca.csrExtensionCount), 0)
	test.AssertEquals(t, signatureCountByPurpose("precertificate", i.ca.signatureCount), 1)
	test.AssertEquals(t, countMustStaple(t, i.cert), 1)
}

func issueCertificateSubTestTLSFeatureUnknown(t *testing.T, ca *CertificateAuthorityImpl, _ *mockSA) {
	test.AssertEquals(t, test.CountCounterVec(csrExtensionCategory, csrExtensionTLSFeature, ca.csrExtensionCount), 1)
	test.AssertEquals(t, test.CountCounterVec(csrExtensionCategory, csrExtensionTLSFeatureInvalid, ca.csrExtensionCount), 1)
}

func issueCertificateSubTestUnknownExtension(t *testing.T, i *TestCertificateIssuance) {
	// Unsupported extensions in the CSR should be silently ignored.
	test.AssertEquals(t, test.CountCounterVec(csrExtensionCategory, csrExtensionOther, i.ca.csrExtensionCount), 1)
	test.AssertEquals(t, signatureCountByPurpose("precertificate", i.ca.signatureCount), 1)

	// NOTE: The hard-coded value here will have to change over time as Boulder
	// adds new (unrequested) extensions to certificates.
	expectedExtensionCount := 10
	test.AssertEquals(t, len(i.cert.Extensions), expectedExtensionCount)
}

func issueCertificateSubTestCTPoisonExtension(t *testing.T, i *TestCertificateIssuance) {
	// The CT poison extension in the CSR should be silently ignored like an
	// unknown extension, whether it has a valid or invalid value. The check
	// for whether or not the poison extension is present in the issued
	// certificate/precertificate is done in the caller.
	test.AssertEquals(t, test.CountCounterVec(csrExtensionCategory, csrExtensionOther, i.ca.csrExtensionCount), 1)
	test.AssertEquals(t, signatureCountByPurpose("precertificate", i.ca.signatureCount), 1)
}

func findExtension(extensions []pkix.Extension, id asn1.ObjectIdentifier) *pkix.Extension {
	for _, ext := range extensions {
		if ext.Id.Equal(id) {
			return &ext
		}
	}
	return nil
}

func signatureCountByPurpose(signatureType string, signatureCount *prometheus.CounterVec) int {
	return test.CountCounterVec("purpose", signatureType, signatureCount)
}

func TestIssueCertificateForPrecertificate(t *testing.T) {
	testCtx := setup(t)
	sa := &mockSA{}
	ca, err := NewCertificateAuthorityImpl(
		testCtx.caConfig,
		sa,
		testCtx.pa,
		testCtx.fc,
		testCtx.stats,
		testCtx.issuers,
		testCtx.keyPolicy,
		testCtx.logger,
		nil)
	test.AssertNotError(t, err, "Failed to create CA")

	orderID := int64(0)
	issueReq := caPB.IssueCertificateRequest{Csr: CNandSANCSR, RegistrationID: &arbitraryRegID, OrderID: &orderID}
	precert, err := ca.IssuePrecertificate(ctx, &issueReq)
	test.AssertNotError(t, err, "Failed to issue precert")
	parsedPrecert, err := x509.ParseCertificate(precert.DER)
	test.AssertNotError(t, err, "Failed to parse precert")

	// Check for poison extension
	poisoned := false
	for _, ext := range parsedPrecert.Extensions {
		if ext.Id.Equal(signer.CTPoisonOID) && ext.Critical {
			poisoned = true
		}
	}
	test.Assert(t, poisoned, "returned precert not poisoned")

	sct := ct.SignedCertificateTimestamp{
		SCTVersion: 0,
		Timestamp:  2020,
		Signature: ct.DigitallySigned{
			Signature: []byte{0},
		},
	}
	sctBytes, err := cttls.Marshal(sct)
	test.AssertNotError(t, err, "Failed to marshal SCT")
	cert, err := ca.IssueCertificateForPrecertificate(ctx, &caPB.IssueCertificateForPrecertificateRequest{
		DER:            precert.DER,
		SCTs:           [][]byte{sctBytes},
		RegistrationID: &arbitraryRegID,
		OrderID:        new(int64),
	})
	test.AssertNotError(t, err, "Failed to issue cert from precert")
	parsedCert, err := x509.ParseCertificate(cert.DER)
	test.AssertNotError(t, err, "Failed to parse cert")

	// Check for SCT list extension
	list := false
	for _, ext := range parsedCert.Extensions {
		if ext.Id.Equal(signer.SCTListOID) && !ext.Critical {
			list = true
			var rawValue []byte
			_, err = asn1.Unmarshal(ext.Value, &rawValue)
			test.AssertNotError(t, err, "Failed to unmarshal extension value")
			sctList, err := helpers.DeserializeSCTList(rawValue)
			test.AssertNotError(t, err, "Failed to deserialize SCT list")
			test.Assert(t, len(sctList) == 1, fmt.Sprintf("Wrong number of SCTs, wanted: 1, got: %d", len(sctList)))
		}
	}
	test.Assert(t, list, "returned cert doesn't contain SCT list")
}

type queueSA struct {
	fail      bool
	duplicate bool

	issued *time.Time
}

func (qsa *queueSA) AddCertificate(_ context.Context, _ []byte, _ int64, _ []byte, issued *time.Time) (string, error) {
	if qsa.fail {
		return "", errors.New("bad")
	} else if qsa.duplicate {
		return "", berrors.DuplicateError("is a dupe")
	}
	qsa.issued = issued
	return "", nil
}

func TestOrphanQueue(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "orphan-queue-tmp")
	defer os.Remove(tmpDir)
	test.AssertNotError(t, err, "Failed to create temp directory")
	orphanQueue, err := goque.OpenQueue(tmpDir)
	test.AssertNotError(t, err, "Failed to open orphaned certificate queue")

	qsa := &queueSA{fail: true}
	testCtx := setup(t)
	ca, err := NewCertificateAuthorityImpl(
		testCtx.caConfig,
		qsa,
		testCtx.pa,
		testCtx.fc,
		testCtx.stats,
		testCtx.issuers,
		testCtx.keyPolicy,
		testCtx.logger,
		orphanQueue)
	test.AssertNotError(t, err, "Failed to create CA")

	err = ca.integrateOrphan()
	if err != goque.ErrEmpty {
		t.Fatalf("Unexpected error, wanted %q, got %q", goque.ErrEmpty, err)
	}

	// generate basic test cert
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "Failed to generate test key")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"test.invalid"},
		NotBefore:    time.Time{}.Add(time.Hour * 24),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	test.AssertNotError(t, err, "Failed to generate test cert")
	_, err = ca.generateOCSPAndStoreCertificate(
		context.Background(),
		1,
		1,
		tmpl.SerialNumber,
		certDER,
	)
	test.AssertError(t, err, "generateOCSPAndStoreCertificate didn't fail when AddCertificate failed")

	qsa.fail = false
	err = ca.integrateOrphan()
	test.AssertNotError(t, err, "integrateOrphan failed")
	test.AssertEquals(t, *qsa.issued, time.Time{}.Add(time.Hour*24).Add(-time.Hour))
	err = ca.integrateOrphan()
	if err != goque.ErrEmpty {
		t.Fatalf("Unexpected error, wanted %q, got %q", goque.ErrEmpty, err)
	}

	// test with a duplicate cert
	ca.queueOrphan(&orphanedCert{
		DER:      certDER,
		OCSPResp: []byte{},
		RegID:    1,
	})

	qsa.duplicate = true
	err = ca.integrateOrphan()
	test.AssertNotError(t, err, "integrateOrphan failed with duplicate cert")
	test.AssertEquals(t, *qsa.issued, time.Time{}.Add(time.Hour*24).Add(-time.Hour))
	err = ca.integrateOrphan()
	if err != goque.ErrEmpty {
		t.Fatalf("Unexpected error, wanted %q, got %q", goque.ErrEmpty, err)
	}

	// add cert to queue, and recreate queue to make sure it still has the cert
	qsa.fail = true
	qsa.duplicate = false
	_, err = ca.generateOCSPAndStoreCertificate(
		context.Background(),
		1,
		1,
		tmpl.SerialNumber,
		certDER,
	)
	test.AssertError(t, err, "generateOCSPAndStoreCertificate didn't fail when AddCertificate failed")
	err = orphanQueue.Close()
	test.AssertNotError(t, err, "Failed to close the queue cleanly")
	orphanQueue, err = goque.OpenQueue(tmpDir)
	test.AssertNotError(t, err, "Failed to open orphaned certificate queue")
	defer func() { _ = orphanQueue.Close() }()
	ca.orphanQueue = orphanQueue

	qsa.fail = false
	err = ca.integrateOrphan()
	test.AssertNotError(t, err, "integrateOrphan failed")
	test.AssertEquals(t, *qsa.issued, time.Time{}.Add(time.Hour*24).Add(-time.Hour))
	err = ca.integrateOrphan()
	if err != goque.ErrEmpty {
		t.Fatalf("Unexpected error, wanted %q, got %q", goque.ErrEmpty, err)
	}
}
