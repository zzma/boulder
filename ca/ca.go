package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/zzma/boulder/cmd"
	"math/big"
	"strings"
	"time"

	"github.com/beeker1121/goque"
	cfsslConfig "github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/ocsp"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	"github.com/jmhodges/clock"
	"github.com/miekg/pkcs11"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/zzma/boulder/ca/config"
	caPB "github.com/zzma/boulder/ca/proto"
	"github.com/zzma/boulder/core"
	csrlib "github.com/zzma/boulder/csr"
	berrors "github.com/zzma/boulder/errors"
	"github.com/zzma/boulder/goodkey"
	blog "github.com/zzma/boulder/log"
	"github.com/zzma/boulder/metrics"
)

// Miscellaneous PKIX OIDs that we need to refer to
var (
	// X.509 Extensions
	oidAuthorityInfoAccess    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidBasicConstraints       = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidCertificatePolicies    = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidCrlDistributionPoints  = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidExtKeyUsage            = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidKeyUsage               = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidSubjectAltName         = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidSubjectKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidTLSFeature             = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

	// CSR attribute requesting extensions
	oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
)

// OID and fixed value for the "must staple" variant of the TLS Feature
// extension:
//
//  Features ::= SEQUENCE OF INTEGER                  [RFC7633]
//  enum { ... status_request(5) ...} ExtensionType;  [RFC6066]
//
// DER Encoding:
//  30 03 - SEQUENCE (3 octets)
//  |-- 02 01 - INTEGER (1 octet)
//  |   |-- 05 - 5
var (
	mustStapleFeatureValue = []byte{0x30, 0x03, 0x02, 0x01, 0x05}
	mustStapleExtension    = signer.Extension{
		ID:       cfsslConfig.OID(oidTLSFeature),
		Critical: false,
		Value:    hex.EncodeToString(mustStapleFeatureValue),
	}

	// https://tools.ietf.org/html/rfc6962#section-3.1
	ctPoisonExtension = signer.Extension{
		ID:       cfsslConfig.OID(signer.CTPoisonOID),
		Critical: true,
		Value:    "0500", // ASN.1 DER NULL, Hex encoded.
	}
)

// Metrics for CA statistics
const (
	// Increments when CA observes an HSM or signing error
	metricSigningError = "SigningError"
	metricHSMError     = metricSigningError + ".HSMError"

	csrExtensionCategory          = "category"
	csrExtensionBasic             = "basic"
	csrExtensionTLSFeature        = "tls-feature"
	csrExtensionTLSFeatureInvalid = "tls-feature-invalid"
	csrExtensionOther             = "other"
)

type certificateStorage interface {
	AddCertificate(context.Context, []byte, int64, []byte, *time.Time) (string, error)
}

type certificateType string

const (
	precertType = certificateType("precertificate")
	certType    = certificateType("certificate")
)

// CertificateAuthorityImpl represents a CA that signs certificates, CRLs, and
// OCSP responses.
type CertificateAuthorityImpl struct {
	configPath   string
	rsaProfile   string
	ecdsaProfile string
	// A map from issuer cert common name to an internalIssuer struct
	issuers map[string]*internalIssuer
	// The common name of the default issuer cert
	defaultIssuer     *internalIssuer
	sa                certificateStorage
	pa                core.PolicyAuthority
	keyPolicy         goodkey.KeyPolicy
	clk               clock.Clock
	log               blog.Logger
	stats             metrics.Scope
	prefix            int // Prepended to the serial number
	validityPeriod    time.Duration
	backdate          time.Duration
	maxNames          int
	forceCNFromSAN    bool
	signatureCount    *prometheus.CounterVec
	csrExtensionCount *prometheus.CounterVec
	orphanQueue       *goque.Queue
}

// Issuer represents a single issuer certificate, along with its key.
type Issuer struct {
	Signer crypto.Signer
	Cert   *x509.Certificate
}

// internalIssuer represents the fully initialized internal state for a single
// issuer, including the cfssl signer and OCSP signer objects.
type internalIssuer struct {
	cert       *x509.Certificate
	eeSigner   *local.Signer
	ocspSigner ocsp.Signer
}

// Hacky-copy of struct from boulder-ca/main.go
type config struct {
	CA ca_config.CAConfig

	PA cmd.PAConfig

	Syslog cmd.SyslogConfig
}

func makeInternalIssuers(
	issuers []Issuer,
	policy *cfsslConfig.Signing,
	lifespanOCSP time.Duration,
) (map[string]*internalIssuer, error) {
	if len(issuers) == 0 {
		return nil, errors.New("No issuers specified.")
	}
	internalIssuers := make(map[string]*internalIssuer)
	for _, iss := range issuers {
		if iss.Cert == nil || iss.Signer == nil {
			return nil, errors.New("Issuer with nil cert or signer specified.")
		}
		eeSigner, err := local.NewSigner(iss.Signer, iss.Cert, x509.SHA256WithRSA, policy)
		if err != nil {
			return nil, err
		}

		// Set up our OCSP signer. Note this calls for both the issuer cert and the
		// OCSP signing cert, which are the same in our case.
		ocspSigner, err := ocsp.NewSigner(iss.Cert, iss.Cert, iss.Signer, lifespanOCSP)
		if err != nil {
			return nil, err
		}
		cn := iss.Cert.Subject.CommonName
		if internalIssuers[cn] != nil {
			return nil, errors.New("Multiple issuer certs with the same CommonName are not supported")
		}
		internalIssuers[cn] = &internalIssuer{
			cert:       iss.Cert,
			eeSigner:   eeSigner,
			ocspSigner: ocspSigner,
		}
	}
	return internalIssuers, nil
}

// NewCertificateAuthorityImpl creates a CA instance that can sign certificates
// from a single issuer (the first first in the issuers slice), and can sign OCSP
// for any of the issuer certificates provided.
func NewCertificateAuthorityImpl(
	configPath string,
	config ca_config.CAConfig,
	sa certificateStorage,
	pa core.PolicyAuthority,
	clk clock.Clock,
	stats metrics.Scope,
	issuers []Issuer,
	keyPolicy goodkey.KeyPolicy,
	logger blog.Logger,
	orphanQueue *goque.Queue,
) (*CertificateAuthorityImpl, error) {
	var ca *CertificateAuthorityImpl
	var err error

	if config.SerialPrefix <= 0 || config.SerialPrefix >= 256 {
		err = errors.New("Must have a positive non-zero serial prefix less than 256 for CA.")
		return nil, err
	}

	// CFSSL requires processing JSON configs through its own LoadConfig, so we
	// serialize and then deserialize.
	cfsslJSON, err := json.Marshal(config.CFSSL)
	if err != nil {
		return nil, err
	}
	cfsslConfigObj, err := cfsslConfig.LoadConfig(cfsslJSON)
	if err != nil {
		return nil, err
	}

	if config.LifespanOCSP.Duration == 0 {
		return nil, errors.New("Config must specify an OCSP lifespan period.")
	}

	for _, profile := range cfsslConfigObj.Signing.Profiles {
		if len(profile.IssuerURL) > 1 {
			return nil, errors.New("only one issuer_url supported")
		}
	}

	internalIssuers, err := makeInternalIssuers(
		issuers,
		cfsslConfigObj.Signing,
		config.LifespanOCSP.Duration)
	if err != nil {
		return nil, err
	}
	defaultIssuer := internalIssuers[issuers[0].Cert.Subject.CommonName]

	rsaProfile := config.RSAProfile
	ecdsaProfile := config.ECDSAProfile

	if rsaProfile == "" || ecdsaProfile == "" {
		return nil, errors.New("must specify rsaProfile and ecdsaProfile")
	}

	csrExtensionCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "csrExtensions",
			Help: "Number of CSRs with extensions of the given category",
		},
		[]string{csrExtensionCategory})
	stats.MustRegister(csrExtensionCount)

	signatureCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signatures",
			Help: "Number of signatures",
		},
		[]string{"purpose"})
	stats.MustRegister(signatureCount)

	ca = &CertificateAuthorityImpl{
		configPath:        configPath,
		sa:                sa,
		pa:                pa,
		issuers:           internalIssuers,
		defaultIssuer:     defaultIssuer,
		rsaProfile:        rsaProfile,
		ecdsaProfile:      ecdsaProfile,
		prefix:            config.SerialPrefix,
		clk:               clk,
		log:               logger,
		stats:             stats,
		keyPolicy:         keyPolicy,
		forceCNFromSAN:    !config.DoNotForceCN, // Note the inversion here
		signatureCount:    signatureCount,
		csrExtensionCount: csrExtensionCount,
		orphanQueue:       orphanQueue,
	}

	if config.Expiry == "" {
		return nil, errors.New("Config must specify an expiry period.")
	}
	ca.validityPeriod, err = time.ParseDuration(config.Expiry)
	if err != nil {
		return nil, err
	}

	// TODO(briansmith): Make the backdate setting mandatory after the
	// production ca.json has been updated to include it. Until then, manually
	// default to 1h, which is the backdating duration we currently use.
	ca.backdate = config.Backdate.Duration
	if ca.backdate == 0 {
		ca.backdate = time.Hour
	}

	ca.maxNames = config.MaxNames

	return ca, nil
}

// noteSignError is called after operations that may cause a CFSSL
// or PKCS11 signing error.
func (ca *CertificateAuthorityImpl) noteSignError(err error) {
	if err != nil {
		if _, ok := err.(*pkcs11.Error); ok {
			ca.stats.Inc(metricHSMError, 1)
		} else if cfErr, ok := err.(*cferr.Error); ok {
			ca.stats.Inc(fmt.Sprintf("%s.%d", metricSigningError, cfErr.ErrorCode), 1)
		}
	}
	return
}

// Extract supported extensions from a CSR.  The following extensions are
// currently supported:
//
// * 1.3.6.1.5.5.7.1.24 - TLS Feature [RFC7633], with the "must staple" value.
//                        Any other value will result in an error.
//
// Other requested extensions are silently ignored.
func (ca *CertificateAuthorityImpl) extensionsFromCSR(csr *x509.CertificateRequest) ([]signer.Extension, error) {
	extensions := []signer.Extension{}

	extensionSeen := map[string]bool{}
	hasBasic := false
	hasOther := false

	for _, attr := range csr.Attributes {
		if !attr.Type.Equal(oidExtensionRequest) {
			continue
		}

		for _, extList := range attr.Value {
			for _, ext := range extList {
				if extensionSeen[ext.Type.String()] {
					// Ignore duplicate certificate extensions
					continue
				}
				extensionSeen[ext.Type.String()] = true

				switch {
				case ext.Type.Equal(oidTLSFeature):
					ca.csrExtensionCount.With(prometheus.Labels{csrExtensionCategory: csrExtensionTLSFeature}).Inc()
					value, ok := ext.Value.([]byte)
					if !ok {
						return nil, berrors.MalformedError("malformed extension with OID %v", ext.Type)
					} else if !bytes.Equal(value, mustStapleFeatureValue) {
						ca.csrExtensionCount.With(prometheus.Labels{csrExtensionCategory: csrExtensionTLSFeatureInvalid}).Inc()
						return nil, berrors.MalformedError("unsupported value for extension with OID %v", ext.Type)
					}

					extensions = append(extensions, mustStapleExtension)
				case ext.Type.Equal(oidAuthorityInfoAccess),
					ext.Type.Equal(oidAuthorityKeyIdentifier),
					ext.Type.Equal(oidBasicConstraints),
					ext.Type.Equal(oidCertificatePolicies),
					ext.Type.Equal(oidCrlDistributionPoints),
					ext.Type.Equal(oidExtKeyUsage),
					ext.Type.Equal(oidKeyUsage),
					ext.Type.Equal(oidSubjectAltName),
					ext.Type.Equal(oidSubjectKeyIdentifier):
					hasBasic = true
				default:
					hasOther = true
				}
			}
		}
	}

	if hasBasic {
		ca.csrExtensionCount.With(prometheus.Labels{csrExtensionCategory: csrExtensionBasic}).Inc()
	}

	if hasOther {
		ca.csrExtensionCount.With(prometheus.Labels{csrExtensionCategory: csrExtensionOther}).Inc()
	}

	return extensions, nil
}

// GenerateOCSP produces a new OCSP response and returns it
func (ca *CertificateAuthorityImpl) GenerateOCSP(ctx context.Context, xferObj core.OCSPSigningRequest) ([]byte, error) {
	cert, err := x509.ParseCertificate(xferObj.CertDER)
	if err != nil {
		ca.log.AuditErr(err.Error())
		return nil, err
	}

	signRequest := ocsp.SignRequest{
		Certificate: cert,
		Status:      xferObj.Status,
		Reason:      int(xferObj.Reason),
		RevokedAt:   xferObj.RevokedAt,
	}

	cn := cert.Issuer.CommonName
	issuer := ca.issuers[cn]
	if issuer == nil {
		return nil, fmt.Errorf("This CA doesn't have an issuer cert with CommonName %q", cn)
	}

	err = cert.CheckSignatureFrom(issuer.cert)
	if err != nil {
		return nil, fmt.Errorf("GenerateOCSP was asked to sign OCSP for cert "+
			"%s from %q, but the cert's signature was not valid: %s.",
			core.SerialToString(cert.SerialNumber), cn, err)
	}

	ocspResponse, err := issuer.ocspSigner.Sign(signRequest)
	ca.noteSignError(err)
	if err == nil {
		ca.signatureCount.With(prometheus.Labels{"purpose": "ocsp"}).Inc()
	}
	return ocspResponse, err
}

func (ca *CertificateAuthorityImpl) reloadCFSSLConfig() error {

	var c config
	err := cmd.ReadConfigFile(ca.configPath, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	// CFSSL requires processing JSON configs through its own LoadConfig, so we
	// serialize and then deserialize.
	cfsslJSON, err := json.Marshal(c.CA.CFSSL)
	if err != nil {
		return err
	}
	cfsslConfigObj, err := cfsslConfig.LoadConfig(cfsslJSON)
	if err != nil {
		return err
	}

	issuers, err := LoadIssuers(c.CA)
	cmd.FailOnError(err, "Couldn't load issuers")

	internalIssuers, err := makeInternalIssuers(
		issuers,
		cfsslConfigObj.Signing,
		c.CA.LifespanOCSP.Duration)
	if err != nil {
		return err
	}

	defaultIssuer := internalIssuers[issuers[0].Cert.Subject.CommonName]

	rsaProfile := c.CA.RSAProfile
	ecdsaProfile := c.CA.ECDSAProfile

	ca.issuers = internalIssuers
	ca.defaultIssuer = defaultIssuer
	ca.rsaProfile = rsaProfile
	ca.ecdsaProfile = ecdsaProfile

	return nil
}

func (ca *CertificateAuthorityImpl) IssuePrecertificate(ctx context.Context, issueReq *caPB.IssueCertificateRequest) (*caPB.IssuePrecertificateResponse, error) {
	ca.reloadCFSSLConfig()

	serialBigInt, validity, err := ca.generateSerialNumberAndValidity()
	if err != nil {
		return nil, err
	}

	precertDER, err := ca.issuePrecertificateInner(ctx, issueReq, serialBigInt, validity, precertType)
	if err != nil {
		return nil, err
	}

	ca.log.AuditInfof("PRECERT: %s", base64.StdEncoding.EncodeToString(precertDER))

	return &caPB.IssuePrecertificateResponse{
		DER: precertDER,
	}, nil
}

// IssueCertificateForPrecertificate takes a precertificate and a set of SCTs for that precertificate
// and uses the signer to create and sign a certificate from them. The poison extension is removed
// and a SCT list extension is inserted in its place. Except for this and the signature the certificate
// exactly matches the precertificate. After the certificate is signed a OCSP response is generated
// and the response and certificate are stored in the database.
func (ca *CertificateAuthorityImpl) IssueCertificateForPrecertificate(ctx context.Context, req *caPB.IssueCertificateForPrecertificateRequest) (core.Certificate, error) {
	emptyCert := core.Certificate{}
	precert, err := x509.ParseCertificate(req.DER)
	if err != nil {
		return emptyCert, err
	}
	var scts []ct.SignedCertificateTimestamp
	for _, sctBytes := range req.SCTs {
		var sct ct.SignedCertificateTimestamp
		_, err = cttls.Unmarshal(sctBytes, &sct)
		if err != nil {
			return emptyCert, err
		}
		scts = append(scts, sct)
	}
	certPEM, err := ca.defaultIssuer.eeSigner.SignFromPrecert(precert, scts)
	if err != nil {
		return emptyCert, err
	}
	serialHex := core.SerialToString(precert.SerialNumber)
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		err = berrors.InternalServerError("invalid certificate value returned")
		ca.log.AuditErrf("PEM decode error, aborting: serial=[%s] pem=[%s] err=[%v]", serialHex, certPEM, err)
		return emptyCert, err
	}
	certDER := block.Bytes
	ca.log.AuditInfof("Signing success: serial=[%s] names=[%s] precertificate=[%s] certificate=[%s]",
		serialHex, strings.Join(precert.DNSNames, ", "), hex.EncodeToString(req.DER),
		hex.EncodeToString(certDER))
	return ca.generateOCSPAndStoreCertificate(ctx, *req.RegistrationID, *req.OrderID, precert.SerialNumber, certDER)
}

type validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

func (ca *CertificateAuthorityImpl) generateSerialNumberAndValidity() (*big.Int, validity, error) {
	// We want 136 bits of random number, plus an 8-bit instance id prefix.
	const randBits = 136
	serialBytes := make([]byte, randBits/8+1)
	serialBytes[0] = byte(ca.prefix)
	_, err := rand.Read(serialBytes[1:])
	if err != nil {
		err = berrors.InternalServerError("failed to generate serial: %s", err)
		ca.log.AuditErrf("Serial randomness failed, err=[%v]", err)
		return nil, validity{}, err
	}
	serialBigInt := big.NewInt(0)
	serialBigInt = serialBigInt.SetBytes(serialBytes)

	notBefore := ca.clk.Now().Add(-1 * ca.backdate)
	validity := validity{
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(ca.validityPeriod),
	}

	return serialBigInt, validity, nil
}

func (ca *CertificateAuthorityImpl) issuePrecertificateInner(ctx context.Context, issueReq *caPB.IssueCertificateRequest, serialBigInt *big.Int, validity validity, certType certificateType) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(issueReq.Csr)
	if err != nil {
		return nil, err
	}

	if err := csrlib.VerifyCSR(
		csr,
		ca.maxNames,
		&ca.keyPolicy,
		ca.pa,
		ca.forceCNFromSAN,
		*issueReq.RegistrationID,
	); err != nil {
		ca.log.AuditErr(err.Error())
		return nil, berrors.MalformedError(err.Error())
	}

	extensions, err := ca.extensionsFromCSR(csr)
	if err != nil {
		return nil, err
	}

	issuer := ca.defaultIssuer

	if issuer.cert.NotAfter.Before(validity.NotAfter) {
		err = berrors.InternalServerError("cannot issue a certificate that expires after the issuer certificate")
		ca.log.AuditErr(err.Error())
		return nil, err
	}

	// Convert the CSR to PEM
	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	}))

	var profile string
	switch csr.PublicKey.(type) {
	case *rsa.PublicKey:
		profile = ca.rsaProfile
	case *ecdsa.PublicKey:
		profile = ca.ecdsaProfile
	default:
		err = berrors.InternalServerError("unsupported key type %T", csr.PublicKey)
		ca.log.AuditErr(err.Error())
		return nil, err
	}

	// Send the cert off for signing
	req := signer.SignRequest{
		Request: csrPEM,
		Profile: profile,
		Hosts:   csr.DNSNames,
		Subject: &signer.Subject{
			CN: csr.Subject.CommonName,
		},
		Serial:     serialBigInt,
		Extensions: extensions,
		NotBefore:  validity.NotBefore,
		NotAfter:   validity.NotAfter,
	}

	if certType == precertType {
		req.ReturnPrecert = true
	}

	serialHex := core.SerialToString(serialBigInt)

	if !ca.forceCNFromSAN {
		req.Subject.SerialNumber = serialHex
	}

	ca.log.AuditInfof("Signing: serial=[%s] names=[%s] csr=[%s]",
		serialHex, strings.Join(csr.DNSNames, ", "), hex.EncodeToString(csr.Raw))

	certPEM, err := issuer.eeSigner.Sign(req)
	ca.noteSignError(err)
	if err != nil {
		err = berrors.InternalServerError("failed to sign certificate: %s", err)
		ca.log.AuditErrf("Signing failed: serial=[%s] err=[%v]", serialHex, err)
		return nil, err
	}
	ca.signatureCount.With(prometheus.Labels{"purpose": string(certType)}).Inc()

	if len(certPEM) == 0 {
		err = berrors.InternalServerError("no certificate returned by server")
		ca.log.AuditErrf("PEM empty from Signer: serial=[%s] err=[%v]", serialHex, err)
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		err = berrors.InternalServerError("invalid certificate value returned")
		ca.log.AuditErrf("PEM decode error, aborting: serial=[%s] pem=[%s] err=[%v]", serialHex, certPEM, err)
		return nil, err
	}
	certDER := block.Bytes

	ca.log.AuditInfof("Signing success: serial=[%s] names=[%s] csr=[%s] %s=[%s]",
		serialHex, strings.Join(csr.DNSNames, ", "), hex.EncodeToString(csr.Raw), certType,
		hex.EncodeToString(certDER))

	return certDER, nil
}

func (ca *CertificateAuthorityImpl) generateOCSPAndStoreCertificate(
	ctx context.Context,
	regID int64,
	orderID int64,
	serialBigInt *big.Int,
	certDER []byte) (core.Certificate, error) {
	ocspResp, err := ca.GenerateOCSP(ctx, core.OCSPSigningRequest{
		CertDER: certDER,
		Status:  "good",
	})
	if err != nil {
		err = berrors.InternalServerError(err.Error())
		ca.log.AuditInfof("OCSP Signing failure: serial=[%s] err=[%s]", core.SerialToString(serialBigInt), err)
		// Ignore errors here to avoid orphaning the certificate. The
		// ocsp-updater will look for certs with a zero ocspLastUpdated
		// and generate the initial response in this case.
	}

	now := ca.clk.Now()
	_, err = ca.sa.AddCertificate(ctx, certDER, regID, ocspResp, &now)
	if err != nil {
		err = berrors.InternalServerError(err.Error())
		// Note: This log line is parsed by cmd/orphan-finder. If you make any
		// changes here, you should make sure they are reflected in orphan-finder.
		ca.log.AuditErrf("Failed RPC to store at SA, orphaning certificate: serial=[%s] cert=[%s] err=[%v], regID=[%d], orderID=[%d]",
			core.SerialToString(serialBigInt), hex.EncodeToString(certDER), err, regID, orderID)
		if ca.orphanQueue != nil {
			ca.queueOrphan(&orphanedCert{
				DER:      certDER,
				OCSPResp: ocspResp,
				RegID:    regID,
			})
		}
		return core.Certificate{}, err
	}

	return core.Certificate{DER: certDER}, nil
}

type orphanedCert struct {
	DER      []byte
	OCSPResp []byte
	RegID    int64
}

func (ca *CertificateAuthorityImpl) queueOrphan(o *orphanedCert) {
	if _, err := ca.orphanQueue.EnqueueObject(o); err != nil {
		ca.log.AuditErrf("failed to queue orphan for integration: %s", err)
	}
}

// OrphanIntegrationLoop runs a loop executing integrateOrphans and then waiting a minute.
// It is split out into a separate function called directly by boulder-ca in order to make
// testing the orphan queue functionality somewhat more simple.
func (ca *CertificateAuthorityImpl) OrphanIntegrationLoop() {
	for {
		if err := ca.integrateOrphan(); err != nil {
			if err == goque.ErrEmpty {
				time.Sleep(time.Minute)
				continue
			}
			ca.log.AuditErrf("failed to integrate orphaned certs: %s", err)
		}
	}
}

// integrateOrpan removes an orphan from the queue and adds it to the database. The
// item isn't dequeued until it is actually added to the database to prevent items from
// being lost if the CA is restarted between the item being dequeued and being added to
// the database. It calculates the issuance time by subtracting the backdate period from
// the notBefore time.
func (ca *CertificateAuthorityImpl) integrateOrphan() error {
	item, err := ca.orphanQueue.Peek()
	if err != nil {
		if err == goque.ErrEmpty {
			return goque.ErrEmpty
		}
		return fmt.Errorf("failed to peek into orphan queue: %s", err)
	}
	var orphan orphanedCert
	if err = item.ToObject(&orphan); err != nil {
		return fmt.Errorf("failed to marshal orphan: %s", err)
	}
	cert, err := x509.ParseCertificate(orphan.DER)
	if err != nil {
		return fmt.Errorf("failed to parse orphan: %s", err)
	}
	issued := cert.NotBefore.Add(-ca.backdate)
	_, err = ca.sa.AddCertificate(context.Background(), orphan.DER, orphan.RegID, orphan.OCSPResp, &issued)
	if err != nil && !berrors.Is(err, berrors.Duplicate) {
		return fmt.Errorf("failed to store orphaned certificate: %s", err)
	}
	if _, err = ca.orphanQueue.Dequeue(); err != nil {
		return fmt.Errorf("failed to dequeue integrated orphaned certificate: %s", err)
	}
	return nil
}
