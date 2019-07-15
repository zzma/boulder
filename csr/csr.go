package csr

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/zzma/boulder/core"
	"github.com/zzma/boulder/goodkey"
	"github.com/zzma/boulder/identifier"
)

// maxCNLength is the maximum length allowed for the common name as specified in RFC 5280
const maxCNLength = 64

// This map is used to decide which CSR signing algorithms we consider
// strong enough to use. Significantly the missing algorithms are:
// * No algorithms using MD2, MD5, or SHA-1
// * No DSA algorithms
//
// SHA1WithRSA is allowed because there's still a fair bit of it
// out there, but we should try to remove it soon.
var goodSignatureAlgorithms = map[x509.SignatureAlgorithm]bool{
	x509.SHA1WithRSA:     true, // TODO(#2988): Remove support
	x509.SHA256WithRSA:   true,
	x509.SHA384WithRSA:   true,
	x509.SHA512WithRSA:   true,
	x509.ECDSAWithSHA256: true,
	x509.ECDSAWithSHA384: true,
	x509.ECDSAWithSHA512: true,
}

var (
	invalidPubKey        = errors.New("invalid public key in CSR")
	unsupportedSigAlg    = errors.New("signature algorithm not supported")
	invalidSig           = errors.New("invalid signature on CSR")
	invalidEmailPresent  = errors.New("CSR contains one or more email address fields")
	invalidIPPresent     = errors.New("CSR contains one or more IP address fields")
	invalidNoDNS         = errors.New("at least one DNS name is required")
	invalidAllSANTooLong = errors.New("CSR doesn't contain a SAN short enough to fit in CN")
)

// VerifyCSR checks the validity of a x509.CertificateRequest. Before doing checks it normalizes
// the CSR which lowers the case of DNS names and subject CN, and if forceCNFromSAN is true it
// will hoist a DNS name into the CN if it is empty.
func VerifyCSR(csr *x509.CertificateRequest, maxNames int, keyPolicy *goodkey.KeyPolicy, pa core.PolicyAuthority, forceCNFromSAN bool, regID int64) error {
	normalizeCSR(csr, forceCNFromSAN)
	key, ok := csr.PublicKey.(crypto.PublicKey)
	if !ok {
		return invalidPubKey
	}
	if err := keyPolicy.GoodKey(key); err != nil {
		return fmt.Errorf("invalid public key in CSR: %s", err)
	}
	if !goodSignatureAlgorithms[csr.SignatureAlgorithm] {
		return unsupportedSigAlg
	}
	if err := csr.CheckSignature(); err != nil {
		return invalidSig
	}
	if len(csr.EmailAddresses) > 0 {
		return invalidEmailPresent
	}
	if len(csr.IPAddresses) > 0 {
		return invalidIPPresent
	}
	if len(csr.DNSNames) == 0 && csr.Subject.CommonName == "" {
		return invalidNoDNS
	}
	if forceCNFromSAN && csr.Subject.CommonName == "" {
		return invalidAllSANTooLong
	}
	if len(csr.Subject.CommonName) > maxCNLength {
		return fmt.Errorf("CN was longer than %d bytes", maxCNLength)
	}
	if len(csr.DNSNames) > maxNames {
		return fmt.Errorf("CSR contains more than %d DNS names", maxNames)
	}
	idents := make([]identifier.ACMEIdentifier, len(csr.DNSNames))
	for i, dnsName := range csr.DNSNames {
		idents[i] = identifier.DNSIdentifier(dnsName)
	}
	if err := pa.WillingToIssueWildcards(idents); err != nil {
		return err
	}
	return nil
}

// normalizeCSR deduplicates and lowers the case of dNSNames and the subject CN.
// If forceCNFromSAN is true it will also hoist a dNSName into the CN if it is empty.
func normalizeCSR(csr *x509.CertificateRequest, forceCNFromSAN bool) {
	if forceCNFromSAN && csr.Subject.CommonName == "" {
		var forcedCN string
		// Promote the first SAN that is less than maxCNLength (if any)
		for _, name := range csr.DNSNames {
			if len(name) <= maxCNLength {
				forcedCN = name
				break
			}
		}
		csr.Subject.CommonName = forcedCN
	} else if csr.Subject.CommonName != "" {
		csr.DNSNames = append(csr.DNSNames, csr.Subject.CommonName)
	}
	csr.Subject.CommonName = strings.ToLower(csr.Subject.CommonName)
	csr.DNSNames = core.UniqueLowerNames(csr.DNSNames)
}
