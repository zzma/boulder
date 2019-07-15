package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/zzma/boulder/cmd"
	"github.com/zzma/boulder/core"

	"github.com/letsencrypt/pkcs11key"
	"golang.org/x/crypto/ocsp"
)

const usage = `
name:
  single-ocsp - Creates a single OCSP response

usage:
  single-ocsp [args]

description:
  According to the BRs, the OCSP responses for intermediate certificate must
  be issued once per year.  So we need to issue OCSP responses for these
  certificates, but it doesn't make sense to use all the infrastructure
  that the "ocsp-updater" tool requires.  This tool allows an administrator
  to manually generate an OCSP response for an intermediate certificate.

  This will write a base64-encoded DER format OCSP response to the file
  specified with -out, ending in a newline. This output can be directly
  appended to the flat file used by ocsp-responder for intermediate and
  root OCSP responses.
`

const pkcs11Usage = `
PKCS#11 configuration (JSON), e.g.:

{
	"module": "/usr/local/lib/libpkcs11-proxy.so",
	"tokenLabel": "intermediate",
	"pin": "5678",
	"privateKeyLabel": "intermediate_key"
}

Note: These values should *not* be the same as the ones in the CA's config JSON, which point at a differen HSM partition.
`

func readFiles(issuerFileName, responderFileName, targetFileName, pkcs11FileName string) (issuer, responder, target *x509.Certificate, pkcs11Config pkcs11key.Config, err error) {
	// Issuer certificate
	issuer, err = core.LoadCert(issuerFileName)
	if err != nil {
		return
	}

	// Responder certificate
	responder, err = core.LoadCert(responderFileName)
	if err != nil {
		return
	}

	// Target certificate
	target, err = core.LoadCert(targetFileName)
	if err != nil {
		return
	}

	// PKCS#11 config
	pkcs11Bytes, err := ioutil.ReadFile(pkcs11FileName)
	if err != nil {
		return
	}

	err = json.Unmarshal(pkcs11Bytes, &pkcs11Config)
	if pkcs11Config.Module == "" ||
		pkcs11Config.TokenLabel == "" ||
		pkcs11Config.PIN == "" ||
		pkcs11Config.PrivateKeyLabel == "" {
		err = fmt.Errorf("Missing a field in pkcs11Config %#v", pkcs11Config)
		return
	}
	return
}

func main() {
	issuerFile := flag.String("issuer", "", "Issuer certificate (PEM)")
	responderFile := flag.String("responder", "", "OCSP responder certificate (DER)")
	targetFile := flag.String("target", "", "Certificate whose status is being reported (PEM)")
	pkcs11File := flag.String("pkcs11", "", pkcs11Usage)
	outFile := flag.String("out", "", "File to which the OCSP response will be written")
	thisUpdateString := flag.String("thisUpdate", "", "Time for ThisUpdate field, RFC3339 format (e.g. 2016-09-02T00:00:00Z)")
	nextUpdateString := flag.String("nextUpdate", "", "Time for NextUpdate field, RFC3339 format")
	status := flag.Int("status", 0, "Status for response (0 = good, 1 = revoked)")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()

	if len(*outFile) == 0 {
		cmd.FailOnError(fmt.Errorf("No output file provided"), "")
	}
	thisUpdate, err := time.Parse(time.RFC3339, *thisUpdateString)
	cmd.FailOnError(err, "Parsing thisUpdate flag")
	nextUpdate, err := time.Parse(time.RFC3339, *nextUpdateString)
	cmd.FailOnError(err, "Parsing nextUpdate flag")

	issuer, responder, target, pkcs11, err := readFiles(*issuerFile, *responderFile, *targetFile, *pkcs11File)
	cmd.FailOnError(err, "Failed to read files")

	// Instantiate the private key from PKCS11
	priv, err := pkcs11key.New(pkcs11.Module, pkcs11.TokenLabel, pkcs11.PIN, pkcs11.PrivateKeyLabel)
	cmd.FailOnError(err, "Failed to load PKCS#11 key")

	// Populate the remaining fields in the template
	template := ocsp.Response{
		SerialNumber: target.SerialNumber,
		Certificate:  responder,
		Status:       *status,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
	}

	if !core.KeyDigestEquals(responder.PublicKey, priv.Public()) {
		cmd.FailOnError(fmt.Errorf("PKCS#11 pubkey does not match pubkey "+
			"in responder certificate"), "loading keys")
	}

	// Sign the OCSP response
	responseBytes, err := ocsp.CreateResponse(issuer, responder, template, priv)
	cmd.FailOnError(err, "Failed to sign OCSP response")

	_, err = ocsp.ParseResponse(responseBytes, nil)
	cmd.FailOnError(err, "Failed to parse signed response")

	responseBytesBase64 := base64.StdEncoding.EncodeToString(responseBytes) + "\n"

	// Write the OCSP response to stdout
	err = ioutil.WriteFile(*outFile, []byte(responseBytesBase64), 0666)
	cmd.FailOnError(err, "Failed to write output file")
}
