// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package publisher

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

// google.com
var testLeaf = `-----BEGIN CERTIFICATE-----
MIIHgzCCBmugAwIBAgIIe8+KOaV1RzowDQYJKoZIhvcNAQELBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTUwNzAxMjA1ODE1WhcNMTUwOTI5MDAwMDAw
WjBmMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEVMBMGA1UEAwwMKi5n
b29nbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqmQ2g8a+
2SOobcZYXi4dC9K5ty7mXicyD9awakpaH9kDe6cRNn0VqyypkGZ4j6F0h9Ggsubo
Kzi/1+aKM4AdFv2BD2X3OYUVr7aeuTAADWdbr11XW3a4iwQRomqxs09HAxZBtvii
eyIPy6ZQCU+GbOqqsi4TOfc1mogSDCHI7QZ1u01W4ExHGNe4eNZ26cJ4o8OiTmK4
zCT5BNGovGKE3MTqJecj6jWbJHgI5sps6zIfZYXZIzrkO9OYpa3jLKBfvec4P+tu
L5SwfwCpOnt16JrbwF8MhuthcUPkGE1YfzCX8EcPdakNhWuPYTmp8BGmTwnWaSgZ
XHh2qA6skCww5QIDAQABo4IEUDCCBEwwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsG
AQUFBwMCMIIDJgYDVR0RBIIDHTCCAxmCDCouZ29vZ2xlLmNvbYINKi5hbmRyb2lk
LmNvbYIWKi5hcHBlbmdpbmUuZ29vZ2xlLmNvbYISKi5jbG91ZC5nb29nbGUuY29t
ghYqLmdvb2dsZS1hbmFseXRpY3MuY29tggsqLmdvb2dsZS5jYYILKi5nb29nbGUu
Y2yCDiouZ29vZ2xlLmNvLmlugg4qLmdvb2dsZS5jby5qcIIOKi5nb29nbGUuY28u
dWuCDyouZ29vZ2xlLmNvbS5hcoIPKi5nb29nbGUuY29tLmF1gg8qLmdvb2dsZS5j
b20uYnKCDyouZ29vZ2xlLmNvbS5jb4IPKi5nb29nbGUuY29tLm14gg8qLmdvb2ds
ZS5jb20udHKCDyouZ29vZ2xlLmNvbS52boILKi5nb29nbGUuZGWCCyouZ29vZ2xl
LmVzggsqLmdvb2dsZS5mcoILKi5nb29nbGUuaHWCCyouZ29vZ2xlLml0ggsqLmdv
b2dsZS5ubIILKi5nb29nbGUucGyCCyouZ29vZ2xlLnB0ghIqLmdvb2dsZWFkYXBp
cy5jb22CDyouZ29vZ2xlYXBpcy5jboIUKi5nb29nbGVjb21tZXJjZS5jb22CESou
Z29vZ2xldmlkZW8uY29tggwqLmdzdGF0aWMuY26CDSouZ3N0YXRpYy5jb22CCiou
Z3Z0MS5jb22CCiouZ3Z0Mi5jb22CFCoubWV0cmljLmdzdGF0aWMuY29tggwqLnVy
Y2hpbi5jb22CECoudXJsLmdvb2dsZS5jb22CFioueW91dHViZS1ub2Nvb2tpZS5j
b22CDSoueW91dHViZS5jb22CFioueW91dHViZWVkdWNhdGlvbi5jb22CCyoueXRp
bWcuY29tggthbmRyb2lkLmNvbYIEZy5jb4IGZ29vLmdsghRnb29nbGUtYW5hbHl0
aWNzLmNvbYIKZ29vZ2xlLmNvbYISZ29vZ2xlY29tbWVyY2UuY29tggp1cmNoaW4u
Y29tggh5b3V0dS5iZYILeW91dHViZS5jb22CFHlvdXR1YmVlZHVjYXRpb24uY29t
MGgGCCsGAQUFBwEBBFwwWjArBggrBgEFBQcwAoYfaHR0cDovL3BraS5nb29nbGUu
Y29tL0dJQUcyLmNydDArBggrBgEFBQcwAYYfaHR0cDovL2NsaWVudHMxLmdvb2ds
ZS5jb20vb2NzcDAdBgNVHQ4EFgQUN7bdnTry/ryrPIw5obWNWqqcilIwDAYDVR0T
AQH/BAIwADAfBgNVHSMEGDAWgBRK3QYWG7z2aLV29YG2u2IaulqBLzAXBgNVHSAE
EDAOMAwGCisGAQQB1nkCBQEwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL3BraS5n
b29nbGUuY29tL0dJQUcyLmNybDANBgkqhkiG9w0BAQsFAAOCAQEAFMz3Coc6N+Gm
8Fr0YnfIiu4tSLR8/zQtb2pVi5pBWhsFwFm/sCN9c0y8LUHPTjfT+1N5B7HlNHav
ZYvMI632XwKGrvGzU8T8a8L33y4ndjghi5TkPiFdW9WEC7fW0TdRnHT7Mf3icngJ
zLx/3YuWJEeOed2nmsZF1AUxYyXC+4Purdvpkzo2wc5DKoKnegTuarxQHw7psSeY
3hWhii/zbRbSpvEKYWPwTYVka+fsa82BoLIrToLUqnY9Rs7rDcFbCZ9sevRu2W2O
7eM5uvyvDnsckd6+H+IXvkYtqp9QA7cy7wK4Z5h3SbSFAcTNIoVLREXESbhS6+vI
gyL+WTYyjQ==
-----END CERTIFICATE-----`

func TestVerifySignature(t *testing.T) {
	// Based on an actual submission to the aviator log
	sigBytes, err := base64.StdEncoding.DecodeString("BAMASDBGAiEA/4kz9wQq3NhvZ6VlOmjq2Z9MVHGrUjF8uxUG9n1uRc4CIQD2FYnnszKXrR9AP5kBWmTgh3fXy+VlHK8HZXfbzdFf7g==")
	if err != nil {
		fmt.Println("a", err)
		return
	}
	testReciept := signedCertificateTimestamp{
		SCTVersion: sctVersion,
		Timestamp:  1435787268907,
		Signature:  sigBytes,
	}

	aviatorPkBytes, err := base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1JYP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q==")
	if err != nil {
		fmt.Println(err)
		return
	}

	aviatorPk, err := x509.ParsePKIXPublicKey(aviatorPkBytes)
	if err != nil {
		fmt.Println(err)
		return
	}

	leafPEM, _ := pem.Decode([]byte(testLeaf))

	if err != nil {
		fmt.Println(err)
		return
	}

	err = testReciept.Verify(aviatorPk, leafPEM.Bytes)
	fmt.Println("ERR", err)
	test.AssertNotError(t, err, "BAD")
}
