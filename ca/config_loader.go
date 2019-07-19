package ca


import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/letsencrypt/pkcs11key"
	ca_config "github.com/zzma/boulder/ca/config"
	"github.com/zzma/boulder/cmd"
	"github.com/zzma/boulder/core"
	"io/ioutil"
)

func LoadIssuers(c ca_config.CAConfig) ([]Issuer, error) {
	var issuers []Issuer
	for _, issuerConfig := range c.Issuers {
		priv, cert, err := LoadIssuer(issuerConfig)
		cmd.FailOnError(err, "Couldn't load private key")
		issuers = append(issuers, Issuer{
			Signer: priv,
			Cert:   cert,
		})
	}
	return issuers, nil
}

func LoadIssuer(issuerConfig ca_config.IssuerConfig) (crypto.Signer, *x509.Certificate, error) {
	cert, err := core.LoadCert(issuerConfig.CertFile)
	if err != nil {
		return nil, nil, err
	}

	signer, err := LoadSigner(issuerConfig)
	if err != nil {
		return nil, nil, err
	}

	if !core.KeyDigestEquals(signer.Public(), cert.PublicKey) {
		return nil, nil, fmt.Errorf("Issuer key did not match issuer cert %s", issuerConfig.CertFile)
	}
	return signer, cert, err
}

func LoadSigner(issuerConfig ca_config.IssuerConfig) (crypto.Signer, error) {
	if issuerConfig.File != "" {
		keyBytes, err := ioutil.ReadFile(issuerConfig.File)
		if err != nil {
			return nil, fmt.Errorf("Could not read key file %s", issuerConfig.File)
		}

		signer, err := helpers.ParsePrivateKeyPEM(keyBytes)
		if err != nil {
			return nil, err
		}
		return signer, nil
	}

	var pkcs11Config *pkcs11key.Config
	if issuerConfig.ConfigFile != "" {
		contents, err := ioutil.ReadFile(issuerConfig.ConfigFile)
		if err != nil {
			return nil, err
		}
		pkcs11Config = new(pkcs11key.Config)
		err = json.Unmarshal(contents, pkcs11Config)
		if err != nil {
			return nil, err
		}
	} else {
		pkcs11Config = issuerConfig.PKCS11
	}
	if pkcs11Config.Module == "" ||
		pkcs11Config.TokenLabel == "" ||
		pkcs11Config.PIN == "" ||
		pkcs11Config.PrivateKeyLabel == "" {
		return nil, fmt.Errorf("Missing a field in pkcs11Config %#v", pkcs11Config)
	}
	numSessions := issuerConfig.NumSessions
	if numSessions <= 0 {
		numSessions = 1
	}
	return pkcs11key.NewPool(numSessions, pkcs11Config.Module,
		pkcs11Config.TokenLabel, pkcs11Config.PIN, pkcs11Config.PrivateKeyLabel)
}

