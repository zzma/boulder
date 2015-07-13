// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package publisher

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

type logDescription struct {
	ID        []byte
	URI       string
	PublicKey *ecdsa.PublicKey
}

type rawLogDescription struct {
	URI       string `json:"uri"`
	PublicKey string `json:"key"`
}

func (logDesc *logDescription) UnmarshalJSON(data []byte) error {
	var rawLogDesc rawLogDescription
	if err := json.Unmarshal(data, &rawLogDesc); err != nil {
		return fmt.Errorf("Failed to unmarshal log description, %s", err)
	}
	logDesc.URI = rawLogDesc.URI
	// Load Key
	pkBytes, err := base64.StdEncoding.DecodeString(rawLogDesc.PublicKey)
	if err != nil {
		return fmt.Errorf("")
	}
	pk, err := x509.ParsePKIXPublicKey(pkBytes)
	if err != nil {
		return fmt.Errorf("")
	}
	switch k := pk.(type) {
	case ecdsa.PublicKey:
		logDesc.PublicKey = &k
	case *ecdsa.PublicKey:
		logDesc.PublicKey = k
	default:
		return fmt.Errorf("Failed to unmarshal log description for %s, unsupported public key type", logDesc.URI)
	}

	// Generate key hash for log ID
	pkHash := sha256.Sum256(pkBytes)
	logDesc.ID = pkHash[:]
	fmt.Println(logDesc.ID)
	if len(logDesc.ID) != 32 {
		return fmt.Errorf("Invalid log ID length [%d]", len(logDesc.ID))
	}

	return nil
}

// CTConfig defines the JSON configuration file schema
type CTConfig struct {
	Logs              []logDescription `json:"logs"`
	SubmissionRetries int              `json:"submissionRetries"`
	// This should use the same method as the DNS resolver
	SubmissionBackoffString string `json:"submissionBackoff"`

	SubmissionBackoff time.Duration `json:"-"`
	IssuerDER         []byte        `json:"-"`
}

type ctSubmissionRequest struct {
	Chain []string `json:"chain"`
}

const (
	sctVersion       = 0
	sctSigType       = 0
	sctX509EntryType = 0
)

// PublisherAuthorityImpl defines a Publisher
type PublisherAuthorityImpl struct {
	log *blog.AuditLogger
	CT  *CTConfig
	SA  core.StorageAuthority
}

// NewPublisherAuthorityImpl creates a Publisher that will submit certificates
// to any CT logs configured in CTConfig
func NewPublisherAuthorityImpl(ctConfig *CTConfig, issuerDER []byte) (PublisherAuthorityImpl, error) {
	var pub PublisherAuthorityImpl

	logger := blog.GetAuditLogger()
	logger.Notice("Publisher Authority Starting")
	pub.log = logger

	if ctConfig != nil {
		pub.CT = ctConfig
		pub.CT.IssuerDER = issuerDER
		ctBackoff, err := time.ParseDuration(ctConfig.SubmissionBackoffString)
		if err != nil {
			return pub, err
		}
		pub.CT.SubmissionBackoff = ctBackoff
	}

	return pub, nil
}

// SubmitToCT will submit the certificate represented by certDER to any CT
// logs configured in pub.CT.Logs
func (pub *PublisherAuthorityImpl) SubmitToCT(cert *x509.Certificate) error {
	if pub.CT == nil {
		return nil
	}
	submission := ctSubmissionRequest{Chain: []string{base64.StdEncoding.EncodeToString(cert.Raw)}}
	if len(pub.CT.IssuerDER) > 0 {
		submission.Chain = append(submission.Chain, base64.StdEncoding.EncodeToString(pub.CT.IssuerDER))
	}
	client := http.Client{}
	jsonSubmission, err := json.Marshal(submission)
	if err != nil {
		pub.log.Err(fmt.Sprintf("Unable to marshal CT submission, %s", err))
		return err
	}

	for _, ctLog := range pub.CT.Logs {
		done := false
		var retries int
		var sct core.SignedCertificateTimestamp
		for !done && retries <= pub.CT.SubmissionRetries {
			resp, err := postJSON(&client, fmt.Sprintf("%s%s", ctLog.URI, "/ct/v1/add-chain"), jsonSubmission, &sct)
			if err != nil {
				// Retry the request, log the error
				// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
				pub.log.AuditErr(fmt.Errorf("Error POSTing JSON to CT log submission endpoint [%s]: %s", ctLog.URI, err))
				if retries >= pub.CT.SubmissionRetries {
					break
				}
				retries++
				time.Sleep(pub.CT.SubmissionBackoff)
				continue
			} else {
				if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusServiceUnavailable {
					// Retry the request after either 10 seconds or the period specified
					// by the Retry-After header
					backoff := pub.CT.SubmissionBackoff
					if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
						if seconds, err := strconv.Atoi(retryAfter); err != nil {
							backoff = time.Second * time.Duration(seconds)
						}
					}
					if retries >= pub.CT.SubmissionRetries {
						break
					}
					retries++
					time.Sleep(backoff)
					continue
				} else if resp.StatusCode != http.StatusOK {
					// Not something we expect to happen, set error, break loop and log
					// the error
					// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
					pub.log.AuditErr(fmt.Errorf("Unexpected status code returned from CT log submission endpoint [%s]: Unexpected status code [%d]", ctLog.URI, resp.StatusCode))
					break
				}
			}

			done = true
			break
		}
		if !done {
			pub.log.Warning(fmt.Sprintf(
				"Unable to submit certificate to CT log [Serial: %s, Log URI: %s, Retries: %d]",
				core.SerialToString(cert.SerialNumber),
				ctLog.URI,
				retries,
			))
			return fmt.Errorf("Unable to submit certificate")
		}

		if err = sct.VerifySignature(cert.Raw, ctLog.PublicKey); err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			pub.log.AuditErr(err)
			return err
		}

		// Do something with the signedCertificateTimestamp, we might want to
		// include something in the CertificateStatus table or such to indicate
		// that it has been successfully submitted to CT logs so that we can retry
		// sometime in the future if it didn't work this time. (In the future this
		// will be needed anyway for putting SCT in OCSP responses)
		pub.log.Notice(fmt.Sprintf(
			"Submitted certificate to CT log [Serial: %s, Log URI: %s, Retries: %d, Signature: %x]",
			core.SerialToString(cert.SerialNumber),
			ctLog.URI,
			retries, sct.Signature,
		))

		// Set certificate serial and add SCT to SQL
		sct.CertificateSerial = core.SerialToString(cert.SerialNumber)

		// TODO(rolandshoemaker): there shouldn't be any existing reciepts (although
		// since logs should return the same reciept for a duplicate submission we
		// may be able to ignore this and also ignore any existing row errors for
		// the AddToSCTReciept call below)
		existingReciept, err := pub.SA.GetSCTReciept(sct.CertificateSerial, ctLog.ID)
		if err != nil && err != sql.ErrNoRows {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			pub.log.AuditErr(fmt.Errorf(
				"Error checking for existing SCT reciept for [%s to %s]: %s",
				sct.CertificateSerial,
				ctLog.URI,
				err,
			))
		}
		if existingReciept != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			err := fmt.Errorf("Existing SCT reciept for [%s to %s]", sct.CertificateSerial, ctLog.URI)
			pub.log.AuditErr(err)
			return err
		}
		err = pub.SA.AddSCTReciept(sct)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			pub.log.AuditErr(fmt.Errorf(
				"Error adding SCT reciept for [%s to %s]: %s",
				sct.CertificateSerial,
				ctLog.URI,
				err,
			))
			return err
		}
		pub.log.Notice(fmt.Sprintf(
			"Stored SCT reciept from CT log submission [Serial: %s, Log URI: %s]",
			core.SerialToString(cert.SerialNumber),
			ctLog.URI,
		))
	}

	return nil
}

func postJSON(client *http.Client, uri string, data []byte, respObj interface{}) (*http.Response, error) {
	if !strings.HasPrefix(uri, "http://") && !strings.HasPrefix(uri, "https://") {
		uri = fmt.Sprintf("%s%s", "http://", uri)
	}
	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Creating request failed, %s", err)
	}
	req.Header.Set("Keep-Alive", "timeout=15, max=100")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Request failed, %s", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to read response body, %s", err)
	}

	err = json.Unmarshal(body, respObj)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal SCT reciept, %s", err)
	}

	return resp, nil
}
