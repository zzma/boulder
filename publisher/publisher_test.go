// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package publisher

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestCheckSignature(t *testing.T) {
	// Based on a submission to the aviator log
	goodSigBytes, err := base64.StdEncoding.DecodeString("BAMASDBGAiEA/4kz9wQq3NhvZ6VlOmjq2Z9MVHGrUjF8uxUG9n1uRc4CIQD2FYnnszKXrR9AP5kBWmTgh3fXy+VlHK8HZXfbzdFf7g==")
	if err != nil {
		fmt.Println("a", err)
		return
	}
	testReciept := signedCertificateTimestamp{
		Signature: goodSigBytes,
	}

	// Good signature
	err = testReciept.CheckSignature()
	test.AssertNotError(t, err, "BAD")

	// Invalid signature (too short, trailing garbage)
	testReciept.Signature = goodSigBytes[1:]
	err = testReciept.CheckSignature()
	test.AssertError(t, err, "BAD")
	testReciept.Signature = append(goodSigBytes, []byte{0, 0, 1}...)
	err = testReciept.CheckSignature()
	test.AssertError(t, err, "BAD")
}
