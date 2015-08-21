// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import "fmt"

var (
	services = map[string]string{
		"ca":             "Handles issuance operations",
		"ocsp-responder": "Handles OCSP requests",
		"ra":             "Handles service orchestration",
		"sa":             "Handles SQL operations",
		"va":             "Handles challenge validation",
		"wfe":            "Handles API requests",
		"am":             "RPC activity monitor",
	}
	tools = map[string]string{
		"revoker":                "Revoke issued certificates",
		"expiration-mailer":      "Send certificate expiration emails",
		"external-cert-importer": "Import external certificates for POP checks",
		"ocsp-updater":           "Update/Generate OCSP responses",
	}
)

func checkSystem() (map[string]string, error) {
	return nil, nil
}

func printAvailable(services, tools map[string]string) {
	fmt.Printf("Available commands\n# Services\n\n")
	for name, help := range services {
		fmt.Printf("\t%s -- %s\n", name, help)
	}
	fmt.Printf("\n# Tools\n\n")
	for name, help := range tools {
		fmt.Printf("\t%s -- %s\n", name, help)
	}
}

func main() {

}
