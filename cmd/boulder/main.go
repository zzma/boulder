// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"github.com/letsencrypt/boulder/core"
)

type command struct {
	help  string
	where string
}

var (
	services = map[string]command{
		"ca": command{
			help: "Handles issuance operations",
		},
		"ocsp-responder": command{
			help: "Handles OCSP requests",
		},
		"ra": command{
			help: "Handles service orchestration",
		},
		"sa": command{
			help: "Handles SQL operations",
		},
		"va": command{
			help: "Handles challenge validation",
		},
		"wfe": command{
			help: "Handles HTTP API requests",
		},
		"am": command{
			help: "RPC activity monitor",
		},
	}

	tools = map[string]command{
		"revoker": command{
			help: "Revoke issued certificates",
		},
		"expiration-mailer": command{
			help: "Send certificate expiration emails",
		},
		"external-cert-importer": command{
			help: "Import external certificates for POP checks",
		},
		"ocsp-updater": command{
			help: "Update/Generate OCSP responses",
		},
	}
)

func checkSystem(services, tools map[string]command) error {
	// Find service binaries
	for n := range services {
		path, err := exec.LookPath(fmt.Sprintf("boulder-%s", n))
		if err != nil {
			delete(services, n)
			continue
		}
		t := services[n]
		t.where = path
		services[n] = t
	}

	// Find tool binaries
	for n := range tools {
		path, err := exec.LookPath(fmt.Sprintf("boulder-%s", n))
		if err != nil {
			delete(tools, n)
			continue
		}
		t := tools[n]
		t.where = path
		tools[n] = t
	}

	if len(services) == 0 && len(tools) == 0 {
		return fmt.Errorf("Couldn't find any boulder binaries")
	}

	return nil
}

func printAvailable(services, tools map[string]command) {
	if len(services) > 0 {
		fmt.Printf("\n# Available commands\n[Services]\n")
		for n, c := range services {
			fmt.Printf("\t%s -- %s\n", n, c.help)
		}
	}
	if len(tools) > 0 {
		fmt.Printf("\n[Tools]\n")
		for n, c := range tools {
			fmt.Printf("\t%s -- %s\n", n, c.help)
		}
	}
}

func printHeader() {
	fmt.Printf("usage: boulder [command] [subcommand] [flags]\n")
	fmt.Printf("version: %s -- %s, Golang=(%s) BuildHost=(%s)\n", core.GetBuildID(), core.GetBuildTime(), runtime.Version(), core.GetBuildHost())
	fmt.Printf("written by the Boulder contributors <ca-dev@letsencrypt.org\n")
}

func printFooter() {
	fmt.Printf("\nFor more information about specific commands use 'boulder <command> help'\n")
}

func execute(name string, args []string) {
	cmd, present := services[name]
	if !present {
		cmd, present = tools[name]
		if !present {
			fmt.Printf("Uknown command\n\n")
			printHeader()
			printAvailable(services, tools)
			printFooter()
			return
		}
	}
	e := exec.Command(cmd.where, args...)
	e.Env = os.Environ()
	eReader, err := e.StdoutPipe()
	if err != nil {
		// BAD
		return
	}
	go func() {
		scanner := bufio.NewScanner(eReader)
		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
	}()
	if err := e.Run(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			// The program has exited with an exit code != 0

			// This works on both Unix and Windows. Although package
			// syscall is generally platform dependent, WaitStatus is
			// defined for both Unix and Windows and in both cases has
			// an ExitStatus() method with the same signature.
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				os.Exit(status.ExitStatus())
			}
		} else {
			log.Fatalf("Failed to execute [%s %s]: %v", cmd.where, strings.Join(args, " "), err)
		}
	}
}

func main() {
	checkSystem(services, tools)
	if len(os.Args) < 2 || len(os.Args) >= 2 && os.Args[1] == "help" {
		printHeader()
		printAvailable(services, tools)
		printFooter()
		return
	}

	execute(os.Args[1], os.Args[2:])
}
