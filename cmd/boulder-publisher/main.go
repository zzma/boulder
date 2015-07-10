// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/publisher"
	"github.com/letsencrypt/boulder/rpc"
)

func main() {
	app := cmd.NewAppShell("boulder-publisher")
	app.Action = func(c cmd.Config) {
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		// Set up logging
		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Couldn't connect to syslog")

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		blog.SetAuditLogger(auditlogger)

		pubi, err := publisher.NewPublisherAuthorityImpl(c.Publisher.CT, c.Common.IssuerCert)

		go cmd.ProfileCmd("Publisher", stats)

		for {
			ch, err := cmd.AmqpChannel(c)
			cmd.FailOnError(err, "Could not connect to AMQP")

			closeChan := ch.NotifyClose(make(chan *amqp.Error, 1))

			pubs := rpc.NewAmqpRPCServer(c.AMQP.Publisher.Server, ch)

			err = rpc.NewPublisherAuthorityServer(pubs, pubi)
			cmd.FailOnError(err, "Could not create Publisher RPC server")

			auditlogger.Info(app.VersionString())

			cmd.RunUntilSignaled(auditlogger, pubs, closeChan)
		}
	}

	app.Run()
}
