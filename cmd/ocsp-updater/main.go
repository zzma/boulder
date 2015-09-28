// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"
	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"
)

// OCSPUpdater contains the useful objects for the Updater
type OCSPUpdater struct {
	stats statsd.Statter
	log   *blog.AuditLogger
	clk   clock.Clock

	dbMap *gorp.DbMap

	rpcMu *sync.RWMutex
	cac   core.CertificateAuthority
	pub   core.Publisher

	// Bits various loops need but don't really fit in the looper struct
	ocspMinTimeToExpiry time.Duration
	oldestIssuedSCT     time.Duration
	numLogs             int

	newCertificatesLoop  *looper
	oldOCSPResponsesLoop *looper
	missingReceiptsLoop  *looper
}

// This is somewhat gross but can be pared down a bit once the publisher and this
// are fully smooshed together
func newUpdater(log *blog.AuditLogger, stats statsd.Statter, clk clock.Clock,
	dbMap *gorp.DbMap, ca core.CertificateAuthority, pub core.Publisher,
	numLogs int, config cmd.OCSPUpdaterConfig) (*OCSPUpdater, error) {
	if config.NewCertificateBatchSize == 0 || config.OldOCSPBatchSize == 0 || config.MissingSCTBatchSize == 0 {
		return nil, fmt.Errorf("Batch sizes must be non-zero")
	}

	updater := OCSPUpdater{
		stats:   stats,
		log:     log,
		clk:     clk,
		dbMap:   dbMap,
		cac:     ca,
		pub:     pub,
		numLogs: numLogs,
		// Stuff we initialize
		rpcMu: new(sync.RWMutex),
	}

	// Setup loops
	updater.newCertificatesLoop = &looper{
		clk:       clk,
		stats:     stats,
		batchSize: config.NewCertificateBatchSize,
		tickDur:   config.NewCertificateWindow.Duration,
		tickFunc:  updater.newCertificateTick,
		name:      "NewCertificates",
	}
	updater.oldOCSPResponsesLoop = &looper{
		clk:       clk,
		stats:     stats,
		batchSize: config.OldOCSPBatchSize,
		tickDur:   config.OldOCSPWindow.Duration,
		tickFunc:  updater.oldOCSPResponsesTick,
		name:      "OldOCSPResponses",
	}
	updater.missingReceiptsLoop = &looper{
		clk:       clk,
		stats:     stats,
		batchSize: config.MissingSCTBatchSize,
		tickDur:   config.MissingSCTWindow.Duration,
		tickFunc:  updater.missingReceiptsTick,
		name:      "MissingSCTReceipts",
	}

	updater.ocspMinTimeToExpiry = config.OCSPMinTimeToExpiry.Duration
	updater.oldestIssuedSCT = config.SCTOldestIssued.Duration

	return &updater, nil
}

func setupClients(c cmd.Config, stats statsd.Statter) (core.CertificateAuthority, core.Publisher, chan *amqp.Error) {
	ch, err := rpc.AmqpChannel(c)
	cmd.FailOnError(err, "Could not connect to AMQP")

	closeChan := ch.NotifyClose(make(chan *amqp.Error, 1))

	caRPC, err := rpc.NewAmqpRPCClient("OCSP->CA", c.AMQP.CA.Server, ch, stats)
	cmd.FailOnError(err, "Unable to create RPC client")

	cac, err := rpc.NewCertificateAuthorityClient(caRPC)
	cmd.FailOnError(err, "Unable to create CA client")

	pubRPC, err := rpc.NewAmqpRPCClient("OCSP->Publisher", c.AMQP.Publisher.Server, ch, stats)
	cmd.FailOnError(err, "Unable to create RPC client")

	pubc, err := rpc.NewPublisherClient(pubRPC)
	cmd.FailOnError(err, "Failed to create Publisher client")

	return cac, pubc, closeChan
}

var errNoStaleResponses = errors.New("No stale responses to update")

func (updater *OCSPUpdater) findStaleOCSPResponses(oldestLastUpdatedTime time.Time, batchSize int) ([]core.Certificate, error) {
	var certs []core.Certificate
	_, err := updater.dbMap.Select(
		&certs,
		`SELECT cert.*
		 FROM certificateStatus AS cs
		 JOIN certificates AS cert
		 ON cs.serial = cert.serial
		 WHERE cs.ocspLastUpdated < :lastUpdate
		 AND cert.expires > now()
		 ORDER BY cs.ocspLastUpdated ASC
		 LIMIT :limit`,
		map[string]interface{}{
			"lastUpdate": oldestLastUpdatedTime,
			"limit":      batchSize,
		},
	)
	if err == sql.ErrNoRows || len(certs) == 0 {
		return certs, errNoStaleResponses
	}
	return certs, err
}

func (updater *OCSPUpdater) getNumberOfReceipts(serial string) (int, error) {
	var count int
	err := updater.dbMap.SelectOne(
		&count,
		"SELECT COUNT(*) FROM sctReceipts WHERE certificateSerial = :serial",
		map[string]interface{}{"serial": serial},
	)
	return count, err
}

var errNoNewCertificates = errors.New("No certificates issued since last check")

func (updater *OCSPUpdater) getCertificatesIssuedSince(since time.Time, batchSize int) ([]core.Certificate, error) {
	var certs []core.Certificate
	_, err := updater.dbMap.Select(
		&certs,
		`SELECT * FROM certificates
		 WHERE issued > :since
		 LIMIT :limit`,
		map[string]interface{}{
			"since": since,
			"limit": batchSize,
		},
	)
	if err == sql.ErrNoRows || len(certs) == 0 {
		return certs, errNoNewCertificates
	}
	return certs, err
}

func (updater *OCSPUpdater) getSerialsIssuedSince(since time.Time, batchSize int) ([]string, error) {
	var serials []string
	_, err := updater.dbMap.Select(
		&serials,
		`SELECT serial FROM certificates
		 WHERE issued > :since
		 LIMIT :limit`,
		map[string]interface{}{
			"since": since,
			"limit": batchSize,
		},
	)
	if err == sql.ErrNoRows || len(serials) == 0 {
		return serials, errNoNewCertificates
	}
	return serials, err
}

type responseMeta struct {
	*core.OCSPResponse
	*core.CertificateStatus
}

func (updater *OCSPUpdater) generateResponse(cert core.Certificate) (responseMeta, error) {
	var status core.CertificateStatus
	err := updater.dbMap.SelectOne(
		&status,
		"SELECT * FROM certificateStatus WHERE serial = :serial",
		map[string]interface{}{"serial": cert.Serial},
	)
	if err != nil {
		return responseMeta{}, err
	}

	_, err = x509.ParseCertificate(cert.DER)
	if err != nil {
		return responseMeta{}, err
	}

	signRequest := core.OCSPSigningRequest{
		CertDER:   cert.DER,
		Reason:    status.RevokedReason,
		Status:    string(status.Status),
		RevokedAt: status.RevokedDate,
	}

	ocspResponse, err := updater.cac.GenerateOCSP(signRequest)
	if err != nil {
		return responseMeta{}, err
	}

	timestamp := updater.clk.Now()
	status.OCSPLastUpdated = timestamp
	ocspResp := &core.OCSPResponse{Serial: cert.Serial, CreatedAt: timestamp, Response: ocspResponse}
	return responseMeta{ocspResp, &status}, nil
}

func (updater *OCSPUpdater) storeResponse(tx *gorp.Transaction, meta responseMeta) error {
	// Record the response.
	err := tx.Insert(meta.OCSPResponse)
	if err != nil {
		return err
	}

	// Reset the update clock
	_, err = tx.Update(meta.CertificateStatus)
	if err != nil {
		return err
	}

	// Done
	return nil
}

func (updater *OCSPUpdater) newCertificateTick(batchSize int, _, prev time.Time) {
	updater.rpcMu.RLock()

	// Check for anything issued between now and previous tick and generate the
	// OCSP responses and submit them to CT logs using the Publisher
	certs, err := updater.getCertificatesIssuedSince(prev, batchSize)
	if err != nil && err != errNoNewCertificates {
		updater.rpcMu.RUnlock()
		return
	}

	// Do OCSP response generation / CT submission in parallel
	wg := new(sync.WaitGroup)
	updater.generateOCSPResponses(wg, certs)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, cert := range certs {
			err = updater.pub.SubmitToCT(cert.DER)
			if err != nil {
				updater.log.AuditErr(err)
				continue
			}
		}
	}()

	wg.Wait()
	updater.rpcMu.RUnlock()
}

func (updater *OCSPUpdater) missingReceiptsTick(batchSize int, now, _ time.Time) {
	updater.rpcMu.RLock()

	since := now.Add(-updater.oldestIssuedSCT)
	serials, err := updater.getSerialsIssuedSince(since, batchSize)
	if err != nil && err != errNoNewCertificates {
		updater.log.AuditErr(err)
		updater.rpcMu.RUnlock()
		return
	}

	for _, serial := range serials {
		// TODO(rolandshoemaker): For now this will do, in the future we should
		// really have another method that allows us to specify which log/s should
		// be submitted to so we don't double submit to logs we already have receipts
		// for
		if count, err := updater.getNumberOfReceipts(serial); err == nil && count != updater.numLogs {
			var certDER []byte
			updater.dbMap.SelectOne(
				&certDER,
				`SELECT der FROM certificates
					 WHERE serial = :serial`,
				map[string]interface{}{"serial": serial},
			)
			if err != nil {
				updater.log.AuditErr(err)
				continue
			}

			err = updater.pub.SubmitToCT(certDER)
			if err != nil {
				updater.log.AuditErr(err)
				continue
			}
		} else if err != nil {
			updater.log.AuditErr(err)
			continue
		}
	}

	updater.rpcMu.RUnlock()
}

func (updater *OCSPUpdater) generateOCSPResponses(wg *sync.WaitGroup, certs []core.Certificate) {
	responseChan := make(chan responseMeta)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, cert := range certs {
			meta, err := updater.generateResponse(cert)
			if err != nil {
				updater.log.AuditErr(err)
				continue
			}
			responseChan <- meta
		}
		close(responseChan)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		tx, err := updater.dbMap.Begin()
		if err != nil {
			updater.log.AuditErr(err)
			return
		}
		for meta := range responseChan {
			err = updater.storeResponse(tx, meta)
			if err != nil {
				updater.log.AuditErr(err)
				tx.Rollback()
				return
			}
		}
		err = tx.Commit()
		if err != nil {
			updater.log.AuditErr(err)
			return
		}
	}()

	return
}

func (updater *OCSPUpdater) oldOCSPResponsesTick(batchSize int, now, _ time.Time) {
	updater.rpcMu.RLock()

	certs, err := updater.findStaleOCSPResponses(now.Add(-updater.ocspMinTimeToExpiry), batchSize)
	if err != nil && err != errNoStaleResponses {
		updater.stats.Inc("OCSP.Updates.Failed", 1, 1.0)
		updater.log.AuditErr(err)
		updater.rpcMu.RUnlock()
		return
	}

	wg := new(sync.WaitGroup)
	updater.generateOCSPResponses(wg, certs)
	wg.Wait()
	updater.rpcMu.RUnlock()
}

type looper struct {
	clk       clock.Clock
	stats     statsd.Statter
	batchSize int
	tickDur   time.Duration
	tickFunc  func(int, time.Time, time.Time)
	name      string
}

func (l *looper) loop() {
	prev := l.clk.Now().Add(-l.tickDur)
	for {
		now := l.clk.Now()
		l.tickFunc(l.batchSize, now, prev)
		l.stats.TimingDuration(fmt.Sprintf("OCSP.%s.TickDuration", l.name), time.Since(now), 1.0)
		// If the tick didn't take as long as expected sleep for the difference
		if diff := l.clk.Now().Sub(now.Add(l.tickDur)); diff > 0 {
			l.stats.Inc(fmt.Sprintf("OCSP.%s.ShortTicks", l.name), 1, 1.0)
			l.clk.Sleep(diff)
		} else if diff < (-2 * l.tickDur) {
			l.stats.Inc(fmt.Sprintf("OCSP.%s.LongTicks", l.name), 1, 1.0)
		} else {
			l.stats.Inc(fmt.Sprintf("OCSP.%s.NormalTicks", l.name), 1, 1.0)
		}
		prev = now
	}
}

func main() {
	app := cmd.NewAppShell("ocsp-updater", "Generates and updates OCSP responses")

	app.Action = func(c cmd.Config) {
		// Set up logging
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Could not connect to Syslog")

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		blog.SetAuditLogger(auditlogger)

		go cmd.DebugServer(c.OCSPUpdater.DebugAddr)
		go cmd.ProfileCmd("OCSP-Updater", stats)

		// Configure DB
		dbMap, err := sa.NewDbMap(c.OCSPUpdater.DBConnect)
		cmd.FailOnError(err, "Could not connect to database")

		cac, pubc, closeChan := setupClients(c, stats)

		updater, err := newUpdater(
			auditlogger,
			stats,
			clock.Default(),
			dbMap,
			cac,
			pubc,
			// Necessary evil for now
			len(c.Publisher.CT.Logs),
			c.OCSPUpdater,
		)
		cmd.FailOnError(err, "Failed to create updater")

		auditlogger.Info(app.VersionString())

		// Handle AMQP disconnections gracefully (and block other operations while
		// disconnected...)
		go func() {
			for {
				err := <-closeChan
				auditlogger.Warning(fmt.Sprintf(" [!] AMQP Channel closed, will reconnect in 5 seconds: [%s]", err))
				time.Sleep(5 * time.Second)
				updater.rpcMu.Lock()
				updater.cac, updater.pub, closeChan = setupClients(c, stats)
				updater.rpcMu.Unlock()
				auditlogger.Info(" [!] Reconnected to AMQP Channel")
			}
		}()

		go updater.newCertificatesLoop.loop()
		go updater.oldOCSPResponsesLoop.loop()
		go updater.missingReceiptsLoop.loop()

		// Catch INT/TERM/HUP signals and exit after work is done
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM)
		signal.Notify(sigChan, syscall.SIGINT)
		signal.Notify(sigChan, syscall.SIGHUP)

		// Block until signalled
		<-sigChan
		signal.Stop(sigChan)
		auditlogger.Info(" [!] Caught signal, finishing work in progress")

		// We can only acquire a write lock if all read locks have been relinquished so
		// we wait until then before exiting (this is a bit janky and could probably be
		// done better with a WaitGroup and closing channels, but it also helps with restarting
		// so uh... idk)
		updater.rpcMu.Lock()
		return
	}

	app.Run()
}
