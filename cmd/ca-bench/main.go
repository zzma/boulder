package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/helpers"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/rolandshoemaker/hdrhistogram"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/rpc"
)

// So many things on this struct... but this is just for benchmarking? ._.
type bencher struct {
	cac core.CertificateAuthority

	// Pregenerated CSR and OCSP signing request for calls
	csr         x509.CertificateRequest
	ocspRequest core.OCSPSigningRequest

	// Metadeta for generating stats
	started time.Time

	// latency histograms
	issuanceLatency *hdrhistogram.Histogram
	ocspLatency     *hdrhistogram.Histogram

	// Running totals
	issuances           int64
	issuanceErrors      int64
	issuanceTimeouts    int64
	ocspSignings        int64
	ocspSigningErrors   int64
	ocspSigningTimeouts int64

	// Stats worker state
	stopWG        *sync.WaitGroup
	stopChans     []chan bool
	statsStop     chan bool
	statsInterval time.Duration
	hideStats     bool

	debug bool
}

func (b *bencher) updateStats() {
	c := time.NewTicker(b.statsInterval)
	for _ = range c.C {
		select {
		case <-b.statsStop:
			return
		default:
			if !b.hideStats {
				issuances := b.issuanceLatency.TotalCount()
				issuanceErrors := atomic.LoadInt64(&b.issuanceErrors)
				issuanceTimeouts := atomic.LoadInt64(&b.issuanceTimeouts)
				ocspSignings := b.ocspLatency.TotalCount()
				ocspSigningErrors := atomic.LoadInt64(&b.ocspSigningErrors)
				ocspSigningTimeouts := atomic.LoadInt64(&b.ocspSigningTimeouts)

				issuances -= (issuanceErrors + issuanceTimeouts)
				ocspSignings -= (ocspSigningErrors + ocspSigningTimeouts)

				certRate := float64(issuances) / time.Since(b.started).Seconds()
				ocspRate := float64(ocspSignings) / time.Since(b.started).Seconds()

				fmt.Printf(
					"issuances: %d (avg rate: %3.2f/s, errors: %d, timeouts: %d), ocsp signings: %d (avg rate: %3.2f/s, errors: %d, timeouts: %d)\n",
					issuances,
					certRate,
					issuanceErrors,
					issuanceTimeouts,
					ocspSignings,
					ocspRate,
					ocspSigningErrors,
					ocspSigningTimeouts,
				)
			}
		}
	}
}

func (b *bencher) sendIssueCertificate() {
	s := time.Now()
	_, err := b.cac.IssueCertificate(b.csr, 1)
	b.issuanceLatency.RecordValue(int64(time.Since(s) / time.Millisecond))
	// b.issuanceLatency.RecordCorrectedValue(int64(time.Since(s)/time.Millisecond), int64(b.issuanceLatency.Mean()))
	if err != nil {
		if err.Error() == "AMQP-RPC timeout" {
			atomic.AddInt64(&b.issuanceTimeouts, 1)
			return
		}
		fmt.Printf("Issuance error: %s\n", err)
		atomic.AddInt64(&b.issuanceErrors, 1)
		return
	}
	atomic.AddInt64(&b.issuances, 1)
}

func (b *bencher) sendGenerateOCSP() {
	s := time.Now()
	_, err := b.cac.GenerateOCSP(b.ocspRequest)
	b.ocspLatency.RecordValue(int64(time.Since(s) / time.Millisecond))
	if err != nil {
		if err.Error() == "AMQP-RPC timeout" {
			atomic.AddInt64(&b.ocspSigningTimeouts, 1)
			return
		}
		fmt.Printf("OCSP error: %s\n", err)
		atomic.AddInt64(&b.ocspSigningErrors, 1)
		return
	}
	atomic.AddInt64(&b.ocspSignings, 1)
}

func (b *bencher) serialSender(action func(), maxSenders int64) {
	workers := int64(0)
	stopChan := make(chan bool, 1)
	b.stopChans = append(b.stopChans, stopChan)
	for {
		select {
		case <-stopChan:
			return
		default:
			if atomic.LoadInt64(&workers) < maxSenders {
				atomic.AddInt64(&workers, 1)
				go func() {
					defer atomic.AddInt64(&workers, -1)
					action()
				}()
			}
		}
	}
}

func (b *bencher) runSerial(maxIssuance int, maxOCSP int) {
	b.started = time.Now()
	b.stopWG = new(sync.WaitGroup)
	go b.updateStats()
	go b.serialSender(b.sendIssueCertificate, int64(maxIssuance))
	go b.serialSender(b.sendGenerateOCSP, int64(maxOCSP))
}

func (b *bencher) asyncSetupSender(action func(), throughput int) {
	for i := 0; i < throughput; i++ {
		go func() {
			stopChan := make(chan bool, 1)
			b.stopChans = append(b.stopChans, stopChan)
			for {
				select {
				case <-stopChan:
					return
				default:
					go action()
					time.Sleep(time.Second)
				}
			}
		}()
	}
}

func (b *bencher) runAsync(issuanceThroughput int, ocspThroughput int) {
	b.started = time.Now()
	b.stopWG = new(sync.WaitGroup)
	go b.updateStats()
	b.asyncSetupSender(b.sendIssueCertificate, issuanceThroughput)
	b.asyncSetupSender(b.sendGenerateOCSP, ocspThroughput)
}

func (b *bencher) stop() {
	b.statsStop <- true
	for _, stopChan := range b.stopChans {
		stopChan <- true
	}
	b.stopWG.Wait()
	fmt.Printf("Stopped, ran for %s\n", time.Since(b.started))
	if b.issuanceLatency.TotalCount() != 0 {
		fmt.Printf(
			"\nCertificate Issuance\nCount: %d (%d errors)\nLatency: Max %s, Min %s, Avg %s\n",
			b.issuanceLatency.TotalCount(),
			b.issuanceErrors,
			time.Duration(b.issuanceLatency.Max()),
			time.Duration(b.issuanceLatency.Min()),
			time.Duration(int64(b.issuanceLatency.Mean())),
		)
		fmt.Printf("\n%s\n", b.issuanceLatency)
	}
	if b.ocspLatency.TotalCount() != 0 {
		fmt.Printf(
			"\nOCSP Signing\nCount: %d (%d errors)\nLatency: Max %s, Min %s, Avg %s\n",
			b.ocspLatency.TotalCount(),
			b.ocspSigningErrors,
			time.Duration(b.ocspLatency.Max()),
			time.Duration(b.ocspLatency.Min()),
			time.Duration(int64(b.ocspLatency.Mean())),
		)
		fmt.Printf("\n%s\n", b.ocspLatency)
	}

	if b.debug {
		fmt.Printf(
			"\nDEBUG\nb.issuanceLatency: %d bytes\nb.ocspLatency: %d bytes\n",
			b.issuanceLatency.ByteSize(),
			b.ocspLatency.ByteSize(),
		)
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "ca-bench"
	app.Usage = "Benchmarking tool for boulder-ca"
	app.Version = cmd.Version()
	app.Author = "Boulder contributors"
	app.Email = "ca-dev@letsencrypt.org"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "config",
			Value:  "config.json",
			EnvVar: "BOULDER_CONFIG",
			Usage:  "Path to Boulder JSON configuration file",
		},
		cli.IntFlag{
			Name:  "issuance",
			Usage: "How many ca.IssueCertificate RPC calls to make (if mode=pool this is the max concurrent senders, if mode=async this is how many calls to send per second)",
		},
		cli.IntFlag{
			Name:  "ocsp",
			Usage: "How many ca.GenerateOCSP RPC calls to make (if mode=pool this is the max concurrent senders, if mode=async this is how many calls to send per second)",
		},
		cli.StringFlag{
			Name:  "benchTime",
			Usage: "Time to run for suffixed with s, m, or h",
		},
		cli.StringFlag{
			Name:  "statsInterval",
			Usage: "Stats calculation/printing interval suffixed with s, m, or h",
			Value: "5s",
		},
		cli.BoolFlag{
			Name:  "hideStats",
			Usage: "Hides in progress stats, information about the run will still be printed at exit",
		},
		cli.StringFlag{
			Name:  "issuerKeyPath",
			Usage: "Path to correct issuer key to use for generating certificates and ocsp requests",
		},
		cli.StringFlag{
			Name:  "issuerPath",
			Usage: "Path to correct issuer cert to use for generating certificates and ocsp requests",
		},
		cli.BoolFlag{
			Name:  "debug",
			Usage: "Shows some debug information",
		},
		cli.StringFlag{
			Name:  "mode",
			Usage: "Testing mode (pool|async)",
		},
	}

	app.Action = func(c *cli.Context) {
		mode := c.GlobalString("mode")
		if mode != "pool" && mode != "async" {
			fmt.Println("mode must be either pool or async")
			return
		}

		configFileName := c.GlobalString("config")
		configJSON, err := ioutil.ReadFile(configFileName)
		cmd.FailOnError(err, "Unable to read config file")

		var config cmd.Config
		err = json.Unmarshal(configJSON, &config)
		cmd.FailOnError(err, "Failed to read configuration")

		ch, err := rpc.AmqpChannel(config)
		cmd.FailOnError(err, "Could not connect to AMQP")

		stats, err := statsd.NewClient(config.Statsd.Server, config.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		caRPC, err := rpc.NewAmqpRPCClient("Bencher->CA", config.AMQP.CA.Server, ch, stats)
		cmd.FailOnError(err, "Unable to create RPC client")

		cac, err := rpc.NewCertificateAuthorityClient(caRPC)
		cmd.FailOnError(err, "Unable to create CA client")

		issuerPath := c.GlobalString("issuerPath")
		issuerKeyPath := c.GlobalString("issuerKeyPath")
		if issuerPath == "" || issuerKeyPath == "" {
			fmt.Println("Both issuerPath and issuerKeyPath are required")
			return
		}

		issuer, err := core.LoadCert(issuerPath)
		cmd.FailOnError(err, "Failed to load issuer certificate")
		var keyBytes []byte
		keyBytes, err = ioutil.ReadFile(issuerKeyPath)
		cmd.FailOnError(err, "Failed to read issuer key")
		issuerKeyObj, err := helpers.ParsePrivateKeyPEM(keyBytes)
		cmd.FailOnError(err, "Failed to parse issuer key")
		issuerKey := issuerKeyObj.(*rsa.PrivateKey)

		csrDER, err := x509.CreateCertificateRequest(
			rand.Reader,
			&x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: "wat.com"},
				DNSNames: []string{"wat.com"},
			},
			issuerKey,
		)
		csr, err := x509.ParseCertificateRequest(csrDER)
		cmd.FailOnError(err, "Failed to parse generated CSR")

		now := time.Now()
		template := &x509.Certificate{
			NotBefore:             now,
			NotAfter:              now.Add(time.Hour),
			Subject:               pkix.Name{CommonName: "Happy Hacker Fake Cert"},
			BasicConstraintsValid: true,
		}
		serialNumber, err := rand.Int(rand.Reader, big.NewInt(1000))
		cmd.FailOnError(err, "Failed to generate random serial number")
		template.SerialNumber = serialNumber

		certDER, err := x509.CreateCertificate(rand.Reader, template, issuer, &issuerKey.PublicKey, issuerKey)
		cmd.FailOnError(err, "Failed to generate test certificate")
		cert, err := x509.ParseCertificate(certDER)
		cmd.FailOnError(err, "Failed to parse test certificate")

		issuanceSenders := c.GlobalInt("issuance")
		ocspSenders := c.GlobalInt("ocsp")

		if issuanceSenders <= 0 && ocspSenders <= 0 {
			fmt.Println("Either issuance or ocsp required")
			return
		}

		statsInterval, err := time.ParseDuration(c.GlobalString("statsInterval"))
		cmd.FailOnError(err, "Failed to parse statsInterval")

		timeoutDuration := 10 * time.Second

		b := bencher{
			cac: cac,
			csr: *csr,
			ocspRequest: core.OCSPSigningRequest{
				CertDER: cert.Raw,
				Status:  string(core.OCSPStatusGood),
			},
			statsStop:       make(chan bool, 1),
			statsInterval:   statsInterval,
			hideStats:       c.GlobalBool("hideStats"),
			issuanceLatency: hdrhistogram.New(0, int64(timeoutDuration/time.Millisecond), 5),
			ocspLatency:     hdrhistogram.New(0, int64(timeoutDuration/time.Millisecond), 3),
			debug:           c.GlobalBool("debug"),
		}

		// Setup signal catching and such
		iMu := new(sync.Mutex)
		go func() {
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGTERM)
			signal.Notify(sigChan, syscall.SIGINT)
			signal.Notify(sigChan, syscall.SIGHUP)

			<-sigChan
			fmt.Printf("\nInterrupted\n\n")
			// Can only grab the lock if the stop below hasn't grabbed it first
			iMu.Lock()
			b.stop()
			os.Exit(0)
		}()

		switch mode {
		case "pool":
			b.runSerial(issuanceSenders, ocspSenders)
		case "async":
			b.runAsync(issuanceSenders, ocspSenders)
		}

		runtimeStr := c.GlobalString("benchTime")
		if runtimeStr == "" {
			fmt.Println("Running indefinitely")
			forever := make(chan bool)
			<-forever
		}
		runtime, err := time.ParseDuration(runtimeStr)
		cmd.FailOnError(err, "Failed to parse benchTime")
		fmt.Printf("Running for (approximately) %s\n", runtime)

		time.Sleep(runtime)
		iMu.Lock()
		b.stop()
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}
