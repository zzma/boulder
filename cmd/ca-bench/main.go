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
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"

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
	started             time.Time
	totalIssuances      int64
	peakIssuanceRate    float64
	issuances           int64
	issuancesErrors     int64
	totalOCSPSignings   int64
	peakOCSPSigningRate float64
	ocspSignings        int64
	ocspSigningErrors   int64

	// Stats worker state
	stopWG        *sync.WaitGroup
	stopChans     []chan bool
	statsStop     chan bool
	statsInterval time.Duration
	hideStats     bool
}

func (b *bencher) updateStats() {
	c := time.NewTicker(b.statsInterval)
	for _ = range c.C {
		select {
		case <-b.statsStop:
			return
		default:
			// Do the switcheroo
			totalIssuances := atomic.AddInt64(&b.totalIssuances, atomic.LoadInt64(&b.issuances))
			atomic.StoreInt64(&b.issuances, 0)
			totalOCSPSignings := atomic.AddInt64(&b.totalOCSPSignings, atomic.LoadInt64(&b.ocspSignings))
			atomic.StoreInt64(&b.ocspSignings, 0)

			secsSince := float64(time.Since(b.started).Seconds())
			certRate := float64(totalIssuances) / secsSince
			ocspRate := float64(totalOCSPSignings) / secsSince

			if b.peakIssuanceRate == 0.0 || certRate > b.peakIssuanceRate {
				b.peakIssuanceRate = certRate
			}
			if b.peakOCSPSigningRate == 0.0 || ocspRate > b.peakOCSPSigningRate {
				b.peakOCSPSigningRate = ocspRate
			}

			if !b.hideStats {
				fmt.Printf(
					"issuances: %d (rate: %3.2f/s, errors: %d), ocsp signings: %d (rate: %3.2f/s, errors: %d), total rate: %3.2f/s\n",
					totalIssuances,
					certRate,
					atomic.LoadInt64(&b.issuancesErrors),
					totalOCSPSignings,
					ocspRate,
					atomic.LoadInt64(&b.ocspSigningErrors),
					certRate+ocspRate,
				)
			}
		}
	}
}

func (b *bencher) sendIssueCertificate() {
	_, err := b.cac.IssueCertificate(b.csr, 1)
	if err != nil {
		atomic.AddInt64(&b.issuancesErrors, 1)
		return
	}
	atomic.AddInt64(&b.issuances, 1)
}

func (b *bencher) sendGenerateOCSP() {
	_, err := b.cac.GenerateOCSP(b.ocspRequest)
	if err != nil {
		atomic.AddInt64(&b.ocspSigningErrors, 1)
		return
	}
	atomic.AddInt64(&b.ocspSignings, 1)
}

func (b *bencher) run(certSenders, ocspSenders int) {
	b.started = time.Now()
	b.stopWG = new(sync.WaitGroup)
	go b.updateStats()
	for i := 0; i < certSenders; i++ {
		b.stopWG.Add(1)
		stopChan := make(chan bool, 1)
		go func() {
			defer b.stopWG.Done()
			for {
				select {
				case <-stopChan:
					return
				default:
					b.sendIssueCertificate()
				}
			}
		}()
		b.stopChans = append(b.stopChans, stopChan)
	}
	for i := 0; i < ocspSenders; i++ {
		b.stopWG.Add(1)
		stopChan := make(chan bool, 1)
		go func() {
			defer b.stopWG.Done()
			for {
				select {
				case <-stopChan:
					return
				default:
					b.sendGenerateOCSP()
				}
			}
		}()
		b.stopChans = append(b.stopChans, stopChan)
	}
}

func (b *bencher) stop() {
	b.statsStop <- true
	for _, stopChan := range b.stopChans {
		stopChan <- true
	}
	b.stopWG.Wait()
	fmt.Printf(
		"Stopped, ran for: %s, total issuances: %d (peak issuance rate: %3.2f/s), total ocsp signings: %d (peak ocsp signing rate: %3.2f/s)\n",
		time.Since(b.started),
		b.totalIssuances,
		b.peakIssuanceRate,
		b.totalOCSPSignings,
		b.peakOCSPSigningRate,
	)
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
			Name:  "issuanceSenders",
			Usage: "Number of goroutines sending ca.IssueCertificate RPC calls",
		},
		cli.IntFlag{
			Name:  "ocspSenders",
			Usage: "Number of goroutines sending ca.GenerateOCSP RPc calls",
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
	}

	app.Action = func(c *cli.Context) {
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

		issuanceSenders := c.GlobalInt("issuanceSenders")
		ocspSenders := c.GlobalInt("ocspSenders")

		if issuanceSenders <= 0 && ocspSenders <= 0 {
			fmt.Println("Either issuanceSenders or ocspSenders required")
			return
		}

		statsInterval, err := time.ParseDuration(c.GlobalString("statsInterval"))
		cmd.FailOnError(err, "Failed to parse statsInterval")

		b := bencher{
			cac: cac,
			csr: *csr,
			ocspRequest: core.OCSPSigningRequest{
				CertDER: cert.Raw,
				Status:  string(core.OCSPStatusGood),
			},
			statsStop:     make(chan bool, 1),
			statsInterval: statsInterval,
			hideStats:     c.GlobalBool("hideStats"),
		}

		b.run(issuanceSenders, ocspSenders)

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
		b.stop()
	}

	app.Run(os.Args)
}
