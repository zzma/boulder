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
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/rolandshoemaker/hdrhistogram"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/rpc"
)

const (
	testCertDNSName    = "testing.letsencrypt.org"
	testCertCommonName = "Happy Hacker Testing Cert"
)

type rawLatencySeries struct {
	X []time.Time     `json:"x"`
	Y []time.Duration `json:"y"`
}

type latencyPoint struct {
	Dur      time.Duration
	Finished time.Time

	Error   bool
	Timeout bool
}

type combinedSeries []latencyPoint

func (cs combinedSeries) MarshalJSON() ([]byte, error) {
	goodSeries := rawLatencySeries{}
	errorSeries := rawLatencySeries{}
	timeoutSeries := rawLatencySeries{}

	for _, point := range cs {
		switch {
		case point.Error:
			errorSeries.X = append(errorSeries.X, point.Finished)
			errorSeries.Y = append(errorSeries.Y, point.Dur)
		case point.Timeout:
			timeoutSeries.X = append(timeoutSeries.X, point.Finished)
			timeoutSeries.Y = append(timeoutSeries.Y, point.Dur)
		default:
			goodSeries.X = append(goodSeries.X, point.Finished)
			goodSeries.Y = append(goodSeries.Y, point.Dur)
		}
	}

	allSeries := make(map[string]rawLatencySeries, 3)
	if len(errorSeries.X) != 0 {
		allSeries["error"] = errorSeries
	}
	if len(goodSeries.X) != 0 {
		allSeries["good"] = goodSeries
	}
	if len(timeoutSeries.X) != 0 {
		allSeries["timeout"] = timeoutSeries
	}
	jsonSeries, err := json.Marshal(allSeries)
	if err != nil {
		return nil, err
	}

	return jsonSeries, nil
}

type rateSeries struct {
	X        []time.Time `json:"x"`
	GoodY    []float64   `json:"goodY"`
	ErrorY   []float64   `json:"errorY"`
	TimeoutY []float64   `json:"timeoutY"`
	IdealY   float64     `json:"idealY"`
}

type chartData struct {
	Issuance     combinedSeries `json:"issuance,omitempty"`
	IssuanceRate rateSeries     `json:"issuanceRate,omitempty"`
	OCSP         combinedSeries `json:"ocsp,omitempty"`
	OCSPRate     rateSeries     `json:"ocspRate,omitempty"`
}

// So many things on this struct... but this is just for benchmarking? ._.
type bencher struct {
	cac core.CertificateAuthority

	// Pregenerated CSR and OCSP signing request for calls
	csr         x509.CertificateRequest
	regID       int64
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

	// Latency chart data
	chartPath   string
	chartPoints chartData

	debug bool
}

func (b *bencher) updateStats() {
	c := time.NewTicker(b.statsInterval)
	prev := time.Now()
	totalIErrors, totalITimeouts := int64(0), int64(0)
	totalOErrors, totalOTimeouts := int64(0), int64(0)
	for now := range c.C {
		select {
		case <-b.statsStop:
			return
		default:
			if !b.hideStats {
				issuances := atomic.LoadInt64(&b.issuances)
				atomic.StoreInt64(&b.issuances, 0)
				issuanceErrors := atomic.LoadInt64(&b.issuanceErrors)
				atomic.StoreInt64(&b.issuanceErrors, 0)
				issuanceTimeouts := atomic.LoadInt64(&b.issuanceTimeouts)
				atomic.StoreInt64(&b.issuanceTimeouts, 0)
				totalIErrors += issuanceErrors
				totalITimeouts += issuanceTimeouts

				ocspSignings := atomic.LoadInt64(&b.ocspSignings)
				atomic.StoreInt64(&b.ocspSignings, 0)
				ocspSigningErrors := atomic.LoadInt64(&b.ocspSigningErrors)
				atomic.StoreInt64(&b.ocspSigningErrors, 0)
				ocspSigningTimeouts := atomic.LoadInt64(&b.ocspSigningTimeouts)
				atomic.StoreInt64(&b.ocspSigningTimeouts, 0)
				totalOErrors += ocspSigningErrors
				totalOTimeouts += ocspSigningTimeouts

				since := time.Since(prev).Seconds()
				goodCertRate := float64(issuances) / since
				errorCertRate := float64(issuanceErrors) / since
				timeoutCertRate := float64(issuanceTimeouts) / since
				if b.chartPath != "" {
					b.chartPoints.IssuanceRate.X = append(b.chartPoints.IssuanceRate.X, now.UTC())
					b.chartPoints.IssuanceRate.GoodY = append(b.chartPoints.IssuanceRate.GoodY, goodCertRate)
					b.chartPoints.IssuanceRate.ErrorY = append(b.chartPoints.IssuanceRate.ErrorY, errorCertRate)
					b.chartPoints.IssuanceRate.TimeoutY = append(b.chartPoints.IssuanceRate.TimeoutY, timeoutCertRate)
				}

				goodOCSPRate := float64(ocspSignings) / since
				if b.chartPath != "" {
					b.chartPoints.OCSPRate.X = append(b.chartPoints.OCSPRate.X, now.UTC())
					b.chartPoints.OCSPRate.GoodY = append(b.chartPoints.OCSPRate.GoodY, goodOCSPRate)
				}

				fmt.Printf(
					"issuance calls: %d (successful calls: %3.2f/s, errors: %d, timeouts: %d), ocsp calls: %d (successful calls: %3.2f/s, errors: %d, timeouts: %d)\n",
					b.issuanceLatency.TotalCount(),
					goodCertRate,
					totalIErrors,
					totalITimeouts,
					b.ocspLatency.TotalCount(),
					goodOCSPRate,
					totalOErrors,
					totalOTimeouts,
				)
				prev = now
			}
		}
	}
}

func (b *bencher) sendIssueCertificate() {
	s := time.Now()
	_, err := b.cac.IssueCertificate(b.csr, b.regID)
	callDuration := time.Since(s)
	b.issuanceLatency.RecordValue(int64(callDuration / time.Millisecond))
	var lp latencyPoint
	if b.chartPath != "" {
		lp = latencyPoint{
			Dur:      callDuration,
			Finished: s.Add(callDuration).UTC(),
		}
		defer func() {
			b.chartPoints.Issuance = append(b.chartPoints.Issuance, lp)
		}()
	}
	if err != nil {
		if err.Error() == "AMQP-RPC timeout" {
			atomic.AddInt64(&b.issuanceTimeouts, 1)
			lp.Timeout = true
			return
		}
		fmt.Printf("Issuance error: %s\n", err)
		lp.Error = true
		atomic.AddInt64(&b.issuanceErrors, 1)
		return
	}
	atomic.AddInt64(&b.issuances, 1)
}

func (b *bencher) sendGenerateOCSP() {
	s := time.Now()
	_, err := b.cac.GenerateOCSP(b.ocspRequest)
	callDuration := time.Since(s)
	b.ocspLatency.RecordValue(int64(callDuration / time.Millisecond))
	var lp latencyPoint
	if b.chartPath != "" {
		lp = latencyPoint{
			Dur:      callDuration,
			Finished: s.Add(callDuration).UTC(),
		}
		defer func() {
			b.chartPoints.OCSP = append(b.chartPoints.OCSP, lp)
		}()
	}
	if err != nil {
		if err.Error() == "AMQP-RPC timeout" {
			atomic.AddInt64(&b.ocspSigningTimeouts, 1)
			lp.Timeout = true
			return
		}
		fmt.Printf("OCSP error: %s\n", err)
		atomic.AddInt64(&b.ocspSigningErrors, 1)
		lp.Error = true
		return
	}
	atomic.AddInt64(&b.ocspSignings, 1)
}

func (b *bencher) asyncSetupSender(action func(), throughput int) {
	stopChan := make(chan bool, 1)
	b.stopChans = append(b.stopChans, stopChan)
	go func() {
		for {
			select {
			case <-stopChan:
				return
			default:
				go action()
				time.Sleep(time.Duration(time.Second.Nanoseconds() / int64(throughput)))
			}
		}
	}()
}

func (b *bencher) runAsync(issuanceThroughput int, ocspThroughput int) {
	b.started = time.Now()
	b.stopWG = new(sync.WaitGroup)
	go b.updateStats()
	if issuanceThroughput > 0 {
		b.asyncSetupSender(b.sendIssueCertificate, issuanceThroughput)
	}
	if ocspThroughput > 0 {
		b.asyncSetupSender(b.sendGenerateOCSP, ocspThroughput)
	}
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

	if b.chartPath != "" {
		chartJSON, err := json.Marshal(b.chartPoints)
		if err != nil {
			fmt.Printf("Failed to marshal chart points: %s", err)
			return
		}
		err = ioutil.WriteFile(b.chartPath, chartJSON, os.ModePerm)
		if err != nil {
			fmt.Printf("Failed to marshal chart point data: %s", err)
			return
		}
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
			Usage: "How many ca.IssueCertificate RPC calls to send per second (for mode=async)",
		},
		cli.IntFlag{
			Name:  "ocsp",
			Usage: "How many ca.GenerateOCSP RPC calls to send per second (for mode=async)",
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
			Usage: "Hides progress stats, information about the run will still be printed at exit",
		},
		cli.BoolFlag{
			Name:  "debug",
			Usage: "Shows some debug information (byte sizes of HDRHistogram structs)",
		},
		cli.StringFlag{
			Name:  "mode",
			Usage: "Testing mode (async)",
		},
		cli.IntFlag{
			Name:  "regID",
			Value: 1,
			Usage: "Registration ID to use when creating ID (must be from an existing registration)",
		},
		cli.StringFlag{
			Name:  "chartDataPath",
			Usage: "Save latency JSON file to this path which can be consumed by latency-chart.py",
		},
	}

	app.Action = func(c *cli.Context) {
		mode := c.GlobalString("mode")
		if mode != "async" {
			fmt.Println("mode must be either backpressure or async")
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

		randKey, err := rsa.GenerateKey(rand.Reader, 2048)
		cmd.FailOnError(err, "Failed to create test key")
		csrDER, err := x509.CreateCertificateRequest(
			rand.Reader,
			&x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: testCertDNSName},
				DNSNames: []string{testCertDNSName},
			},
			randKey,
		)
		csr, err := x509.ParseCertificateRequest(csrDER)
		cmd.FailOnError(err, "Failed to parse generated CSR")

		now := time.Now()
		template := &x509.Certificate{
			NotBefore:             now,
			NotAfter:              now.Add(time.Hour),
			Subject:               pkix.Name{CommonName: testCertCommonName},
			BasicConstraintsValid: true,
		}
		serialNumber, err := rand.Int(rand.Reader, big.NewInt(1000))
		cmd.FailOnError(err, "Failed to generate random serial number")
		template.SerialNumber = serialNumber

		cert, err := cac.IssueCertificate(*csr, int64(c.GlobalInt("regID")))
		cmd.FailOnError(err, "Failed to generate test certificate for OCSP signing request")

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
			cac:   cac,
			csr:   *csr,
			regID: int64(c.GlobalInt("regID")),
			ocspRequest: core.OCSPSigningRequest{
				CertDER: cert.DER,
				Status:  string(core.OCSPStatusGood),
			},
			statsStop:       make(chan bool, 1),
			statsInterval:   statsInterval,
			hideStats:       c.GlobalBool("hideStats"),
			issuanceLatency: hdrhistogram.New(0, int64(timeoutDuration/time.Millisecond), 5),
			ocspLatency:     hdrhistogram.New(0, int64(timeoutDuration/time.Millisecond), 3),
			chartPath:       c.GlobalString("chartDataPath"),
			debug:           c.GlobalBool("debug"),
		}
		if b.chartPath != "" {
			b.chartPoints.IssuanceRate.IdealY = float64(issuanceSenders)
			// b.chartPoints.OCSPRate.IdealY = float64(ocspSenders)
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
