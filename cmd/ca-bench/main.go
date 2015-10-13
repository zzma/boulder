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
	"strconv"
	"strings"
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
	testCertCommonName = "Happy Hacker Benching Cert"
)

func humanTime(seconds int) string {
	nanos := time.Duration(seconds) * time.Second
	hours := int(nanos / (time.Hour))
	nanos %= time.Hour
	minutes := int(nanos / time.Minute)
	nanos %= time.Minute
	seconds = int(nanos / time.Second)
	s := ""
	if hours > 0 {
		s += fmt.Sprintf("%dh", hours)
	}
	if minutes > 0 {
		s += fmt.Sprintf("%dm", minutes)
	}
	if seconds >= 0 {
		s += fmt.Sprintf("%ds", seconds)
	}
	return s
}

type histWrapper struct {
	*hdrhistogram.Histogram
}

func (hw histWrapper) MarshalJSON() ([]byte, error) {
	var marshaler struct {
		X      []float64 `json:"x"`
		ValueY []int64   `json:"valueY"`
		CountY []int64   `json:"countY"`
	}
	for _, b := range hw.CumulativeDistribution() {
		marshaler.X = append(marshaler.X, b.Quantile/100)
		marshaler.ValueY = append(marshaler.ValueY, b.ValueAt)
		marshaler.CountY = append(marshaler.CountY, b.Count)
	}
	return json.Marshal(marshaler)
}

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

type chartData struct {
	Issuance        combinedSeries `json:"issuance,omitempty"`
	IssuanceLatency histWrapper    `json:"issuanceLatency,omitempty"`
	IssuanceSent    int            `json:"issuanceSent,omitempty"`
	OCSP            combinedSeries `json:"ocsp,omitempty"`
	OCSPLatency     histWrapper    `json:"ocspLatency,omitempty"`
	OCSPSent        int            `json:"ocspSent,omitempty"`
}

// So many things on this struct... but this is just for benchmarking? ._.
type bencher struct {
	cac core.CertificateAuthority

	issuanceThroughput int64
	ocspThroughput     int64

	// Pregenerated CSR and OCSP signing request for calls
	csr         x509.CertificateRequest
	regID       int64
	ocspRequest core.OCSPSigningRequest

	// Metadeta for generating stats
	started time.Time

	// Running totals
	issuanceErrors      int64
	issuanceTimeouts    int64
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

	debugHist bool
	printHist bool
}

func (b *bencher) printStats() {
	c := time.NewTicker(b.statsInterval)
	for _ = range c.C {
		select {
		case <-b.statsStop:
			return
		default:
			issuances := b.chartPoints.IssuanceLatency.TotalCount()
			issuanceErrors := atomic.LoadInt64(&b.issuanceErrors)
			issuanceTimeouts := atomic.LoadInt64(&b.issuanceTimeouts)

			ocspSignings := b.chartPoints.OCSPLatency.TotalCount()
			ocspSigningErrors := atomic.LoadInt64(&b.ocspSigningErrors)
			ocspSigningTimeouts := atomic.LoadInt64(&b.ocspSigningTimeouts)

			since := time.Since(b.started).Seconds()
			fmt.Printf("running for: %s", humanTime(int(since)))
			if issuances > 0 {
				goodCertRate := float64(issuances-issuanceErrors-issuanceTimeouts) / since
				fmt.Printf(
					", issuance calls: %d (avg success rate: %3.2f/s, errors: %d, timeouts: %d)",
					issuances,
					goodCertRate,
					issuanceErrors,
					issuanceTimeouts,
				)
			}
			if issuances > 0 && ocspSignings == 0 {
				fmt.Printf("\n")
			} else {
				fmt.Printf(", ")
			}
			if ocspSignings > 0 {
				goodOCSPRate := float64(ocspSignings-ocspSigningErrors-ocspSigningTimeouts) / since
				fmt.Printf(
					"ocsp calls: %d (avg success rate: %3.2f/s, errors: %d, timeouts: %d)\n",
					ocspSignings,
					goodOCSPRate,
					ocspSigningErrors,
					ocspSigningTimeouts,
				)
			}
		}
	}
}

func (b *bencher) sendIssueCertificate() {
	s := time.Now()
	_, err := b.cac.IssueCertificate(b.csr, b.regID)
	callDuration := time.Since(s)
	b.chartPoints.IssuanceLatency.RecordValue(callDuration.Nanoseconds())
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
}

func (b *bencher) sendGenerateOCSP() {
	s := time.Now()
	_, err := b.cac.GenerateOCSP(b.ocspRequest)
	callDuration := time.Since(s)
	b.chartPoints.OCSPLatency.RecordValue(callDuration.Nanoseconds())
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
}

func (b *bencher) asyncSetupSender(action func(), throughput *int64) {
	stopChan := make(chan bool, 1)
	b.stopChans = append(b.stopChans, stopChan)
	b.stopWG.Add(1)
	go func() {
		for {
			select {
			case <-stopChan:
				b.stopWG.Done()
				return
			default:
				go action()
				time.Sleep(time.Duration(time.Second.Nanoseconds() / atomic.LoadInt64(throughput)))
			}
		}
	}()
}

func (b *bencher) runAsync() {
	b.started = time.Now()
	b.stopWG = new(sync.WaitGroup)
	if !b.hideStats {
		go b.printStats()
	}
	if b.issuanceThroughput > 0 {
		b.asyncSetupSender(b.sendIssueCertificate, &b.issuanceThroughput)
	}
	if b.ocspThroughput > 0 {
		b.asyncSetupSender(b.sendGenerateOCSP, &b.ocspThroughput)
	}
}

type event struct {
	After time.Duration
	SetTo int64
}

func eventParser(eventString string) ([]event, error) {
	events := []event{}
	sections := strings.Split(eventString, ":")
	for _, s := range sections {
		fields := strings.Split(s, ",")
		if len(fields) != 2 {
			return nil, fmt.Errorf("Invalid event format")
		}
		after, err := time.ParseDuration(fields[1])
		if err != nil {
			return nil, err
		}
		setTo, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, err
		}
		if setTo <= 0 {
			return nil, fmt.Errorf("throughput must be a positive non-zero integer")
		}
		events = append(events, event{
			After: after,
			SetTo: int64(setTo),
		})
	}
	return events, nil
}

func (b *bencher) changeThroughput(events []event, throughput *int64, what string) {
	for _, e := range events {
		time.Sleep(e.After)
		atomic.StoreInt64(throughput, e.SetTo)
		fmt.Printf("Updated %s throughput to %d/s\n", what, e.SetTo)
	}
}

func (b *bencher) stop() {
	b.statsStop <- true
	for _, stopChan := range b.stopChans {
		stopChan <- true
	}
	b.stopWG.Wait()

	fmt.Printf("Stopped, ran for %s\n", humanTime(int(time.Since(b.started).Seconds())))
	if b.chartPoints.IssuanceLatency.TotalCount() != 0 {
		fmt.Printf(
			"\nCertificate Issuance\nCount: %d (%d errors)\nLatency: Max %s, Min %s, Avg %s\n",
			b.chartPoints.IssuanceLatency.TotalCount(),
			b.issuanceErrors,
			time.Duration(b.chartPoints.IssuanceLatency.Max()),
			time.Duration(b.chartPoints.IssuanceLatency.Min()),
			time.Duration(int64(b.chartPoints.IssuanceLatency.Mean())),
		)
		if b.printHist {
			fmt.Printf("\n%s\n", b.chartPoints.IssuanceLatency)
		}
	}
	if b.chartPoints.OCSPLatency.TotalCount() != 0 {
		fmt.Printf(
			"\nOCSP Signing\nCount: %d (%d errors)\nLatency: Max %s, Min %s, Avg %s\n",
			b.chartPoints.OCSPLatency.TotalCount(),
			b.ocspSigningErrors,
			time.Duration(b.chartPoints.OCSPLatency.Max()),
			time.Duration(b.chartPoints.OCSPLatency.Min()),
			time.Duration(int64(b.chartPoints.OCSPLatency.Mean())),
		)
		if b.printHist {
			fmt.Printf("\n%s\n", b.chartPoints.OCSPLatency)
		}
	}

	if b.debugHist {
		fmt.Printf(
			"\nDEBUG\nb.issuanceLatency: %d bytes\nb.ocspLatency: %d bytes\n",
			b.chartPoints.IssuanceLatency.ByteSize(),
			b.chartPoints.OCSPLatency.ByteSize(),
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
			Usage: "How many ca.IssueCertificate RPC calls to send per second",
		},
		cli.IntFlag{
			Name:  "ocsp",
			Usage: "How many ca.GenerateOCSP RPC calls to send per second",
		},
		cli.StringFlag{
			Name:  "benchTime",
			Usage: "Time to run for suffixed with s, m, or h",
		},
		cli.StringFlag{
			Name:  "statsInterval",
			Usage: "Interval at which to print stats suffixed with s, m, or h",
			Value: "5s",
		},
		cli.BoolFlag{
			Name:  "hideStats",
			Usage: "Hides progress stats, information about the run will still be printed at exit",
		},
		cli.BoolFlag{
			Name:  "debugHist",
			Usage: "Shows some debug information about histograms (byte sizes of HDRHistogram structs)",
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
		cli.BoolFlag{
			Name:  "printHist",
			Usage: "Print HDRHistogram structs (using the chartable format)",
		},
		cli.StringFlag{
			Name:  "issuanceEvents",
			Usage: "Allows changes in issuance throughput over the test (to set throughput to 10 after 5m then 20 after another 10 minutes the format is '10,5m:20,10m')",
		},
		cli.StringFlag{
			Name:  "ocspEvents",
			Usage: "Allows changes in ocsp throughput over the test (to set throughput to 10 after 5m then 20 after another 10 minutes the format is '10,5m:20,10m')",
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

		issuanceEventString, ocspEventString := c.GlobalString("issuanceEvents"), c.GlobalString("ocspEvents")
		issuanceEvents, ocspEvents := []event{}, []event{}
		if issuanceEventString != "" {
			issuanceEvents, err = eventParser(issuanceEventString)
			cmd.FailOnError(err, "Failed to parse issuance events")
		}
		if ocspEventString != "" {
			ocspEvents, err = eventParser(ocspEventString)
			cmd.FailOnError(err, "Failed to parse ocsp events")
		}

		statsInterval, err := time.ParseDuration(c.GlobalString("statsInterval"))
		cmd.FailOnError(err, "Failed to parse statsInterval")

		timeoutDuration := 10 * time.Second

		b := bencher{
			cac:                cac,
			issuanceThroughput: int64(issuanceSenders),
			ocspThroughput:     int64(ocspSenders),
			csr:                *csr,
			regID:              int64(c.GlobalInt("regID")),
			ocspRequest: core.OCSPSigningRequest{
				CertDER: cert.DER,
				Status:  string(core.OCSPStatusGood),
			},
			statsStop:     make(chan bool, 1),
			statsInterval: statsInterval,
			hideStats:     c.GlobalBool("hideStats"),
			chartPoints: chartData{
				IssuanceLatency: histWrapper{hdrhistogram.New(0, int64(timeoutDuration), 5)},
				OCSPLatency:     histWrapper{hdrhistogram.New(0, int64(timeoutDuration), 3)},
			},
			chartPath: c.GlobalString("chartDataPath"),
			debugHist: c.GlobalBool("debugHist"),
		}
		if b.chartPath != "" {
			b.chartPoints.IssuanceSent = issuanceSenders
			b.chartPoints.OCSPSent = ocspSenders
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
			// Can only grab the lock if the stop below hasn't grabbed it first, this is
			// bad and needs to be fixed...
			iMu.Lock()
			b.stop()
			os.Exit(0)
		}()

		b.runAsync()

		if len(issuanceEvents) != 0 {
			go b.changeThroughput(issuanceEvents, &b.issuanceThroughput, "issuance")
		}
		if len(ocspEvents) != 0 {
			go b.changeThroughput(ocspEvents, &b.ocspThroughput, "ocsp")
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
