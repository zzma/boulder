package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log/syslog"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint"
	"github.com/zmap/zlint/lints"

	"github.com/zzma/boulder/cmd"
	"github.com/zzma/boulder/core"
	"github.com/zzma/boulder/features"
	"github.com/zzma/boulder/identifier"
	blog "github.com/zzma/boulder/log"
	"github.com/zzma/boulder/metrics"
	"github.com/zzma/boulder/policy"
	"github.com/zzma/boulder/sa"
)

const (
	good = "valid"
	bad  = "invalid"

	filenameLayout = "20060102"

	expectedValidityPeriod = time.Hour * 24 * 90
)

// For defense-in-depth in addition to using the PA & its hostnamePolicy to
// check domain names we also perform a check against the regex's from the
// forbiddenDomains array
var forbiddenDomainPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^\s*$`),
	regexp.MustCompile(`\.local$`),
	regexp.MustCompile(`^localhost$`),
	regexp.MustCompile(`\.localhost$`),
}

func isForbiddenDomain(name string) (bool, string) {
	for _, r := range forbiddenDomainPatterns {
		if matches := r.FindAllStringSubmatch(name, -1); len(matches) > 0 {
			return true, r.String()
		}
	}
	return false, ""
}

var batchSize = 1000

type report struct {
	begin     time.Time
	end       time.Time
	GoodCerts int64                  `json:"good-certs"`
	BadCerts  int64                  `json:"bad-certs"`
	Entries   map[string]reportEntry `json:"entries"`
}

func (r *report) dump() error {
	content, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, string(content))
	return nil
}

type reportEntry struct {
	Valid    bool     `json:"valid"`
	Problems []string `json:"problems,omitempty"`
}

/*
 * certDB is an interface collecting the gorp.DbMap functions that the
 * various parts of cert-checker rely on. Using this adapter shim allows tests to
 * swap out the dbMap implementation.
 */
type certDB interface {
	Select(i interface{}, query string, args ...interface{}) ([]interface{}, error)
	SelectOne(holder interface{}, query string, args ...interface{}) error
}

type certChecker struct {
	pa           core.PolicyAuthority
	dbMap        certDB
	certs        chan core.Certificate
	clock        clock.Clock
	rMu          *sync.Mutex
	issuedReport report
	checkPeriod  time.Duration
	stats        metrics.Scope
}

func newChecker(saDbMap certDB, clk clock.Clock, pa core.PolicyAuthority, period time.Duration) certChecker {
	c := certChecker{
		pa:          pa,
		dbMap:       saDbMap,
		certs:       make(chan core.Certificate, batchSize),
		rMu:         new(sync.Mutex),
		clock:       clk,
		checkPeriod: period,
	}
	c.issuedReport.Entries = make(map[string]reportEntry)

	return c
}

func (c *certChecker) getCerts(unexpiredOnly bool) error {
	c.issuedReport.end = c.clock.Now()
	c.issuedReport.begin = c.issuedReport.end.Add(-c.checkPeriod)

	args := map[string]interface{}{"issued": c.issuedReport.begin, "now": 0}
	if unexpiredOnly {
		now := c.clock.Now()
		args["now"] = now
	}
	var count int
	err := c.dbMap.SelectOne(
		&count,
		"SELECT count(*) FROM certificates WHERE issued >= :issued AND expires >= :now",
		args,
	)
	if err != nil {
		return err
	}

	var initialID int
	err = c.dbMap.SelectOne(
		&initialID,
		"SELECT id FROM certificates WHERE issued >= :issued AND expires >= :now LIMIT 1",
		args,
	)
	if err != nil {
		return err
	}
	if initialID > 0 {
		// decrement the initial ID so that we select below as we aren't using >=
		initialID -= 1
	}

	// Retrieve certs in batches of 1000 (the size of the certificate channel)
	// so that we don't eat unnecessary amounts of memory and avoid the 16MB MySQL
	// packet limit.
	args["limit"] = batchSize
	args["id"] = initialID
	for offset := 0; offset < count; {
		certs, err := sa.SelectCertificates(
			c.dbMap,
			"WHERE id > :id AND expires >= :now ORDER BY id LIMIT :limit",
			args,
		)
		if err != nil {
			return err
		}
		for _, cert := range certs {
			c.certs <- cert.Certificate
		}
		if len(certs) == 0 {
			break
		}
		args["id"] = certs[len(certs)-1].ID
		offset += len(certs)
	}

	// Close channel so range operations won't block once the channel empties out
	close(c.certs)
	return nil
}

func (c *certChecker) processCerts(wg *sync.WaitGroup, badResultsOnly bool, ignoredLints map[string]bool) {
	for cert := range c.certs {
		problems := c.checkCert(cert, ignoredLints)
		valid := len(problems) == 0
		c.rMu.Lock()
		if !badResultsOnly || (badResultsOnly && !valid) {
			c.issuedReport.Entries[cert.Serial] = reportEntry{
				Valid:    valid,
				Problems: problems,
			}
		}
		c.rMu.Unlock()
		if !valid {
			atomic.AddInt64(&c.issuedReport.BadCerts, 1)
		} else {
			atomic.AddInt64(&c.issuedReport.GoodCerts, 1)
		}
	}
	wg.Done()
}

// Extensions that we allow in certificates
var allowedExtensions = map[string]bool{
	"1.3.6.1.5.5.7.1.1":       true, // Authority info access
	"2.5.29.35":               true, // Authority key identifier
	"2.5.29.19":               true, // Basic constraints
	"2.5.29.32":               true, // Certificate policies
	"2.5.29.31":               true, // CRL distribution points
	"2.5.29.37":               true, // Extended key usage
	"2.5.29.15":               true, // Key usage
	"2.5.29.17":               true, // Subject alternative name
	"2.5.29.14":               true, // Subject key identifier
	"1.3.6.1.4.1.11129.2.4.2": true, // SCT list
	"1.3.6.1.5.5.7.1.24":      true, // TLS feature
}

// For extensions that have a fixed value we check that it contains that value
var expectedExtensionContent = map[string][]byte{
	"1.3.6.1.5.5.7.1.24": []byte{0x30, 0x03, 0x02, 0x01, 0x05}, // Must staple feature
}

func (c *certChecker) checkCert(cert core.Certificate, ignoredLints map[string]bool) (problems []string) {
	// Check digests match
	if cert.Digest != core.Fingerprint256(cert.DER) {
		problems = append(problems, "Stored digest doesn't match certificate digest")
	}

	// Parse certificate
	parsedCert, err := x509.ParseCertificate(cert.DER)
	if err != nil {
		problems = append(problems, fmt.Sprintf("Couldn't parse stored certificate: %s", err))
	} else {
		// Run zlint checks
		results := zlint.LintCertificate(parsedCert)
		for name, res := range results.Results {
			if ignoredLints[name] || res.Status <= lints.Pass {
				continue
			}
			prob := fmt.Sprintf("zlint %s: %s", res.Status, name)
			if res.Details != "" {
				prob = fmt.Sprintf("%s %s", prob, res.Details)
			}
			problems = append(problems, prob)
		}
		// Check stored serial is correct
		storedSerial, err := core.StringToSerial(cert.Serial)
		if err != nil {
			problems = append(problems, "Stored serial is invalid")
		} else if parsedCert.SerialNumber.Cmp(storedSerial) != 0 {
			problems = append(problems, "Stored serial doesn't match certificate serial")
		}
		// Check we have the right expiration time
		if !parsedCert.NotAfter.Equal(cert.Expires) {
			problems = append(problems, "Stored expiration doesn't match certificate NotAfter")
		}
		// Check basic constraints are set
		if !parsedCert.BasicConstraintsValid {
			problems = append(problems, "Certificate doesn't have basic constraints set")
		}
		// Check the cert isn't able to sign other certificates
		if parsedCert.IsCA {
			problems = append(problems, "Certificate can sign other certificates")
		}
		// Check the cert has the correct validity period
		validityPeriod := parsedCert.NotAfter.Sub(parsedCert.NotBefore)
		if validityPeriod > expectedValidityPeriod {
			problems = append(problems, fmt.Sprintf("Certificate has a validity period longer than %s", expectedValidityPeriod))
		} else if validityPeriod < expectedValidityPeriod {
			problems = append(problems, fmt.Sprintf("Certificate has a validity period shorter than %s", expectedValidityPeriod))
		}
		// Check the stored issuance time isn't too far back/forward dated
		if parsedCert.NotBefore.Before(cert.Issued.Add(-6*time.Hour)) || parsedCert.NotBefore.After(cert.Issued.Add(6*time.Hour)) {
			problems = append(problems, "Stored issuance date is outside of 6 hour window of certificate NotBefore")
		}
		// Check CommonName is <= 64 characters
		if len(parsedCert.Subject.CommonName) > 64 {
			problems = append(
				problems,
				fmt.Sprintf("Certificate has common name >64 characters long (%d)", len(parsedCert.Subject.CommonName)),
			)
		}
		// Check that the PA is still willing to issue for each name in DNSNames + CommonName
		for _, name := range append(parsedCert.DNSNames, parsedCert.Subject.CommonName) {
			id := identifier.ACMEIdentifier{Type: identifier.DNS, Value: name}
			// TODO(https://github.com/letsencrypt/boulder/issues/3371): Distinguish
			// between certificates issued by v1 and v2 API.
			if err = c.pa.WillingToIssueWildcards([]identifier.ACMEIdentifier{id}); err != nil {
				problems = append(problems, fmt.Sprintf("Policy Authority isn't willing to issue for '%s': %s", name, err))
			} else {
				// For defense-in-depth, even if the PA was willing to issue for a name
				// we double check it against a list of forbidden domains. This way even
				// if the hostnamePolicyFile malfunctions we will flag the forbidden
				// domain matches
				if forbidden, pattern := isForbiddenDomain(name); forbidden {
					problems = append(problems, fmt.Sprintf(
						"Policy Authority was willing to issue but domain '%s' matches "+
							"forbiddenDomains entry %q", name, pattern))
				}
			}
		}
		// Check the cert has the correct key usage extensions
		if !reflect.DeepEqual(parsedCert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) {
			problems = append(problems, "Certificate has incorrect key usage extensions")
		}

		for _, ext := range parsedCert.Extensions {
			if _, ok := allowedExtensions[ext.Id.String()]; !ok {
				problems = append(problems, fmt.Sprintf("Certificate contains an unexpected extension: %s", ext.Id))
			}
			if expectedContent, ok := expectedExtensionContent[ext.Id.String()]; ok {
				if !bytes.Equal(ext.Value, expectedContent) {
					problems = append(problems, fmt.Sprintf("Certificate extension %s contains unexpected content: has %x, expected %x", ext.Id, ext.Value, expectedContent))
				}
			}
		}
	}
	return problems
}

type config struct {
	CertChecker struct {
		cmd.DBConfig
		cmd.HostnamePolicyConfig

		Workers             int
		ReportDirectoryPath string
		UnexpiredOnly       bool
		BadResultsOnly      bool
		CheckPeriod         cmd.ConfigDuration

		// IgnoredLints is a list of zlint names. Any lint results from a lint in
		// the IgnoredLists list are ignored regardles of LintStatus level.
		IgnoredLints []string

		Features map[string]bool
	}

	PA cmd.PAConfig

	Syslog cmd.SyslogConfig
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	workers := flag.Int("workers", runtime.NumCPU(), "The number of concurrent workers used to process certificates")
	badResultsOnly := flag.Bool("bad-results-only", false, "Only collect and display bad results")
	connect := flag.String("db-connect", "", "SQL URI if not provided in the configuration file")
	cp := flag.Duration("check-period", time.Hour*2160, "How far back to check")
	unexpiredOnly := flag.Bool("unexpired-only", false, "Only check currently unexpired certificates")

	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var config config
	err := cmd.ReadConfigFile(*configFile, &config)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	err = features.Set(config.CertChecker.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	syslogger, err := syslog.Dial("", "", syslog.LOG_INFO|syslog.LOG_LOCAL0, "")
	cmd.FailOnError(err, "Failed to dial syslog")
	logger, err := blog.New(syslogger, 0, 0)
	cmd.FailOnError(err, "Failed to construct logger")
	err = blog.Set(logger)
	cmd.FailOnError(err, "Failed to set audit logger")

	if *connect != "" {
		config.CertChecker.DBConnect = *connect
	}
	if *workers != 0 {
		config.CertChecker.Workers = *workers
	}
	config.CertChecker.UnexpiredOnly = *unexpiredOnly
	config.CertChecker.BadResultsOnly = *badResultsOnly
	config.CertChecker.CheckPeriod.Duration = *cp

	// Validate PA config and set defaults if needed
	cmd.FailOnError(config.PA.CheckChallenges(), "Invalid PA configuration")

	saDbURL, err := config.CertChecker.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	saDbMap, err := sa.NewDbMap(saDbURL, config.CertChecker.DBConfig.MaxDBConns)
	cmd.FailOnError(err, "Could not connect to database")
	scope := metrics.NewPromScope(prometheus.DefaultRegisterer)

	// Collect and periodically report DB metrics using the DBMap and prometheus scope.
	sa.InitDBMetrics(saDbMap, scope)

	pa, err := policy.New(config.PA.Challenges)
	cmd.FailOnError(err, "Failed to create PA")
	err = pa.SetHostnamePolicyFile(config.CertChecker.HostnamePolicyFile)
	cmd.FailOnError(err, "Failed to load HostnamePolicyFile")

	checker := newChecker(
		saDbMap,
		cmd.Clock(),
		pa,
		config.CertChecker.CheckPeriod.Duration,
	)
	fmt.Fprintf(os.Stderr, "# Getting certificates issued in the last %s\n", config.CertChecker.CheckPeriod)

	ignoredLintsMap := make(map[string]bool)
	for _, name := range config.CertChecker.IgnoredLints {
		ignoredLintsMap[name] = true
	}

	// Since we grab certificates in batches we don't want this to block, when it
	// is finished it will close the certificate channel which allows the range
	// loops in checker.processCerts to break
	go func() {
		err := checker.getCerts(config.CertChecker.UnexpiredOnly)
		cmd.FailOnError(err, "Batch retrieval of certificates failed")
	}()

	fmt.Fprintf(os.Stderr, "# Processing certificates using %d workers\n", config.CertChecker.Workers)
	wg := new(sync.WaitGroup)
	for i := 0; i < config.CertChecker.Workers; i++ {
		wg.Add(1)
		go func() {
			s := checker.clock.Now()
			checker.processCerts(wg, config.CertChecker.BadResultsOnly, ignoredLintsMap)
			scope.TimingDuration("certChecker.processingLatency", time.Since(s))
		}()
	}
	wg.Wait()
	fmt.Fprintf(
		os.Stderr,
		"# Finished processing certificates, sample: %d, good: %d, bad: %d\n",
		len(checker.issuedReport.Entries),
		checker.issuedReport.GoodCerts,
		checker.issuedReport.BadCerts,
	)
	err = checker.issuedReport.dump()
	cmd.FailOnError(err, "Failed to dump results: %s\n")

}
