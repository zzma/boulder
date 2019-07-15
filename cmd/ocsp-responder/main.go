package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/go-gorp/gorp.v2"

	cfocsp "github.com/cloudflare/cfssl/ocsp"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"

	"github.com/zzma/boulder/cmd"
	"github.com/zzma/boulder/core"
	"github.com/zzma/boulder/features"
	blog "github.com/zzma/boulder/log"
	"github.com/zzma/boulder/metrics"
	"github.com/zzma/boulder/metrics/measured_http"
	"github.com/zzma/boulder/sa"
)

// statsShim implements the cfocsp.Stats interface which allows
// measurement of number/type of OCSP responses that are served
type statsShim struct {
	responseTypes *prometheus.CounterVec
}

var responseTypeToString = map[ocsp.ResponseStatus]string{
	ocsp.Success:           "Success",
	ocsp.Malformed:         "Malformed",
	ocsp.InternalError:     "InternalError",
	ocsp.TryLater:          "TryLater",
	ocsp.SignatureRequired: "SignatureRequired",
	ocsp.Unauthorized:      "Unauthorized",
}

func (ss *statsShim) ResponseStatus(status ocsp.ResponseStatus) {
	respType, ok := responseTypeToString[status]
	if !ok {
		respType = "unknownType"
	}
	ss.responseTypes.With(prometheus.Labels{"type": respType}).Inc()
}

/*
DBSource maps a given Database schema to a CA Key Hash, so we can pick
from among them when presented with OCSP requests for different certs.

We assume that OCSP responses are stored in a very simple database table,
with two columns: serialNumber and response

  CREATE TABLE ocsp_responses (serialNumber TEXT, response BLOB);

The serialNumber field may have any type to which Go will match a string,
so you can be more efficient than TEXT if you like.  We use it to store the
serial number in base64.  You probably want to have an index on the
serialNumber field, since we will always query on it.

*/
type DBSource struct {
	dbMap             dbSelector
	caKeyHash         []byte
	reqSerialPrefixes []string
	timeout           time.Duration
	log               blog.Logger
}

// Define an interface with the needed methods from gorp.
// This also allows us to simulate MySQL failures by mocking the interface.
type dbSelector interface {
	SelectOne(holder interface{}, query string, args ...interface{}) error
	WithContext(ctx context.Context) gorp.SqlExecutor
}

// NewSourceFromDatabase produces a DBSource representing the binding of a
// given DB schema to a CA key.
func NewSourceFromDatabase(
	dbMap dbSelector,
	caKeyHash []byte,
	reqSerialPrefixes []string,
	timeout time.Duration,
	log blog.Logger,
) (src *DBSource, err error) {
	src = &DBSource{
		dbMap:             dbMap,
		caKeyHash:         caKeyHash,
		reqSerialPrefixes: reqSerialPrefixes,
		timeout:           timeout,
		log:               log,
	}
	return
}

type dbResponse struct {
	OCSPResponse    []byte
	OCSPLastUpdated time.Time
}

// Response is called by the HTTP server to handle a new OCSP request.
func (src *DBSource) Response(req *ocsp.Request) ([]byte, http.Header, error) {
	// Check that this request is for the proper CA
	if bytes.Compare(req.IssuerKeyHash, src.caKeyHash) != 0 {
		src.log.Debugf("Request intended for CA Cert ID: %s", hex.EncodeToString(req.IssuerKeyHash))
		return nil, nil, cfocsp.ErrNotFound
	}

	serialString := core.SerialToString(req.SerialNumber)
	if len(src.reqSerialPrefixes) > 0 {
		match := false
		for _, prefix := range src.reqSerialPrefixes {
			if match = strings.HasPrefix(serialString, prefix); match {
				break
			}
		}
		if !match {
			return nil, nil, cfocsp.ErrNotFound
		}
	}

	src.log.Debugf("Searching for OCSP issued by us for serial %s", serialString)

	var response dbResponse
	defer func() {
		if len(response.OCSPResponse) != 0 {
			src.log.Debugf("OCSP Response sent for CA=%s, Serial=%s", hex.EncodeToString(src.caKeyHash), serialString)
		}
	}()
	ctx := context.Background()
	if src.timeout != 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, src.timeout)
		defer cancel()
	}
	err := src.dbMap.WithContext(ctx).SelectOne(
		&response,
		"SELECT ocspResponse, ocspLastUpdated FROM certificateStatus WHERE serial = :serial",
		map[string]interface{}{"serial": serialString},
	)
	if err == sql.ErrNoRows {
		return nil, nil, cfocsp.ErrNotFound
	}
	if err != nil {
		src.log.AuditErrf("Looking up OCSP response: %s", err)
		return nil, nil, err
	}
	if response.OCSPLastUpdated.IsZero() {
		src.log.Debugf("OCSP Response not sent (ocspLastUpdated is zero) for CA=%s, Serial=%s", hex.EncodeToString(src.caKeyHash), serialString)
		return nil, nil, cfocsp.ErrNotFound
	}

	return response.OCSPResponse, nil, nil
}

func makeDBSource(dbMap dbSelector, issuerCert string, reqSerialPrefixes []string, timeout time.Duration, log blog.Logger) (*DBSource, error) {
	// Load the CA's key so we can store its SubjectKey in the DB
	caCertDER, err := cmd.LoadCert(issuerCert)
	if err != nil {
		return nil, fmt.Errorf("Could not read issuer cert %s: %s", issuerCert, err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("Could not parse issuer cert %s: %s", issuerCert, err)
	}
	if len(caCert.SubjectKeyId) == 0 {
		return nil, fmt.Errorf("Empty subjectKeyID")
	}

	// Construct source from DB
	return NewSourceFromDatabase(dbMap, caCert.SubjectKeyId, reqSerialPrefixes, timeout, log)
}

type config struct {
	OCSPResponder struct {
		cmd.ServiceConfig
		cmd.DBConfig

		// Source indicates the source of pre-signed OCSP responses to be used. It
		// can be a DBConnect string or a file URL. The file URL style is used
		// when responding from a static file for intermediates and roots.
		// If DBConfig has non-empty fields, it takes precedence over this.
		Source string

		Path          string
		ListenAddress string
		// MaxAge is the max-age to set in the Cache-Control response
		// header. It is a time.Duration formatted string.
		MaxAge cmd.ConfigDuration

		// When to timeout a request. This should be slightly lower than the
		// upstream's timeout when making request to ocsp-responder.
		Timeout cmd.ConfigDuration

		ShutdownStopTimeout cmd.ConfigDuration

		RequiredSerialPrefixes []string

		Features map[string]bool
	}

	Syslog cmd.SyslogConfig

	Common struct {
		IssuerCert string
	}
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		fmt.Fprintf(os.Stderr, `Usage of %s:
Config JSON should contain either a DBConnectFile or a Source value containing a file: URL.
If Source is a file: URL, the file should contain a list of OCSP responses in base64-encoded DER,
as generated by Boulder's single-ocsp command.
`, os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")
	err = features.Set(c.OCSPResponder.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.OCSPResponder.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	config := c.OCSPResponder
	var source cfocsp.Source

	if strings.HasPrefix(config.Source, "file:") {
		url, err := url.Parse(config.Source)
		cmd.FailOnError(err, "Source was not a URL")
		filename := url.Path
		// Go interprets cwd-relative file urls (file:test/foo.txt) as having the
		// relative part of the path in the 'Opaque' field.
		if filename == "" {
			filename = url.Opaque
		}
		source, err = cfocsp.NewSourceFromFile(filename)
		cmd.FailOnError(err, fmt.Sprintf("Couldn't read file: %s", url.Path))
	} else {
		// For databases, DBConfig takes precedence over Source, if present.
		dbConnect, err := config.DBConfig.URL()
		cmd.FailOnError(err, "Reading DB config")
		if dbConnect == "" {
			dbConnect = config.Source
		}
		logger.Infof("Loading OCSP Database for CA Cert: %s", c.Common.IssuerCert)
		dbMap, err := sa.NewDbMap(dbConnect, config.DBConfig.MaxDBConns)
		cmd.FailOnError(err, "Could not connect to database")
		sa.SetSQLDebug(dbMap, logger)
		// Collect and periodically report DB metrics using the DBMap and prometheus scope.
		sa.InitDBMetrics(dbMap, scope)

		source, err = makeDBSource(
			dbMap,
			c.Common.IssuerCert,
			c.OCSPResponder.RequiredSerialPrefixes,
			c.OCSPResponder.Timeout.Duration,
			logger)
		cmd.FailOnError(err, "Couldn't load OCSP DB")
		// Export the MaxDBConns
		dbConnStat := prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "max_db_connections",
			Help: "Maximum number of DB connections allowed.",
		})
		scope.MustRegister(dbConnStat)
		dbConnStat.Set(float64(config.DBConfig.MaxDBConns))
	}

	ocspStats := statsShim{responseTypes: prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ocspResponses",
			Help: "Number of OCSP responses returned by type",
		},
		[]string{"type"},
	)}
	scope.MustRegister(ocspStats.responseTypes)

	m := mux(scope, c.OCSPResponder.Path, source, &ocspStats)
	srv := &http.Server{
		Addr:    c.OCSPResponder.ListenAddress,
		Handler: m,
	}

	done := make(chan bool)
	go cmd.CatchSignals(logger, func() {
		ctx, cancel := context.WithTimeout(context.Background(),
			c.OCSPResponder.ShutdownStopTimeout.Duration)
		defer cancel()
		_ = srv.Shutdown(ctx)
		done <- true
	})

	err = srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		cmd.FailOnError(err, "Running HTTP server")
	}

	// https://godoc.org/net/http#Server.Shutdown:
	// When Shutdown is called, Serve, ListenAndServe, and ListenAndServeTLS
	// immediately return ErrServerClosed. Make sure the program doesn't exit and
	// waits instead for Shutdown to return.
	<-done
}

// ocspMux partially implements the interface defined for http.ServeMux but doesn't implement
// the path cleaning its Handler method does. Notably http.ServeMux will collapse repeated
// slashes into a single slash which breaks the base64 encoding that is used in OCSP GET
// requests. CFSSL explicitly recommends against using http.ServeMux for this reason:
// https://github.com/cloudflare/cfssl/blob/6388e1ec18d2933c35f0f8dfbbe383713eb04b1e/ocsp/responder.go#L170
type ocspMux struct {
	handler http.Handler
}

func (om *ocspMux) Handler(_ *http.Request) (http.Handler, string) {
	return om.handler, "/"
}

func mux(scope metrics.Scope, responderPath string, source cfocsp.Source, ocspStats cfocsp.Stats) http.Handler {
	stripPrefix := http.StripPrefix(responderPath, cfocsp.NewResponder(source, ocspStats))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/" {
			w.Header().Set("Cache-Control", "max-age=43200") // Cache for 12 hours
			w.WriteHeader(200)
			return
		}
		stripPrefix.ServeHTTP(w, r)
	})
	return measured_http.New(&ocspMux{h}, cmd.Clock(), scope)
}
