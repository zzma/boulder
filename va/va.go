package va

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/jmhodges/clock"
	"github.com/zzma/boulder/bdns"
	"github.com/zzma/boulder/canceled"
	"github.com/zzma/boulder/cmd"
	"github.com/zzma/boulder/core"
	berrors "github.com/zzma/boulder/errors"
	"github.com/zzma/boulder/features"
	bgrpc "github.com/zzma/boulder/grpc"
	"github.com/zzma/boulder/identifier"
	blog "github.com/zzma/boulder/log"
	"github.com/zzma/boulder/metrics"
	"github.com/zzma/boulder/probs"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// badTLSHeader contains the string 'HTTP /' which is returned when
	// we try to talk TLS to a server that only talks HTTP
	badTLSHeader = []byte{0x48, 0x54, 0x54, 0x50, 0x2f}
	// h2SettingsFrameErrRegex is a regex against a net/http error indicating
	// a malformed HTTP response that matches the initial SETTINGS frame of an
	// HTTP/2 connection. This happens when a server configures HTTP/2 on port
	// :80, failing HTTP-01 challenges.
	//
	// The regex first matches the error string prefix and then matches the raw
	// bytes of an arbitrarily sized HTTP/2 SETTINGS frame:
	//   0x00 0x00 0x?? 0x04 0x00 0x00 0x00 0x00
	//
	// The third byte is variable and indicates the frame size. Typically
	// this will be 0x12.
	// The 0x04 in the fourth byte indicates that the frame is SETTINGS type.
	//
	// See:
	//   * https://tools.ietf.org/html/rfc7540#section-4.1
	//   * https://tools.ietf.org/html/rfc7540#section-6.5
	//
	// NOTE(@cpu): Using a regex is a hack but unfortunately for this case
	// http.Client.Do() will return a url.Error err that wraps
	// a errors.ErrorString instance. There isn't much else to do with one of
	// those except match the encoded byte string with a regex. :-X
	//
	// NOTE(@cpu): The first component of this regex is optional to avoid an
	// integration test flake. In some (fairly rare) conditions the malformed
	// response error will be returned simply as a http.badStringError without
	// the broken transport prefix. Most of the time the error is returned with
	// a transport connection error prefix.
	h2SettingsFrameErrRegex = regexp.MustCompile(`(?:net\/http\: HTTP\/1\.x transport connection broken: )?malformed HTTP response \"\\x00\\x00\\x[a-f0-9]{2}\\x04\\x00\\x00\\x00\\x00\\x00.*"`)
)

// RemoteVA wraps the core.ValidationAuthority interface and adds a field containing the addresses
// of the remote gRPC server since the interface (and the underlying gRPC client) doesn't
// provide a way to extract this metadata which is useful for debugging gRPC connection issues.
type RemoteVA struct {
	core.ValidationAuthority
	Addresses string
}

type vaMetrics struct {
	validationTime                      *prometheus.HistogramVec
	remoteValidationTime                *prometheus.HistogramVec
	remoteValidationFailures            prometheus.Counter
	prospectiveRemoteValidationFailures prometheus.Counter
	tlsALPNOIDCounter                   *prometheus.CounterVec
	http01Fallbacks                     prometheus.Counter
	http01Redirects                     prometheus.Counter
}

func initMetrics(stats metrics.Scope) *vaMetrics {
	validationTime := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "validation_time",
			Help:    "Time taken to validate a challenge",
			Buckets: metrics.InternetFacingBuckets,
		},
		[]string{"type", "result", "problemType"})
	stats.MustRegister(validationTime)
	remoteValidationTime := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "remote_validation_time",
			Help:    "Time taken to remotely validate a challenge",
			Buckets: metrics.InternetFacingBuckets,
		},
		[]string{"type", "result"})
	stats.MustRegister(remoteValidationTime)
	remoteValidationFailures := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "remote_validation_failures",
			Help: "Number of validations failed due to remote VAs returning failure when consensus is enforced",
		})
	stats.MustRegister(remoteValidationFailures)
	prospectiveRemoteValidationFailures := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "prospective_remote_validation_failures",
			Help: "Number of validations that would have failed due to remote VAs returning failure if consesus were enforced",
		})
	stats.MustRegister(prospectiveRemoteValidationFailures)
	tlsALPNOIDCounter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tls_alpn_oid_usage",
			Help: "Number of TLS ALPN validations using either of the two OIDs",
		},
		[]string{"oid"},
	)
	stats.MustRegister(tlsALPNOIDCounter)
	http01Fallbacks := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "http01_fallbacks",
			Help: "Number of IPv6 to IPv4 HTTP-01 fallback requests made",
		})
	stats.MustRegister(http01Fallbacks)
	http01Redirects := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "http01_redirects",
			Help: "Number of HTTP-01 redirects followed",
		})
	stats.MustRegister(http01Redirects)

	return &vaMetrics{
		validationTime:                      validationTime,
		remoteValidationTime:                remoteValidationTime,
		remoteValidationFailures:            remoteValidationFailures,
		prospectiveRemoteValidationFailures: prospectiveRemoteValidationFailures,
		tlsALPNOIDCounter:                   tlsALPNOIDCounter,
		http01Fallbacks:                     http01Fallbacks,
		http01Redirects:                     http01Redirects,
	}
}

// ValidationAuthorityImpl represents a VA
type ValidationAuthorityImpl struct {
	log                blog.Logger
	dnsClient          bdns.DNSClient
	issuerDomain       string
	httpPort           int
	httpsPort          int
	tlsPort            int
	userAgent          string
	stats              metrics.Scope
	clk                clock.Clock
	remoteVAs          []RemoteVA
	maxRemoteFailures  int
	accountURIPrefixes []string
	singleDialTimeout  time.Duration

	metrics *vaMetrics
}

// NewValidationAuthorityImpl constructs a new VA
func NewValidationAuthorityImpl(
	pc *cmd.PortConfig,
	resolver bdns.DNSClient,
	remoteVAs []RemoteVA,
	maxRemoteFailures int,
	userAgent string,
	issuerDomain string,
	stats metrics.Scope,
	clk clock.Clock,
	logger blog.Logger,
	accountURIPrefixes []string,
) (*ValidationAuthorityImpl, error) {
	if pc.HTTPPort == 0 {
		pc.HTTPPort = 80
	}
	if pc.HTTPSPort == 0 {
		pc.HTTPSPort = 443
	}
	if pc.TLSPort == 0 {
		pc.TLSPort = 443
	}

	if features.Enabled(features.CAAAccountURI) && len(accountURIPrefixes) == 0 {
		return nil, errors.New("no account URI prefixes configured")
	}

	return &ValidationAuthorityImpl{
		log:                logger,
		dnsClient:          resolver,
		issuerDomain:       issuerDomain,
		httpPort:           pc.HTTPPort,
		httpsPort:          pc.HTTPSPort,
		tlsPort:            pc.TLSPort,
		userAgent:          userAgent,
		stats:              stats,
		clk:                clk,
		metrics:            initMetrics(stats),
		remoteVAs:          remoteVAs,
		maxRemoteFailures:  maxRemoteFailures,
		accountURIPrefixes: accountURIPrefixes,
		// singleDialTimeout specifies how long an individual `DialContext` operation may take
		// before timing out. This timeout ignores the base RPC timeout and is strictly
		// used for the DialContext operations that take place during an
		// HTTP-01 challenge validation.
		singleDialTimeout: 10 * time.Second,
	}, nil
}

// Used for audit logging
type verificationRequestEvent struct {
	ID                string         `json:",omitempty"`
	Requester         int64          `json:",omitempty"`
	Hostname          string         `json:",omitempty"`
	Challenge         core.Challenge `json:",omitempty"`
	ValidationLatency float64
	Error             string `json:",omitempty"`
}

// detailedError returns a ProblemDetails corresponding to an error
// that occurred during HTTP-01 or TLS-ALPN domain validation. Specifically it
// tries to unwrap known Go error types and present something a little more
// meaningful. It additionally handles `berrors.ConnectionFailure` errors by
// passing through the detailed message.
func detailedError(err error) *probs.ProblemDetails {
	// net/http wraps net.OpError in a url.Error. Unwrap them.
	if urlErr, ok := err.(*url.Error); ok {
		prob := detailedError(urlErr.Err)
		prob.Detail = fmt.Sprintf("Fetching %s: %s", urlErr.URL, prob.Detail)
		return prob
	}

	if tlsErr, ok := err.(tls.RecordHeaderError); ok && bytes.Compare(tlsErr.RecordHeader[:], badTLSHeader) == 0 {
		return probs.Malformed("Server only speaks HTTP, not TLS")
	}

	if netErr, ok := err.(*net.OpError); ok {
		if fmt.Sprintf("%T", netErr.Err) == "tls.alert" {
			// All the tls.alert error strings are reasonable to hand back to a
			// user. Confirmed against Go 1.8.
			return probs.TLSError(netErr.Error())
		} else if syscallErr, ok := netErr.Err.(*os.SyscallError); ok &&
			syscallErr.Err == syscall.ECONNREFUSED {
			return probs.ConnectionFailure("Connection refused")
		} else if syscallErr, ok := netErr.Err.(*os.SyscallError); ok &&
			syscallErr.Err == syscall.ENETUNREACH {
			return probs.ConnectionFailure("Network unreachable")
		} else if syscallErr, ok := netErr.Err.(*os.SyscallError); ok &&
			syscallErr.Err == syscall.ECONNRESET {
			return probs.ConnectionFailure("Connection reset by peer")
		} else if netErr.Timeout() && netErr.Op == "dial" {
			return probs.ConnectionFailure("Timeout during connect (likely firewall problem)")
		} else if netErr.Timeout() {
			return probs.ConnectionFailure("Timeout during %s (your server may be slow or overloaded)", netErr.Op)
		}
	}
	if err, ok := err.(net.Error); ok && err.Timeout() {
		return probs.ConnectionFailure("Timeout after connect (your server may be slow or overloaded)")
	}
	if berrors.Is(err, berrors.ConnectionFailure) {
		return probs.ConnectionFailure(err.Error())
	}
	if berrors.Is(err, berrors.Unauthorized) {
		return probs.Unauthorized(err.Error())
	}

	if h2SettingsFrameErrRegex.MatchString(err.Error()) {
		return probs.ConnectionFailure("Server is speaking HTTP/2 over HTTP")
	}

	return probs.ConnectionFailure("Error getting validation data")
}

// validate performs a challenge validation and, in parallel,
// checks CAA and GSB for the identifier. If any of those steps fails, it
// returns a ProblemDetails plus the validation records created during the
// validation attempt.
func (va *ValidationAuthorityImpl) validate(
	ctx context.Context,
	identifier identifier.ACMEIdentifier,
	challenge core.Challenge,
	authz core.Authorization,
) ([]core.ValidationRecord, *probs.ProblemDetails) {

	// If the identifier is a wildcard domain we need to validate the base
	// domain by removing the "*." wildcard prefix. We create a separate
	// `baseIdentifier` here before starting the `va.checkCAA` goroutine with the
	// `identifier` to avoid a data race.
	baseIdentifier := identifier
	if strings.HasPrefix(identifier.Value, "*.") {
		baseIdentifier.Value = strings.TrimPrefix(identifier.Value, "*.")
	}

	// va.checkCAA accepts wildcard identifiers and handles them appropriately so
	// we can dispatch `checkCAA` with the provided `identifier` instead of
	// `baseIdentifier`
	ch := make(chan *probs.ProblemDetails, 1)
	go func() {
		params := &caaParams{
			accountURIID:     &authz.RegistrationID,
			validationMethod: &challenge.Type,
		}
		ch <- va.checkCAA(ctx, identifier, params)
	}()

	// TODO(#1292): send into another goroutine
	validationRecords, err := va.validateChallenge(ctx, baseIdentifier, challenge)
	if err != nil {
		return validationRecords, err
	}

	for i := 0; i < cap(ch); i++ {
		if extraProblem := <-ch; extraProblem != nil {
			return validationRecords, extraProblem
		}
	}
	return validationRecords, nil
}

func (va *ValidationAuthorityImpl) validateChallenge(ctx context.Context, identifier identifier.ACMEIdentifier, challenge core.Challenge) ([]core.ValidationRecord, *probs.ProblemDetails) {
	if err := challenge.CheckConsistencyForValidation(); err != nil {
		return nil, probs.Malformed("Challenge failed consistency check: %s", err)
	}
	switch challenge.Type {
	case core.ChallengeTypeHTTP01:
		return va.validateHTTP01(ctx, identifier, challenge)
	case core.ChallengeTypeDNS01:
		return va.validateDNS01(ctx, identifier, challenge)
	case core.ChallengeTypeTLSALPN01:
		return va.validateTLSALPN01(ctx, identifier, challenge)
	}
	return nil, probs.Malformed("invalid challenge type %s", challenge.Type)
}

// performRemoteValidation calls `PerformValidation` for each of the configured
// remoteVAs in a random order. The provided `results` chan should have an equal
// size to the number of remote VAs. The validations will be peformed in
// separate go-routines. If the result `error` from a remote
// `PerformValidation` RPC is nil or a nil `ProblemDetails` instance it is
// written directly to the `results` chan. If the err is a cancelled error it is
// treated as a nil error. Otherwise the error/problem is written to the results
// channel as-is.
func (va *ValidationAuthorityImpl) performRemoteValidation(
	ctx context.Context,
	domain string,
	challenge core.Challenge,
	authz core.Authorization,
	results chan *probs.ProblemDetails) {
	for _, i := range rand.Perm(len(va.remoteVAs)) {
		remoteVA := va.remoteVAs[i]
		go func(rva RemoteVA, index int) {
			_, err := rva.PerformValidation(ctx, domain, challenge, authz)
			if err != nil {
				// returned error can be a nil *probs.ProblemDetails which breaks the
				// err != nil check so do a slightly more complicated unwrap check to
				// make sure we don't choke on that.
				// TODO(@cpu): Clean this up once boulder issue 2254[0] is resolved
				// [0] https://github.com/letsencrypt/boulder/issues/2254
				if p, ok := err.(*probs.ProblemDetails); ok && p != (*probs.ProblemDetails)(nil) {
					// If the non-nil err was a non-nil *probs.ProblemDetails then we can
					// log it at an info level. It's a normal non-success validation
					// result and the remote VA will have logged more detail.
					va.log.Infof("Remote VA %q.PerformValidation returned problem: %s", rva.Addresses, err)
				} else if ok && p == (*probs.ProblemDetails)(nil) {
					// If the non-nil err was a nil *probs.ProblemDetails then we don't need to do
					// anything. There isn't really an error here.
					err = nil
				} else if canceled.Is(err) {
					// If the non-nil err was a canceled error, ignore it. That's fine it
					// just means we cancelled the remote VA request before it was
					// finished because we didn't care about its result.
					err = nil
				} else if !ok {
					// Otherwise, the non-nil err was *not* a *probs.ProblemDetails and
					// was *not* a context cancelleded error and represents something that
					// will later be returned as a server internal error
					// without detail if the number of errors is >= va.maxRemoteFailures.
					// Log it at the error level so we can debug from logs.
					va.log.Errf("Remote VA %q.PerformValidation failed: %s", rva.Addresses, err)
				}
			}
			if err == nil {
				results <- nil
			} else if prob, ok := err.(*probs.ProblemDetails); ok {
				results <- prob
			} else {
				results <- probs.ServerInternal("Remote PerformValidation RPC failed")
			}
		}(remoteVA, i)
	}
}

// processRemoteResults evaluates a primary VA result, and a channel of remote
// VA problems to produce a single overall validation result based on configured
// feature flags. The overall result is calculated based on the VA's configured
// `maxRemoteFailures` value.
//
// If the `MultiVAFullResults` feature is enabled then `processRemoteResults`
// will expect to read a result from the `remoteErrors` channel for each VA and
// will not produce an overall result until all remote VAs have responded. In
// this case `logRemoteFailureDifferentials` will also be called to describe the
// differential between the primary and all of the remote VAs.
//
// If the `MultiVAFullResults` feature flag is not enabled then
// `processRemoteResults` will potentially return before all remote VAs have had
// a chance to respond. This happens if the success or failure threshold is met.
// This doesn't allow for logging the differential between the primary and
// remote VAs but is more performant.
func (va *ValidationAuthorityImpl) processRemoteResults(
	domain string,
	challengeType string,
	primaryResult *probs.ProblemDetails,
	remoteErrors chan *probs.ProblemDetails,
	numRemoteVAs int) *probs.ProblemDetails {

	state := "failure"
	start := va.clk.Now()

	defer func() {
		va.metrics.remoteValidationTime.With(prometheus.Labels{
			"type":   challengeType,
			"result": state,
		}).Observe(va.clk.Since(start).Seconds())
	}()

	required := numRemoteVAs - va.maxRemoteFailures
	good := 0
	bad := 0

	var remoteProbs []*probs.ProblemDetails
	var firstProb *probs.ProblemDetails
	// Due to channel behavior this could block indefinitely and we rely on gRPC
	// honoring the context deadline used in client calls to prevent that from
	// happening.
	for prob := range remoteErrors {
		// Add the problem to the slice
		remoteProbs = append(remoteProbs, prob)
		if prob == nil {
			good++
		} else {
			bad++
		}

		// Store the first non-nil problem to return later (if `MultiVAFullResults`
		// is enabled).
		if firstProb == nil && prob != nil {
			firstProb = prob
		}

		// If MultiVAFullResults isn't enabled then return early whenever the
		// success or failure threshold is met.
		if !features.Enabled(features.MultiVAFullResults) {
			if good >= required {
				state = "success"
				return nil
			} else if bad > va.maxRemoteFailures {
				return prob
			}
		}

		// If we haven't returned early because of MultiVAFullResults being enabled
		// we need to break the loop once all of the VAs have returned a result.
		if len(remoteProbs) == numRemoteVAs {
			break
		}
	}

	// If we are using `features.MultiVAFullResults` then we haven't returned
	// early and can now log the differential between what the primary VA saw and
	// what all of the remote VAs saw.
	va.logRemoteValidationDifferentials(domain, primaryResult, remoteProbs)

	// Based on the threshold of good/bad return nil or a problem.
	if good >= required {
		state = "success"
		return nil
	} else if bad > va.maxRemoteFailures {
		return firstProb
	}

	// This condition should not occur - it indicates the good/bad counts didn't
	// meet either the required threshold or the maxRemoteFailures threshold.
	return probs.ServerInternal("Too few remote PerformValidation RPC results")
}

// logRemoteValidationDifferentials is called by `processRemoteResults` when the
// `MultiVAFullResults` feature flag is enabled. It produces a JSON log line
// that contains the primary VA result and the results each remote VA returned.
func (va *ValidationAuthorityImpl) logRemoteValidationDifferentials(
	domain string,
	primaryResult *probs.ProblemDetails,
	remoteProbs []*probs.ProblemDetails) {

	var successes []*probs.ProblemDetails
	var failures []*probs.ProblemDetails

	allEqual := true
	for _, e := range remoteProbs {
		if e != primaryResult {
			allEqual = false
		}
		if e == nil {
			successes = append(successes, nil)
		} else {
			failures = append(failures, e)
		}
	}
	if allEqual {
		// There's no point logging a differential line if the primary VA and remote
		// VAs all agree.
		return
	}

	// If the primary result was OK and there were more failures than the allowed
	// threshold increment a stat that indicates this overall validation will have
	// failed if features.EnforceMultiVA is enabled.
	if primaryResult == nil && len(failures) > va.maxRemoteFailures {
		va.metrics.prospectiveRemoteValidationFailures.Inc()
	}

	logOb := struct {
		Domain          string
		PrimaryResult   *probs.ProblemDetails
		RemoteSuccesses int
		RemoteFailures  []*probs.ProblemDetails
	}{
		Domain:          domain,
		PrimaryResult:   primaryResult,
		RemoteSuccesses: len(successes),
		RemoteFailures:  failures,
	}

	logJSON, err := json.Marshal(logOb)
	if err != nil {
		// log a warning - a marshaling failure isn't expected given the data and
		// isn't critical enough to break validation for by returning an error to
		// the caller.
		va.log.Warningf("Could not marshal log object in "+
			"logRemoteValidationDifferentials: %s", err)
		return
	}

	va.log.Infof("remoteVADifferentials JSON=%s", string(logJSON))
}

// PerformValidation validates the given challenge. It always returns a list of
// validation records, even when it also returns an error.
func (va *ValidationAuthorityImpl) PerformValidation(ctx context.Context, domain string, challenge core.Challenge, authz core.Authorization) ([]core.ValidationRecord, error) {
	logEvent := verificationRequestEvent{
		ID:        authz.ID,
		Requester: authz.RegistrationID,
		Hostname:  domain,
	}
	vStart := va.clk.Now()

	var remoteProbs chan *probs.ProblemDetails
	if remoteVACount := len(va.remoteVAs); remoteVACount > 0 {
		remoteProbs = make(chan *probs.ProblemDetails, remoteVACount)
		go va.performRemoteValidation(ctx, domain, challenge, authz, remoteProbs)
	}

	records, prob := va.validate(ctx, identifier.DNSIdentifier(domain), challenge, authz)
	challenge.ValidationRecord = records

	// Check for malformed ValidationRecords
	if !challenge.RecordsSane() && prob == nil {
		prob = probs.ServerInternal("Records for validation failed sanity check")
	}

	var problemType string
	if prob != nil {
		problemType = string(prob.Type)
		challenge.Status = core.StatusInvalid
		challenge.Error = prob
		logEvent.Error = prob.Error()
	} else if remoteProbs != nil {
		if !features.Enabled(features.EnforceMultiVA) && features.Enabled(features.MultiVAFullResults) {
			// If we're not going to enforce multi VA but we are logging the
			// differentials then collect and log the remote results in a separate go
			// routine to avoid blocking the primary VA.
			go func() {
				_ = va.processRemoteResults(domain, string(challenge.Type), prob, remoteProbs, len(va.remoteVAs))
			}()
			// Since prob was nil and we're not enforcing the results from
			// `processRemoteResults` set the challenge status to valid so the
			// validationTime metrics increment has the correct result label.
			challenge.Status = core.StatusValid
		} else if features.Enabled(features.EnforceMultiVA) {
			remoteProb := va.processRemoteResults(domain, string(challenge.Type), prob, remoteProbs, len(va.remoteVAs))
			if remoteProb != nil {
				prob = remoteProb
				challenge.Status = core.StatusInvalid
				challenge.Error = remoteProb
				logEvent.Error = remoteProb.Error()
				va.log.Infof("Validation failed due to remote failures: identifier=%v err=%s",
					domain, remoteProb)
				va.metrics.remoteValidationFailures.Inc()
			} else {
				challenge.Status = core.StatusValid
			}
		}
	} else {
		challenge.Status = core.StatusValid
	}

	logEvent.Challenge = challenge

	validationLatency := time.Since(vStart)
	logEvent.ValidationLatency = validationLatency.Round(time.Millisecond).Seconds()

	va.metrics.validationTime.With(prometheus.Labels{
		"type":        string(challenge.Type),
		"result":      string(challenge.Status),
		"problemType": problemType,
	}).Observe(validationLatency.Seconds())

	va.log.AuditObject("Validation result", logEvent)
	va.log.Infof("Validations: %+v", authz)

	// Try to marshal the validation results and prob (if any) to protocol
	// buffers. We log at this layer instead of leaving it up to gRPC because gRPC
	// doesn't log the actual contents that failed to marshal, making it hard to
	// figure out what's broken.
	if _, err := bgrpc.ValidationResultToPB(records, prob); err != nil {
		va.log.Errf(
			"failed to marshal records %#v and prob %#v to protocol buffer: %v",
			records, prob, err)
	}

	if prob == nil {
		// This is necessary because if we just naively returned prob, it would be a
		// non-nil interface value containing a nil pointer, rather than a nil
		// interface value. See, e.g.
		// https://stackoverflow.com/questions/29138591/hiding-nil-values-understanding-why-golang-fails-here
		return records, nil
	}

	return records, prob
}
