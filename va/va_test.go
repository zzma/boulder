package va

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/zzma/boulder/bdns"
	"github.com/zzma/boulder/cmd"
	"github.com/zzma/boulder/core"
	"github.com/zzma/boulder/features"
	"github.com/zzma/boulder/identifier"
	blog "github.com/zzma/boulder/log"
	"github.com/zzma/boulder/metrics"
	"github.com/zzma/boulder/probs"
	"github.com/zzma/boulder/test"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/square/go-jose.v2"
)

func bigIntFromB64(b64 string) *big.Int {
	bytes, _ := base64.URLEncoding.DecodeString(b64)
	x := big.NewInt(0)
	x.SetBytes(bytes)
	return x
}

func intFromB64(b64 string) int {
	return int(bigIntFromB64(b64).Int64())
}

var n = bigIntFromB64("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw==")
var e = intFromB64("AQAB")
var d = bigIntFromB64("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ==")
var p = bigIntFromB64("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc=")
var q = bigIntFromB64("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc=")

var TheKey = rsa.PrivateKey{
	PublicKey: rsa.PublicKey{N: n, E: e},
	D:         d,
	Primes:    []*big.Int{p, q},
}

var accountKey = &jose.JSONWebKey{Key: TheKey.Public()}

// Return an ACME DNS identifier for the given hostname
func dnsi(hostname string) identifier.ACMEIdentifier {
	return identifier.ACMEIdentifier{Type: identifier.DNS, Value: hostname}
}

var ctx context.Context

func TestMain(m *testing.M) {
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Minute)
	ret := m.Run()
	cancel()
	os.Exit(ret)
}

var accountURIPrefixes = []string{"http://boulder:4000/acme/reg/"}

// challengeType == "tls-sni-00" or "dns-00", since they're the same
func createChallenge(challengeType string) core.Challenge {
	chall := core.Challenge{
		Type:                     challengeType,
		Status:                   core.StatusPending,
		Token:                    expectedToken,
		ValidationRecord:         []core.ValidationRecord{},
		ProvidedKeyAuthorization: expectedKeyAuthorization,
	}

	return chall
}

// setChallengeToken sets the token value, and sets the ProvidedKeyAuthorization
// to match.
func setChallengeToken(ch *core.Challenge, token string) {
	ch.Token = token
	ch.ProvidedKeyAuthorization = token + ".9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI"
}

func TestPerformValidationInvalid(t *testing.T) {
	va, _ := setup(nil, 0, "", nil)

	chalDNS := createChallenge(core.ChallengeTypeDNS01)
	_, prob := va.PerformValidation(context.Background(), "foo.com", chalDNS, core.Authorization{})
	test.Assert(t, prob != nil, "validation succeeded")

	samples := test.CountHistogramSamples(va.metrics.validationTime.With(prometheus.Labels{
		"type":        "dns-01",
		"result":      "invalid",
		"problemType": "unauthorized",
	}))
	if samples != 1 {
		t.Errorf("Wrong number of samples for invalid validation. Expected 1, got %d", samples)
	}
}

func TestPerformValidationValid(t *testing.T) {
	va, mockLog := setup(nil, 0, "", nil)

	// create a challenge with well known token
	chalDNS := core.DNSChallenge01("")
	chalDNS.Token = expectedToken
	chalDNS.ProvidedKeyAuthorization = expectedKeyAuthorization
	_, prob := va.PerformValidation(context.Background(), "good-dns01.com", chalDNS, core.Authorization{})
	test.Assert(t, prob == nil, fmt.Sprintf("validation failed: %#v", prob))

	samples := test.CountHistogramSamples(va.metrics.validationTime.With(prometheus.Labels{
		"type":        "dns-01",
		"result":      "valid",
		"problemType": "",
	}))
	if samples != 1 {
		t.Errorf("Wrong number of samples for successful validation. Expected 1, got %d", samples)
	}
	resultLog := mockLog.GetAllMatching(`Validation result`)
	if len(resultLog) != 1 {
		t.Fatalf("Wrong number of matching lines for 'Validation result'")
	}
	if !strings.Contains(resultLog[0], `"Hostname":"good-dns01.com"`) {
		t.Errorf("PerformValidation didn't log validation hostname.")
	}
}

// TestPerformValidationWildcard tests that the VA properly strips the `*.`
// prefix from a wildcard name provided to the PerformValidation function.
func TestPerformValidationWildcard(t *testing.T) {
	va, mockLog := setup(nil, 0, "", nil)

	// create a challenge with well known token
	chalDNS := core.DNSChallenge01("")
	chalDNS.Token = expectedToken
	chalDNS.ProvidedKeyAuthorization = expectedKeyAuthorization
	// perform a validation for a wildcard name
	_, prob := va.PerformValidation(context.Background(), "*.good-dns01.com", chalDNS, core.Authorization{})
	test.Assert(t, prob == nil, fmt.Sprintf("validation failed: %#v", prob))

	samples := test.CountHistogramSamples(va.metrics.validationTime.With(prometheus.Labels{
		"type":        "dns-01",
		"result":      "valid",
		"problemType": "",
	}))
	if samples != 1 {
		t.Errorf("Wrong number of samples for successful validation. Expected 1, got %d", samples)
	}
	resultLog := mockLog.GetAllMatching(`Validation result`)
	if len(resultLog) != 1 {
		t.Fatalf("Wrong number of matching lines for 'Validation result'")
	}

	// We expect that the top level Hostname reflect the wildcard name
	if !strings.Contains(resultLog[0], `"Hostname":"*.good-dns01.com"`) {
		t.Errorf("PerformValidation didn't log correct validation hostname.")
	}
	// We expect that the ValidationRecord contain the correct non-wildcard
	// hostname that was validated
	if !strings.Contains(resultLog[0], `"hostname":"good-dns01.com"`) {
		t.Errorf("PerformValidation didn't log correct validation record hostname.")
	}
}

func setup(
	srv *httptest.Server,
	maxRemoteFailures int,
	userAgent string,
	remoteVAs []RemoteVA) (*ValidationAuthorityImpl, *blog.Mock) {
	features.Reset()

	logger := blog.NewMock()

	if userAgent == "" {
		userAgent = "user agent 1.0"
	}

	var portConfig cmd.PortConfig
	if srv != nil {
		port := getPort(srv)
		portConfig = cmd.PortConfig{
			HTTPPort: port,
			TLSPort:  port,
		}
	}
	va, err := NewValidationAuthorityImpl(
		// Use the test server's port as both the HTTPPort and the TLSPort for the VA
		&portConfig,
		&bdns.MockDNSClient{},
		nil,
		maxRemoteFailures,
		userAgent,
		"letsencrypt.org",
		metrics.NewNoopScope(),
		clock.Default(),
		logger,
		accountURIPrefixes)
	if err != nil {
		panic(fmt.Sprintf("Failed to create validation authority: %v", err))
	}
	if remoteVAs != nil {
		va.remoteVAs = remoteVAs
	}
	return va, logger
}

type multiSrv struct {
	*httptest.Server

	mu         sync.Mutex
	allowedUAs map[string]bool
}

func (s *multiSrv) setAllowedUAs(allowedUAs map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowedUAs = allowedUAs
}

func httpMultiSrv(t *testing.T, token string, allowedUAs map[string]bool) *multiSrv {
	m := http.NewServeMux()

	server := httptest.NewUnstartedServer(m)
	ms := &multiSrv{server, sync.Mutex{}, allowedUAs}

	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() == "slow remote" {
			time.Sleep(time.Second * 5)
		}
		ms.mu.Lock()
		defer ms.mu.Unlock()
		if ms.allowedUAs[r.UserAgent()] {
			ch := core.Challenge{Token: token}
			keyAuthz, _ := ch.ExpectedKeyAuthorization(accountKey)
			fmt.Fprint(w, keyAuthz, "\n\r \t")
		} else {
			fmt.Fprint(w, "???")
		}
	})

	ms.Start()
	return ms
}

// cancelledVA is a mock that always returns context.Canceled for
// PerformValidation calls
type cancelledVA struct{}

func (v cancelledVA) PerformValidation(_ context.Context, _ string, _ core.Challenge, _ core.Authorization) ([]core.ValidationRecord, error) {
	return nil, context.Canceled
}

// brokenRemoteVA is a mock for the core.ValidationAuthority interface mocked to
// always return errors.
type brokenRemoteVA struct{}

// brokenRemoteVAError is the error returned by a brokenRemoteVA's
// PerformValidation and IsSafeDomain functions.
var brokenRemoteVAError = errors.New("brokenRemoteVA is broken")

// PerformValidation returns brokenRemoteVAError unconditionally
func (b *brokenRemoteVA) PerformValidation(
	_ context.Context,
	_ string,
	_ core.Challenge,
	_ core.Authorization) ([]core.ValidationRecord, error) {
	return nil, brokenRemoteVAError
}

func TestMultiVA(t *testing.T) {
	// Create a new challenge to use for the httpSrv
	chall := core.HTTPChallenge01("")
	setChallengeToken(&chall, core.NewToken())
	expectedKeyAuthorization, err := chall.ExpectedKeyAuthorization(accountKey)
	test.AssertNotError(t, err, "could not compute expected key auth value")

	const (
		remoteUA1 = "remote 1"
		remoteUA2 = "remote 2"
		localUA   = "local 1"
	)
	allowedUAs := map[string]bool{
		localUA:   true,
		remoteUA1: true,
		remoteUA2: true,
	}

	// Create an IPv4 test server
	ms := httpMultiSrv(t, chall.Token, allowedUAs)
	defer ms.Close()

	remoteVA1, _ := setup(ms.Server, 0, remoteUA1, nil)
	remoteVA2, _ := setup(ms.Server, 0, remoteUA2, nil)

	remoteVAs := []RemoteVA{
		{remoteVA1, remoteUA1},
		{remoteVA2, remoteUA2},
	}

	enforceMultiVA := map[string]bool{
		"EnforceMultiVA": true,
	}
	enforceMultiVAFullResults := map[string]bool{
		"EnforceMultiVA":     true,
		"MultiVAFullResults": true,
	}
	noEnforceMultiVA := map[string]bool{
		"EnforceMultiVA": false,
	}
	noEnforceMultiVAFullResults := map[string]bool{
		"EnforceMultiVA":     false,
		"MultiVAFullResults": true,
	}

	unauthorized := probs.Unauthorized(
		`The key authorization file from the server did not match this challenge %q != "???"`,
		expectedKeyAuthorization)

	internalErr := probs.ServerInternal("Remote PerformValidation RPC failed")

	expectedInternalErrLine := fmt.Sprintf(
		`ERR: \[AUDIT\] Remote VA "broken".PerformValidation failed: %s`,
		brokenRemoteVAError.Error())

	testCases := []struct {
		Name         string
		RemoteVAs    []RemoteVA
		AllowedUAs   map[string]bool
		Features     map[string]bool
		ExpectedProb *probs.ProblemDetails
		ExpectedLog  string
	}{
		{
			// With local and both remote VAs working there should be no problem.
			Name:       "Local and remote VAs OK, enforce multi VA",
			RemoteVAs:  remoteVAs,
			AllowedUAs: allowedUAs,
			Features:   enforceMultiVA,
		},
		{
			// Ditto if multi VA enforcement is disabled
			Name:       "Local and remote VAs OK, no enforce multi VA",
			RemoteVAs:  remoteVAs,
			AllowedUAs: allowedUAs,
			Features:   noEnforceMultiVA,
		},
		{
			// If the local VA fails everything should fail
			Name:         "Local VA bad, remote VAs OK, no enforce multi VA",
			RemoteVAs:    remoteVAs,
			AllowedUAs:   map[string]bool{remoteUA1: true, remoteUA2: true},
			Features:     noEnforceMultiVA,
			ExpectedProb: unauthorized,
		},
		{
			// Ditto when enforcing remote VA
			Name:         "Local VA bad, remote VAs OK, enforce multi VA",
			RemoteVAs:    remoteVAs,
			AllowedUAs:   map[string]bool{remoteUA1: true, remoteUA2: true},
			Features:     enforceMultiVA,
			ExpectedProb: unauthorized,
		},
		{
			// If a remote VA fails with an internal err it should fail when enforcing multi VA
			Name: "Local VA ok, remote VA internal err, enforce multi VA",
			RemoteVAs: []RemoteVA{
				{remoteVA1, remoteUA1},
				{&brokenRemoteVA{}, "broken"},
			},
			AllowedUAs:   allowedUAs,
			Features:     enforceMultiVA,
			ExpectedProb: internalErr,
			// The real failure cause should be logged
			ExpectedLog: expectedInternalErrLine,
		},
		{
			// If a remote VA fails with an internal err it should not fail when not
			// enforcing multi VA
			Name: "Local VA ok, remote VA internal err, no enforce multi VA",
			RemoteVAs: []RemoteVA{
				{remoteVA1, remoteUA1},
				{&brokenRemoteVA{}, "broken"},
			},
			AllowedUAs: allowedUAs,
			Features:   noEnforceMultiVA,
			// The real failure cause should be logged
			ExpectedLog: expectedInternalErrLine,
		},
		{
			// With only one working remote VA there should *not* be a validation
			// failure when not enforcing multi VA.
			Name:       "Local VA and one remote VA OK, no enforce multi VA",
			RemoteVAs:  remoteVAs,
			AllowedUAs: map[string]bool{localUA: true, remoteUA2: true},
			Features:   noEnforceMultiVA,
		},
		{
			// With only one working remote VA there should be a validation failure
			// when enforcing multi VA.
			Name:         "Local VA and one remote VA OK, enforce multi VA",
			RemoteVAs:    remoteVAs,
			AllowedUAs:   map[string]bool{localUA: true, remoteUA2: true},
			Features:     enforceMultiVA,
			ExpectedProb: unauthorized,
		},
		{
			// With one remote VA cancelled there should not be a validation failure
			// when enforcing multi VA.
			Name: "Local VA and one remote VA OK, one cancelled VA, enforce multi VA",
			RemoteVAs: []RemoteVA{
				{remoteVA1, remoteUA1},
				{cancelledVA{}, remoteUA2},
			},
			AllowedUAs: allowedUAs,
			Features:   enforceMultiVA,
		},
		{
			// With two remote VAs cancelled there should not be a validation failure
			// when enforcing multi VA
			Name: "Local VA and one remote VA OK, one cancelled VA, enforce multi VA",
			RemoteVAs: []RemoteVA{
				{cancelledVA{}, remoteUA1},
				{cancelledVA{}, remoteUA2},
			},
			AllowedUAs: allowedUAs,
			Features:   enforceMultiVA,
		},
		{
			// With the local and remote VAs seeing diff problems and the full results
			// feature flag on but multi VA enforcement off we expect
			// no problem.
			Name:       "Local and remove VA differential, full results, no enforce multi VA",
			RemoteVAs:  remoteVAs,
			AllowedUAs: map[string]bool{localUA: true},
			Features:   noEnforceMultiVAFullResults,
		},
		{
			// With the local and remote VAs seeing diff problems and the full results
			// feature flag on and multi VA enforcement on we expect a problem.
			Name:         "Local and remove VA differential, full results, enforce multi VA",
			RemoteVAs:    remoteVAs,
			AllowedUAs:   map[string]bool{localUA: true},
			Features:     enforceMultiVAFullResults,
			ExpectedProb: unauthorized,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Configure the test server with the testcase allowed UAs.
			ms.setAllowedUAs(tc.AllowedUAs)

			// Configure a primary VA with testcase remote VAs.
			localVA, mockLog := setup(ms.Server, 0, localUA, tc.RemoteVAs)

			if tc.Features != nil {
				err := features.Set(tc.Features)
				test.AssertNotError(t, err, "Failed to set feature flags")
				defer features.Reset()
			}

			// Perform all validations
			_, prob := localVA.PerformValidation(ctx, "localhost", chall, core.Authorization{})
			if prob == nil && tc.ExpectedProb != nil {
				t.Errorf("expected prob %v, got nil", tc.ExpectedProb)
			} else if prob != nil {
				// That result should match expected.
				test.AssertDeepEquals(t, prob, tc.ExpectedProb)
			}

			if tc.ExpectedLog != "" {
				lines := mockLog.GetAllMatching(tc.ExpectedLog)
				test.AssertEquals(t, len(lines), 1)
			}
		})
	}
}

func TestMultiVAEarlyReturn(t *testing.T) {
	chall := core.HTTPChallenge01("")
	setChallengeToken(&chall, core.NewToken())

	const (
		remoteUA1 = "remote 1"
		remoteUA2 = "slow remote"
		localUA   = "local 1"
	)
	allowedUAs := map[string]bool{
		localUA:   true,
		remoteUA1: false, // forbid UA 1 to provoke early return
		remoteUA2: true,
	}

	ms := httpMultiSrv(t, chall.Token, allowedUAs)
	defer ms.Close()

	remoteVA1, _ := setup(ms.Server, 0, remoteUA1, nil)
	remoteVA2, _ := setup(ms.Server, 0, remoteUA2, nil)

	remoteVAs := []RemoteVA{
		{remoteVA1, remoteUA1},
		{remoteVA2, remoteUA2},
	}

	// Create a local test VA with the two remote VAs
	localVA, mockLog := setup(ms.Server, 0, localUA, remoteVAs)

	testCases := []struct {
		Name        string
		EarlyReturn bool
	}{
		{
			Name: "One slow remote VA, no early return",
		},
		{
			Name:        "One slow remote VA, early return",
			EarlyReturn: true,
		},
	}

	earlyReturnFeatures := map[string]bool{
		"EnforceMultiVA":     true,
		"MultiVAFullResults": false,
	}
	noEarlyReturnFeatures := map[string]bool{
		"EnforceMultiVA":     true,
		"MultiVAFullResults": true,
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mockLog.Clear()

			var err error
			if tc.EarlyReturn {
				err = features.Set(earlyReturnFeatures)
			} else {
				err = features.Set(noEarlyReturnFeatures)
			}
			test.AssertNotError(t, err, "Failed to set MultiVAFullResults feature flag")
			defer features.Reset()

			start := time.Now()

			// Perform all validations
			_, prob := localVA.PerformValidation(ctx, "localhost", chall, core.Authorization{})
			// It should always fail
			if prob == nil {
				t.Error("expected prob from PerformValidation, got nil")
			}

			elapsed := time.Since(start).Round(time.Millisecond).Seconds()

			// The slow UA should sleep for 5 seconds. In the early return case the
			// first remote VA should fail the overall validation and a prob should be
			// returned quickly. In the non-early return case we don't expect
			// a problem for 5s.
			if tc.EarlyReturn && elapsed > 4.0 {
				t.Errorf(
					"Expected an early return from PerformValidation in < 4.0s, took %f",
					elapsed)
			}
		})
	}
}

func TestDetailedError(t *testing.T) {
	cases := []struct {
		err      error
		expected string
	}{
		{
			&net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: &os.SyscallError{
					Syscall: "getsockopt",
					Err:     syscall.ECONNREFUSED,
				},
			},
			"Connection refused",
		},
		{
			&net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: &os.SyscallError{
					Syscall: "getsockopt",
					Err:     syscall.ECONNRESET,
				},
			},
			"Connection reset by peer",
		},
	}
	for _, tc := range cases {
		actual := detailedError(tc.err).Detail
		if actual != tc.expected {
			t.Errorf("Wrong detail for %v. Got %q, expected %q", tc.err, actual, tc.expected)
		}
	}
}
