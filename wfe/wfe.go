package wfe

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/zzma/boulder/core"
	corepb "github.com/zzma/boulder/core/proto"
	berrors "github.com/zzma/boulder/errors"
	"github.com/zzma/boulder/features"
	"github.com/zzma/boulder/goodkey"
	bgrpc "github.com/zzma/boulder/grpc"
	"github.com/zzma/boulder/identifier"
	blog "github.com/zzma/boulder/log"
	"github.com/zzma/boulder/metrics"
	"github.com/zzma/boulder/metrics/measured_http"
	"github.com/zzma/boulder/nonce"
	noncepb "github.com/zzma/boulder/nonce/proto"
	"github.com/zzma/boulder/probs"
	rapb "github.com/zzma/boulder/ra/proto"
	"github.com/zzma/boulder/revocation"
	sapb "github.com/zzma/boulder/sa/proto"
	"github.com/zzma/boulder/web"
)

// Paths are the ACME-spec identified URL path-segments for various methods.
// NOTE: In metrics/measured_http we make the assumption that these are all
// lowercase plus hyphens. If you violate that assumption you should update
// measured_http.
const (
	directoryPath  = "/directory"
	newRegPath     = "/acme/new-reg"
	regPath        = "/acme/reg/"
	newAuthzPath   = "/acme/new-authz"
	authzPath      = "/acme/authz/"
	challengePath  = "/acme/challenge/"
	newCertPath    = "/acme/new-cert"
	certPath       = "/acme/cert/"
	revokeCertPath = "/acme/revoke-cert"
	termsPath      = "/terms"
	issuerPath     = "/acme/issuer-cert"
	buildIDPath    = "/build"
	rolloverPath   = "/acme/key-change"
)

const authz2Prefix = "v2"

// WebFrontEndImpl provides all the logic for Boulder's web-facing interface,
// i.e., ACME.  Its members configure the paths for various ACME functions,
// plus a few other data items used in ACME.  Its methods are primarily handlers
// for HTTPS requests for the various ACME functions.
type WebFrontEndImpl struct {
	RA    core.RegistrationAuthority
	SA    core.StorageGetter
	stats metrics.Scope
	log   blog.Logger
	clk   clock.Clock

	// URL configuration parameters
	BaseURL string

	// Issuer certificate (DER) for /acme/issuer-cert
	IssuerCert []byte

	// URL to the current subscriber agreement (should contain some version identifier)
	SubscriberAgreementURL string

	// DirectoryCAAIdentity is used for the /directory response's "meta"
	// element's "caaIdentities" field. It should match the VA's issuerDomain
	// field value.
	DirectoryCAAIdentity string

	// DirectoryWebsite is used for the /directory response's "meta" element's
	// "website" field.
	DirectoryWebsite string

	// Register of anti-replay nonces
	nonceService       *nonce.NonceService
	remoteNonceService noncepb.NonceServiceClient
	noncePrefixMap     map[string]noncepb.NonceServiceClient

	// Key policy.
	keyPolicy goodkey.KeyPolicy

	// CORS settings
	AllowOrigins []string

	// Maximum duration of a request
	RequestTimeout time.Duration

	AcceptRevocationReason bool
	AllowAuthzDeactivation bool

	csrSignatureAlgs *prometheus.CounterVec
}

// NewWebFrontEndImpl constructs a web service for Boulder
func NewWebFrontEndImpl(
	stats metrics.Scope,
	clk clock.Clock,
	keyPolicy goodkey.KeyPolicy,
	remoteNonceService noncepb.NonceServiceClient,
	noncePrefixMap map[string]noncepb.NonceServiceClient,
	logger blog.Logger,
) (WebFrontEndImpl, error) {
	csrSignatureAlgs := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "csrSignatureAlgs",
			Help: "Number of CSR signatures by algorithm",
		},
		[]string{"type"},
	)
	stats.MustRegister(csrSignatureAlgs)

	wfe := WebFrontEndImpl{
		log:                logger,
		clk:                clk,
		stats:              stats,
		keyPolicy:          keyPolicy,
		csrSignatureAlgs:   csrSignatureAlgs,
		remoteNonceService: remoteNonceService,
		noncePrefixMap:     noncePrefixMap,
	}

	if wfe.remoteNonceService == nil {
		nonceService, err := nonce.NewNonceService(stats, 0, "")
		if err != nil {
			return WebFrontEndImpl{}, err
		}
		wfe.nonceService = nonceService
	}

	return wfe, nil
}

// HandleFunc registers a handler at the given path. It's
// http.HandleFunc(), but with a wrapper around the handler that
// provides some generic per-request functionality:
//
// * Set a Replay-Nonce header.
//
// * Respond to OPTIONS requests, including CORS preflight requests.
//
// * Set a no cache header
//
// * Respond http.StatusMethodNotAllowed for HTTP methods other than
// those listed.
//
// * Set CORS headers when responding to CORS "actual" requests.
//
// * Never send a body in response to a HEAD request. Anything
// written by the handler will be discarded if the method is HEAD.
// Also, all handlers that accept GET automatically accept HEAD.
func (wfe *WebFrontEndImpl) HandleFunc(mux *http.ServeMux, pattern string, h web.WFEHandlerFunc, methods ...string) {
	methodsMap := make(map[string]bool)
	for _, m := range methods {
		methodsMap[m] = true
	}
	if methodsMap["GET"] && !methodsMap["HEAD"] {
		// Allow HEAD for any resource that allows GET
		methods = append(methods, "HEAD")
		methodsMap["HEAD"] = true
	}
	methodsStr := strings.Join(methods, ", ")
	handler := http.StripPrefix(pattern, web.NewTopHandler(wfe.log,
		web.WFEHandlerFunc(func(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
			// Historically we did not return a error to the client
			// if we failed to get a new nonce. We preserve that
			// behavior if using the built in nonce service, but
			// if we get a failure using the new remote nonce service
			// we return an internal server error so that it is
			// clearer both in our metrics and to the client that
			// something is wrong.
			if wfe.remoteNonceService != nil {
				nonceMsg, err := wfe.remoteNonceService.Nonce(ctx, &corepb.Empty{})
				if err != nil {
					wfe.sendError(response, logEvent, probs.ServerInternal("unable to get nonce"), err)
					return
				}
				response.Header().Set("Replay-Nonce", nonceMsg.Nonce)
			} else {
				nonce, err := wfe.nonceService.Nonce()
				if err == nil {
					response.Header().Set("Replay-Nonce", nonce)
				} else {
					logEvent.AddError("unable to make nonce: %s", err)
				}
			}

			logEvent.Endpoint = pattern
			if request.URL != nil {
				logEvent.Slug = request.URL.Path
			}

			switch request.Method {
			case "HEAD":
				// Go's net/http (and httptest) servers will strip out the body
				// of responses for us. This keeps the Content-Length for HEAD
				// requests as the same as GET requests per the spec.
			case "OPTIONS":
				wfe.Options(response, request, methodsStr, methodsMap)
				return
			}

			// No cache header is set for all requests, succeed or fail.
			addNoCacheHeader(response)

			if !methodsMap[request.Method] {
				response.Header().Set("Allow", methodsStr)
				wfe.sendError(response, logEvent, probs.MethodNotAllowed(), nil)
				return
			}

			wfe.setCORSHeaders(response, request, "")

			timeout := wfe.RequestTimeout
			if timeout == 0 {
				timeout = 5 * time.Minute
			}
			ctx, cancel := context.WithTimeout(ctx, timeout)
			// TODO(riking): add request context using WithValue

			// Call the wrapped handler.
			h(ctx, logEvent, response, request)
			cancel()
		}),
	))
	mux.Handle(pattern, handler)
}

func marshalIndent(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

func (wfe *WebFrontEndImpl) writeJsonResponse(response http.ResponseWriter, logEvent *web.RequestEvent, status int, v interface{}) error {
	jsonReply, err := marshalIndent(v)
	if err != nil {
		return err // All callers are responsible for handling this error
	}

	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, err = response.Write(jsonReply)
	if err != nil {
		// Don't worry about returning this error because the caller will
		// never handle it.
		wfe.log.Warningf("Could not write response: %s", err)
		logEvent.AddError(fmt.Sprintf("failed to write response: %s", err))
	}
	return nil
}

const randomDirKeyExplanationLink = "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417"

func (wfe *WebFrontEndImpl) relativeDirectory(request *http.Request, directory map[string]interface{}) ([]byte, error) {
	// Create an empty map sized equal to the provided directory to store the
	// relative-ized result
	relativeDir := make(map[string]interface{}, len(directory))

	// Copy each entry of the provided directory into the new relative map,
	// prefixing it with the request protocol and host.
	for k, v := range directory {
		if v == randomDirKeyExplanationLink {
			relativeDir[k] = v
			continue
		}
		switch v := v.(type) {
		case string:
			// Only relative-ize top level string values, e.g. not the "meta" element
			relativeDir[k] = web.RelativeEndpoint(request, v)
		default:
			// If it isn't a string, put it into the results unmodified
			relativeDir[k] = v
		}
	}

	directoryJSON, err := marshalIndent(relativeDir)
	// This should never happen since we are just marshalling known strings
	if err != nil {
		return nil, err
	}

	return directoryJSON, nil
}

// Handler returns an http.Handler that uses various functions for
// various ACME-specified paths.
func (wfe *WebFrontEndImpl) Handler() http.Handler {
	m := http.NewServeMux()
	wfe.HandleFunc(m, directoryPath, wfe.Directory, "GET")
	wfe.HandleFunc(m, newRegPath, wfe.NewRegistration, "POST")
	wfe.HandleFunc(m, newAuthzPath, wfe.NewAuthorization, "POST")
	wfe.HandleFunc(m, newCertPath, wfe.NewCertificate, "POST")
	wfe.HandleFunc(m, regPath, wfe.Registration, "POST")
	wfe.HandleFunc(m, authzPath, wfe.Authorization, "GET", "POST")
	wfe.HandleFunc(m, challengePath, wfe.Challenge, "GET", "POST")
	wfe.HandleFunc(m, certPath, wfe.Certificate, "GET")
	wfe.HandleFunc(m, revokeCertPath, wfe.RevokeCertificate, "POST")
	wfe.HandleFunc(m, termsPath, wfe.Terms, "GET")
	wfe.HandleFunc(m, issuerPath, wfe.Issuer, "GET")
	wfe.HandleFunc(m, buildIDPath, wfe.BuildID, "GET")
	wfe.HandleFunc(m, rolloverPath, wfe.KeyRollover, "POST")

	// We don't use our special HandleFunc for "/" because it matches everything,
	// meaning we can wind up returning 405 when we mean to return 404. See
	// https://github.com/letsencrypt/boulder/issues/717
	m.Handle("/", web.NewTopHandler(wfe.log, web.WFEHandlerFunc(wfe.Index)))
	return measured_http.New(m, wfe.clk, wfe.stats)
}

// Method implementations

// Index serves a simple identification page. It is not part of the ACME spec.
func (wfe *WebFrontEndImpl) Index(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	// http://golang.org/pkg/net/http/#example_ServeMux_Handle
	// The "/" pattern matches everything, so we need to check
	// that we're at the root here.
	if request.URL.Path != "/" {
		logEvent.AddError("Resource not found")
		http.NotFound(response, request)
		response.Header().Set("Content-Type", "application/problem+json")
		return
	}

	if request.Method != "GET" {
		logEvent.AddError("Bad method")
		response.Header().Set("Allow", "GET")
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	addNoCacheHeader(response)
	response.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(response, `<html>
		<body>
			This is an <a href="https://github.com/ietf-wg-acme/acme/">ACME</a>
			Certificate Authority running <a href="https://github.com/letsencrypt/boulder">Boulder</a>.
			JSON directory is available at <a href="%s">%s</a>.
		</body>
	</html>
	`, directoryPath, directoryPath)
}

func addNoCacheHeader(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", "public, max-age=0, no-cache")
}

func addRequesterHeader(w http.ResponseWriter, requester int64) {
	if requester > 0 {
		w.Header().Set("Boulder-Requester", strconv.FormatInt(requester, 10))
	}
}

// Directory is an HTTP request handler that provides the directory
// object stored in the WFE's DirectoryEndpoints member with paths prefixed
// using the `request.Host` of the HTTP request.
func (wfe *WebFrontEndImpl) Directory(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	directoryEndpoints := map[string]interface{}{
		"new-reg":     newRegPath,
		"new-authz":   newAuthzPath,
		"new-cert":    newCertPath,
		"revoke-cert": revokeCertPath,
	}

	// Versions of Certbot pre-0.6.0 (named LetsEncryptPythonClient at the time) break when they
	// encounter a directory containing elements they don't expect so we gate
	// adding new directory fields for clients matching this UA.
	clientDirChangeIntolerant := strings.HasPrefix(request.UserAgent(), "LetsEncryptPythonClient")
	if !clientDirChangeIntolerant {
		directoryEndpoints["key-change"] = rolloverPath
	}
	if !clientDirChangeIntolerant {
		// Add a random key to the directory in order to make sure that clients don't hardcode an
		// expected set of keys. This ensures that we can properly extend the directory when we
		// need to add a new endpoint or meta element.
		directoryEndpoints[core.RandomString(8)] = randomDirKeyExplanationLink

		// ACME since draft-02 describes an optional "meta" directory entry. The
		// meta entry may optionally contain a "terms-of-service" URI for the
		// current ToS.
		metaMap := map[string]interface{}{
			"terms-of-service": wfe.SubscriberAgreementURL,
		}
		// The "meta" directory entry may also include a []string of CAA identities
		if wfe.DirectoryCAAIdentity != "" {
			// The specification says caaIdentities is an array of strings. In
			// practice Boulder's VA only allows configuring ONE CAA identity. Given
			// that constraint it doesn't make sense to allow multiple directory CAA
			// identities so we use just the `wfe.DirectoryCAAIdentity` alone.
			metaMap["caaIdentities"] = []string{
				wfe.DirectoryCAAIdentity,
			}
		}
		// The "meta" directory entry may also include a string with a website URL
		if wfe.DirectoryWebsite != "" {
			metaMap["website"] = wfe.DirectoryWebsite
		}
		directoryEndpoints["meta"] = metaMap
	}

	response.Header().Set("Content-Type", "application/json")

	relDir, err := wfe.relativeDirectory(request, directoryEndpoints)
	if err != nil {
		marshalProb := probs.ServerInternal("unable to marshal JSON directory")
		wfe.sendError(response, logEvent, marshalProb, nil)
		return
	}

	response.Write(relDir)
}

const (
	unknownKey = "No registration exists matching provided key"
)

func (wfe *WebFrontEndImpl) extractJWSKey(body string) (*jose.JSONWebKey, *jose.JSONWebSignature, error) {
	parsedJws, err := jose.ParseSigned(body)
	if err != nil {
		wfe.stats.Inc("Errors.UnableToParseJWS", 1)
		return nil, nil, errors.New("Parse error reading JWS")
	}

	if len(parsedJws.Signatures) > 1 {
		wfe.stats.Inc("Errors.TooManyJWSSignaturesInPOST", 1)
		return nil, nil, errors.New("Too many signatures in POST body")
	}
	if len(parsedJws.Signatures) == 0 {
		wfe.stats.Inc("Errors.JWSNotSignedInPOST", 1)
		return nil, nil, errors.New("POST JWS not signed")
	}

	key := parsedJws.Signatures[0].Header.JSONWebKey
	if key == nil {
		wfe.stats.Inc("Errors.NoJWKInJWSSignatureHeader", 1)
		return nil, nil, errors.New("No JWK in JWS header")
	}

	if !key.Valid() {
		wfe.stats.Inc("Errors.InvalidJWK", 1)
		return nil, nil, errors.New("Invalid JWK in JWS header")
	}

	return key, parsedJws, nil
}

// verifyPOST reads and parses the request body, looks up the Registration
// corresponding to its JWK, verifies the JWS signature, checks that the
// resource field is present and correct in the JWS protected header, and
// returns the JWS payload bytes, the key used to verify, and the corresponding
// Registration (or error).  If regCheck is false, verifyPOST will still try to
// look up a registration object, and will return it if found. However, if no
// registration object is found, verifyPOST will attempt to verify the JWS using
// the key in the JWS headers, and return the key plus a dummy registration if
// successful. If a caller passes regCheck = false, it should plan on validating
// the key itself.  verifyPOST also appends its errors to web.RequestEvent.Errors so
// code calling it does not need to if they immediately return a response to the
// user.
func (wfe *WebFrontEndImpl) verifyPOST(ctx context.Context, logEvent *web.RequestEvent, request *http.Request, regCheck bool, resource core.AcmeResource) ([]byte, *jose.JSONWebKey, core.Registration, *probs.ProblemDetails) {
	// TODO: We should return a pointer to a registration, which can be nil,
	// rather the a registration value with a sentinel value.
	// https://github.com/letsencrypt/boulder/issues/877
	reg := core.Registration{ID: 0}

	if _, ok := request.Header["Content-Length"]; !ok {
		wfe.stats.Inc("HTTP.ClientErrors.LengthRequiredError", 1)
		return nil, nil, reg, probs.ContentLengthRequired()
	}

	// Read body
	if request.Body == nil {
		wfe.stats.Inc("Errors.NoPOSTBody", 1)
		return nil, nil, reg, probs.Malformed("No body on POST")
	}

	bodyBytes, err := ioutil.ReadAll(request.Body)
	if err != nil {
		wfe.stats.Inc("Errors.UnableToReadRequestBody", 1)
		return nil, nil, reg, probs.ServerInternal("unable to read request body")
	}

	body := string(bodyBytes)

	// Verify JWS
	// NOTE: It might seem insecure for the WFE to be trusted to verify
	// client requests, i.e., that the verification should be done at the
	// RA.  However the WFE is the RA's only view of the outside world
	// *anyway*, so it could always lie about what key was used by faking
	// the signature itself.
	submittedKey, parsedJws, err := wfe.extractJWSKey(body)
	if err != nil {
		return nil, nil, reg, probs.Malformed(err.Error())
	}

	var key *jose.JSONWebKey
	reg, err = wfe.SA.GetRegistrationByKey(ctx, submittedKey)
	// Special case: If no registration was found, but regCheck is false, use an
	// empty registration and the submitted key. The caller is expected to do some
	// validation on the returned key.
	if berrors.Is(err, berrors.NotFound) && !regCheck {
		// When looking up keys from the registrations DB, we can be confident they
		// are "good". But when we are verifying against any submitted key, we want
		// to check its quality before doing the verify.
		if err = wfe.keyPolicy.GoodKey(submittedKey.Key); err != nil {
			wfe.stats.Inc("Errors.JWKRejectedByGoodKey", 1)
			return nil, nil, reg, probs.Malformed(err.Error())
		}
		key = submittedKey
	} else if err != nil {
		// For all other errors, or if regCheck is true, return error immediately.
		wfe.stats.Inc("Errors.UnableToGetRegistrationByKey", 1)
		logEvent.AddError("unable to fetch registration by the given JWK: %s", err)
		if berrors.Is(err, berrors.NotFound) {
			return nil, nil, reg, probs.Unauthorized(unknownKey)
		}

		return nil, nil, reg, probs.ServerInternal("Failed to get registration by key")
	} else {
		// If the lookup was successful, use that key.
		key = reg.Key
		logEvent.Requester = reg.ID
		if reg.Contact != nil {
			logEvent.Contacts = *reg.Contact
		}
	}

	// Only check for validity if we are actually checking the registration
	if regCheck && reg.Status != core.StatusValid {
		return nil, nil, reg, probs.Unauthorized("Registration is not valid, has status '%s'", reg.Status)
	}

	if statName, err := checkAlgorithm(key, parsedJws); err != nil {
		wfe.stats.Inc(statName, 1)
		return nil, nil, reg, probs.Malformed(err.Error())
	}

	payload, err := parsedJws.Verify(key)
	if err != nil {
		wfe.stats.Inc("Errors.JWSVerificationFailed", 1)
		n := len(body)
		if n > 100 {
			n = 100
		}
		logEvent.AddError("verification of JWS with the JWK failed: %v; body: %s", err, body[:n])
		return nil, nil, reg, probs.Malformed("JWS verification error")
	}
	logEvent.Payload = string(payload)

	// Check that the request has a known anti-replay nonce
	nonceStr := parsedJws.Signatures[0].Header.Nonce
	if len(nonceStr) == 0 {
		wfe.stats.Inc("Errors.JWSMissingNonce", 1)
		return nil, nil, reg, probs.BadNonce("JWS has no anti-replay nonce")
	}
	var nonceValid bool
	if wfe.remoteNonceService != nil {
		valid, err := nonce.RemoteRedeem(ctx, wfe.noncePrefixMap, nonceStr)
		if err != nil {
			return nil, nil, reg, probs.ServerInternal("failed to verify nonce validity: %s", err)
		}
		nonceValid = valid
	} else {
		nonceValid = wfe.nonceService.Valid(nonceStr)
	}
	if !nonceValid {
		wfe.stats.Inc("Errors.JWSInvalidNonce", 1)
		return nil, nil, reg, probs.BadNonce("JWS has invalid anti-replay nonce %s", nonceStr)
	}

	// Check that the "resource" field is present and has the correct value
	var parsedRequest struct {
		Resource string `json:"resource"`
	}
	err = json.Unmarshal([]byte(payload), &parsedRequest)
	if err != nil {
		wfe.stats.Inc("Errors.UnparseableJWSPayload", 1)
		return nil, nil, reg, probs.Malformed("Request payload did not parse as JSON")
	}
	if parsedRequest.Resource == "" {
		wfe.stats.Inc("Errors.NoResourceInJWSPayload", 1)
		return nil, nil, reg, probs.Malformed("Request payload does not specify a resource")
	} else if resource != core.AcmeResource(parsedRequest.Resource) {
		wfe.stats.Inc("Errors.MismatchedResourceInJWSPayload", 1)
		return nil, nil, reg, probs.Malformed("JWS resource payload does not match the HTTP resource: %s != %s", parsedRequest.Resource, resource)
	}

	return []byte(payload), key, reg, nil
}

// sendError wraps web.SendError
func (wfe *WebFrontEndImpl) sendError(response http.ResponseWriter, logEvent *web.RequestEvent, prob *probs.ProblemDetails, ierr error) {
	wfe.stats.Inc(fmt.Sprintf("HTTP.ProblemTypes.%s", prob.Type), 1)
	web.SendError(wfe.log, probs.V1ErrorNS, response, logEvent, prob, ierr)
}

func link(url, relation string) string {
	return fmt.Sprintf("<%s>;rel=\"%s\"", url, relation)
}

// NewRegistration is used by clients to submit a new registration/account
func (wfe *WebFrontEndImpl) NewRegistration(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	body, key, _, prob := wfe.verifyPOST(ctx, logEvent, request, false, core.ResourceNewReg)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		// verifyPOST handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	existingReg, err := wfe.SA.GetRegistrationByKey(ctx, key)
	if err != nil && !berrors.Is(err, berrors.NotFound) {
		wfe.sendError(response, logEvent, probs.ServerInternal("couldn't retrieve the registration"), err)
		return
	} else if err == nil || !berrors.Is(err, berrors.NotFound) {
		response.Header().Set("Location", web.RelativeEndpoint(request, fmt.Sprintf("%s%d", regPath, existingReg.ID)))
		wfe.sendError(response, logEvent, probs.Conflict("Registration key is already in use"), err)
		return
	}

	var init core.Registration
	err = json.Unmarshal(body, &init)
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling JSON"), err)
		return
	}
	if len(init.Agreement) > 0 && init.Agreement != wfe.SubscriberAgreementURL {
		msg := fmt.Sprintf("Provided agreement URL [%s] does not match current agreement URL [%s]", init.Agreement, wfe.SubscriberAgreementURL)
		wfe.sendError(response, logEvent, probs.Malformed(msg), nil)
		return
	}
	init.Key = key
	init.InitialIP = net.ParseIP(request.Header.Get("X-Real-IP"))
	if init.InitialIP == nil {
		host, _, err := net.SplitHostPort(request.RemoteAddr)
		if err == nil {
			init.InitialIP = net.ParseIP(host)
		} else {
			wfe.sendError(
				response,
				logEvent,
				probs.ServerInternal("couldn't parse the remote (that is, the client's) address"),
				fmt.Errorf("Couldn't parse RemoteAddr: %s", request.RemoteAddr),
			)
			return
		}
	}

	reg, err := wfe.RA.NewRegistration(ctx, init)
	if err != nil {
		if berrors.Is(err, berrors.Duplicate) {
			existingReg, err := wfe.SA.GetRegistrationByKey(ctx, key)
			if err != nil {
				// return error even if berrors.NotFound, as the duplicate key error we got from
				// ra.NewRegistration indicates it _does_ already exist.
				wfe.sendError(response, logEvent, probs.ServerInternal("couldn't retrieve the registration"), err)
				return
			}
			response.Header().Set("Location", web.RelativeEndpoint(request, fmt.Sprintf("%s%d", regPath, existingReg.ID)))
			wfe.sendError(response, logEvent, probs.Conflict("Registration key is already in use"), err)
			return
		}
		wfe.sendError(response, logEvent, web.ProblemDetailsForError(err, "Error creating new registration"), err)
		return
	}
	logEvent.Requester = reg.ID
	addRequesterHeader(response, reg.ID)
	if reg.Contact != nil {
		logEvent.Contacts = *reg.Contact
	}

	// Use an explicitly typed variable. Otherwise `go vet' incorrectly complains
	// that reg.ID is a string being passed to %d.
	regURL := web.RelativeEndpoint(request, fmt.Sprintf("%s%d", regPath, reg.ID))

	response.Header().Add("Location", regURL)
	response.Header().Add("Link", link(web.RelativeEndpoint(request, newAuthzPath), "next"))
	if len(wfe.SubscriberAgreementURL) > 0 {
		response.Header().Add("Link", link(wfe.SubscriberAgreementURL, "terms-of-service"))
	}

	err = wfe.writeJsonResponse(response, logEvent, http.StatusCreated, reg)
	if err != nil {
		// ServerInternal because we just created this registration, and it
		// should be OK.
		wfe.sendError(response, logEvent, probs.ServerInternal("Error marshaling registration"), err)
		return
	}
}

// NewAuthorization is used by clients to submit a new ID Authorization
func (wfe *WebFrontEndImpl) NewAuthorization(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	body, _, currReg, prob := wfe.verifyPOST(ctx, logEvent, request, true, core.ResourceNewAuthz)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		// verifyPOST handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}
	// Any version of the agreement is acceptable here. Version match is enforced in
	// wfe.Registration when agreeing the first time. Agreement updates happen
	// by mailing subscribers and don't require a registration update.
	if currReg.Agreement == "" {
		wfe.sendError(response, logEvent, probs.Unauthorized("Must agree to subscriber agreement before any further actions"), nil)
		return
	}

	var init core.Authorization
	if err := json.Unmarshal(body, &init); err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling JSON"), err)
		return
	}
	if init.Identifier.Type == identifier.DNS {
		logEvent.DNSName = init.Identifier.Value
	}

	// Create new authz and return
	authz, err := wfe.RA.NewAuthorization(ctx, init, currReg.ID)
	if err != nil {
		wfe.sendError(response, logEvent, web.ProblemDetailsForError(err, "Error creating new authz"), err)
		return
	}
	logEvent.Created = authz.ID

	// Make a URL for this authz, then blow away the ID and RegID before serializing
	authzURL := urlForAuthz(authz, request)
	wfe.prepAuthorizationForDisplay(request, &authz)

	response.Header().Add("Location", authzURL)
	response.Header().Add("Link", link(web.RelativeEndpoint(request, newCertPath), "next"))

	err = wfe.writeJsonResponse(response, logEvent, http.StatusCreated, authz)
	if err != nil {
		// ServerInternal because we generated the authz, it should be OK
		wfe.sendError(response, logEvent, probs.ServerInternal("Error marshaling authz"), err)
		return
	}
}

func (wfe *WebFrontEndImpl) regHoldsAuthorizations(ctx context.Context, regID int64, names []string) (bool, error) {
	var authzMap map[string]*core.Authorization
	if features.Enabled(features.NewAuthorizationSchema) {
		now := wfe.clk.Now().UnixNano()
		authzMapPB, err := wfe.SA.GetValidAuthorizations2(ctx, &sapb.GetValidAuthorizationsRequest{
			RegistrationID: &regID,
			Domains:        names,
			Now:            &now,
		})
		if err != nil {
			return false, err
		}
		authzMap, err = bgrpc.PBToAuthzMap(authzMapPB)
		if err != nil {
			return false, err
		}
	} else {
		var err error
		authzMap, err = wfe.SA.GetValidAuthorizations(ctx, regID, names, wfe.clk.Now())
		if err != nil {
			return false, err
		}
	}
	if len(names) != len(authzMap) {
		return false, nil
	}
	missingNames := false
	for _, name := range names {
		if _, present := authzMap[name]; !present {
			missingNames = true
		}
	}
	return !missingNames, nil
}

// RevokeCertificate is used by clients to request the revocation of a cert.
func (wfe *WebFrontEndImpl) RevokeCertificate(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	// We don't ask verifyPOST to verify there is a corresponding registration,
	// because anyone with the right private key can revoke a certificate.
	body, requestKey, registration, prob := wfe.verifyPOST(ctx, logEvent, request, false, core.ResourceRevokeCert)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		// verifyPOST handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	type RevokeRequest struct {
		CertificateDER core.JSONBuffer    `json:"certificate"`
		Reason         *revocation.Reason `json:"reason"`
	}
	var revokeRequest RevokeRequest
	if err := json.Unmarshal(body, &revokeRequest); err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Unable to JSON parse revoke request"), err)
		return
	}
	providedCert, err := x509.ParseCertificate(revokeRequest.CertificateDER)
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Unable to parse revoke certificate DER"), err)
		return
	}

	serial := core.SerialToString(providedCert.SerialNumber)
	logEvent.Extra["ProvidedCertificateSerial"] = serial
	cert, err := wfe.SA.GetCertificate(ctx, serial)
	// TODO(#991): handle db errors better
	if err != nil || !bytes.Equal(cert.DER, revokeRequest.CertificateDER) {
		wfe.sendError(response, logEvent, probs.NotFound("No such certificate"), err)
		return
	}
	parsedCertificate, err := x509.ParseCertificate(cert.DER)
	if err != nil {
		// InternalServerError because this is a failure to decode from our DB.
		wfe.sendError(response, logEvent, probs.ServerInternal("invalid parse of stored certificate"), err)
		return
	}
	if parsedCertificate.NotAfter.Before(wfe.clk.Now()) {
		wfe.sendError(response, logEvent, probs.Unauthorized("Certificate is expired"), nil)
		return
	}
	logEvent.Extra["RetrievedCertificateSerial"] = core.SerialToString(parsedCertificate.SerialNumber)
	logEvent.Extra["RetrievedCertificateDNSNames"] = parsedCertificate.DNSNames
	logEvent.Extra["RetrievedCertificateEmailAddresses"] = parsedCertificate.EmailAddresses
	logEvent.Extra["RetrievedCertificateIPAddresses"] = parsedCertificate.IPAddresses

	certStatus, err := wfe.SA.GetCertificateStatus(ctx, serial)
	if err != nil {
		// TODO(#991): handle db errors
		wfe.sendError(response, logEvent, probs.NotFound("Certificate status not yet available"), err)
		return
	}
	logEvent.Extra["CertificateStatus"] = certStatus.Status

	if certStatus.Status == core.OCSPStatusRevoked {
		wfe.sendError(response, logEvent, probs.Conflict("Certificate already revoked"), nil)
		return
	}

	if !(core.KeyDigestEquals(requestKey, parsedCertificate.PublicKey) || registration.ID == cert.RegistrationID) {
		valid, err := wfe.regHoldsAuthorizations(ctx, registration.ID, parsedCertificate.DNSNames)
		if err != nil {
			wfe.sendError(response, logEvent, probs.ServerInternal("Failed to retrieve authorizations for names in certificate"), err)
			return
		}
		if !valid {
			wfe.sendError(response, logEvent,
				probs.Unauthorized("Revocation request must be signed by private key of cert to be revoked, by the "+
					"account key of the account that issued it, or by the account key of an account that holds valid "+
					"authorizations for all names in the certificate."),
				nil)
			return
		}
	}

	reason := revocation.Reason(0)
	if revokeRequest.Reason != nil && wfe.AcceptRevocationReason {
		if _, present := revocation.UserAllowedReasons[*revokeRequest.Reason]; !present {
			wfe.sendError(response, logEvent, probs.Malformed("unsupported revocation reason code provided"), nil)
			return
		}
		reason = *revokeRequest.Reason
	}

	err = wfe.RA.RevokeCertificateWithReg(ctx, *parsedCertificate, reason, registration.ID)
	if err != nil {
		wfe.sendError(response, logEvent, web.ProblemDetailsForError(err, "Failed to revoke certificate"), err)
	} else {
		wfe.log.Debugf("Revoked %v", serial)
		response.WriteHeader(http.StatusOK)
	}
}

func (wfe *WebFrontEndImpl) logCsr(request *http.Request, cr core.CertificateRequest, registration core.Registration) {
	var csrLog = struct {
		ClientAddr string
		CSR        string
		Requester  int64
	}{
		ClientAddr: web.GetClientAddr(request),
		CSR:        hex.EncodeToString(cr.Bytes),
		Requester:  registration.ID,
	}
	wfe.log.AuditObject("Certificate request", csrLog)
}

// NewCertificate is used by clients to request the issuance of a cert for an
// authorized identifier.
func (wfe *WebFrontEndImpl) NewCertificate(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	body, _, reg, prob := wfe.verifyPOST(ctx, logEvent, request, true, core.ResourceNewCert)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		// verifyPOST handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}
	// Any version of the agreement is acceptable here. Version match is enforced in
	// wfe.Registration when agreeing the first time. Agreement updates happen
	// by mailing subscribers and don't require a registration update.
	if reg.Agreement == "" {
		wfe.sendError(response, logEvent, probs.Unauthorized("Must agree to subscriber agreement before any further actions"), nil)
		return
	}

	var rawCSR core.RawCertificateRequest
	err := json.Unmarshal(body, &rawCSR)
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling certificate request"), err)
		return
	}
	// Assuming a properly formatted CSR there should be two four byte SEQUENCE
	// declarations then a two byte integer declaration which defines the version
	// of the CSR. If those two bytes (at offset 8 and 9) and equal to 2 and 0
	// then the CSR was generated by a pre-1.0.2 version of OpenSSL with a client
	// which didn't explicitly set the version causing the integer to be malformed
	// and encoding/asn1 will refuse to parse it. If this is the case exit early
	// with a more useful error message.
	if len(rawCSR.CSR) >= 10 && rawCSR.CSR[8] == 2 && rawCSR.CSR[9] == 0 {
		wfe.sendError(
			response,
			logEvent,
			probs.Malformed("CSR generated using a pre-1.0.2 OpenSSL with a client that doesn't properly specify the CSR version. See https://community.letsencrypt.org/t/openssl-bug-information/19591"),
			nil,
		)
		return
	}

	certificateRequest := core.CertificateRequest{Bytes: rawCSR.CSR}
	certificateRequest.CSR, err = x509.ParseCertificateRequest(rawCSR.CSR)
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Error parsing certificate request: %s", err), err)
		return
	}
	wfe.logCsr(request, certificateRequest, reg)
	// Check that the key in the CSR is good. This will also be checked in the CA
	// component, but we want to discard CSRs with bad keys as early as possible
	// because (a) it's an easy check and we can save unnecessary requests and
	// bytes on the wire, and (b) the CA logs all rejections as audit events, but
	// a bad key from the client is just a malformed request and doesn't need to
	// be audited.
	if err := wfe.keyPolicy.GoodKey(certificateRequest.CSR.PublicKey); err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Invalid key in certificate request :: %s", err), err)
		return
	}
	logEvent.Extra["CSRDNSNames"] = certificateRequest.CSR.DNSNames
	logEvent.Extra["CSREmailAddresses"] = certificateRequest.CSR.EmailAddresses
	logEvent.Extra["CSRIPAddresses"] = certificateRequest.CSR.IPAddresses

	// Inc CSR signature algorithm counter
	wfe.csrSignatureAlgs.With(prometheus.Labels{"type": certificateRequest.CSR.SignatureAlgorithm.String()}).Inc()

	// Create new certificate and return
	// TODO IMPORTANT: The RA trusts the WFE to provide the correct key. If the
	// WFE is compromised, *and* the attacker knows the public key of an account
	// authorized for target site, they could cause issuance for that site by
	// lying to the RA. We should probably pass a copy of the whole request to the
	// RA for secondary validation.
	cert, err := wfe.RA.NewCertificate(ctx, certificateRequest, reg.ID)
	if err != nil {
		wfe.sendError(response, logEvent, web.ProblemDetailsForError(err, "Error creating new cert"), err)
		return
	}

	// Make a URL for this certificate.
	// We use only the sequential part of the serial number, because it should
	// uniquely identify the certificate, and this makes it easy for anybody to
	// enumerate and mirror our certificates.
	parsedCertificate, err := x509.ParseCertificate([]byte(cert.DER))
	if err != nil {
		wfe.sendError(response, logEvent, probs.ServerInternal("Unable to parse certificate"), err)
		return
	}
	serial := parsedCertificate.SerialNumber
	certURL := web.RelativeEndpoint(request, certPath+core.SerialToString(serial))

	// TODO Content negotiation
	response.Header().Add("Location", certURL)
	relativeIssuerPath := web.RelativeEndpoint(request, issuerPath)
	response.Header().Add("Link", link(relativeIssuerPath, "up"))
	response.Header().Set("Content-Type", "application/pkix-cert")
	response.WriteHeader(http.StatusCreated)
	if _, err = response.Write(cert.DER); err != nil {
		wfe.log.Warningf("Could not write response: %s", err)
	}
}

// Challenge handles POST requests to challenge URLs.  Such requests are clients'
// responses to the server's challenges.
func (wfe *WebFrontEndImpl) Challenge(
	ctx context.Context,
	logEvent *web.RequestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	notFound := func() {
		wfe.sendError(response, logEvent, probs.NotFound("No such challenge"), nil)
	}

	// Challenge URIs are of the form /acme/challenge/<auth id>/<challenge id>
	// or /acme/challenge/v2/<auth id>/<challenge id> depending on the authorization
	// version. Here we parse out the authorization and challenge IDs and retrieve
	// the authorization.
	slug := strings.Split(request.URL.Path, "/")
	if len(slug) != 2 && len(slug) != 3 {
		notFound()
		return
	}
	var authorizationID string
	var challengeID interface{}
	var err error
	var v2 bool
	if len(slug) == 3 {
		if !features.Enabled(features.NewAuthorizationSchema) || slug[0] != authz2Prefix {
			notFound()
			return
		}
		v2 = true
		authorizationID, challengeID = slug[1], slug[2]
	} else {
		authorizationID = slug[0]
		challengeID, err = strconv.ParseInt(slug[1], 10, 64)
		if err != nil {
			notFound()
			return
		}
	}

	var authz core.Authorization
	if v2 {
		id, err := strconv.ParseInt(authorizationID, 10, 64)
		if err != nil {
			notFound()
			return
		}
		authzPB, err := wfe.SA.GetAuthorization2(ctx, &sapb.AuthorizationID2{Id: &id})
		if err != nil {
			if berrors.Is(err, berrors.NotFound) {
				notFound()
			} else {
				wfe.sendError(response, logEvent, probs.ServerInternal("Problem getting authorization"), err)
			}
			return
		}
		authz, err = bgrpc.PBToAuthz(authzPB)
		if err != nil {
			wfe.sendError(response, logEvent, probs.ServerInternal("Problem getting authorization"), err)
			return
		}
	} else {
		authz, err = wfe.SA.GetAuthorization(ctx, authorizationID)
		if err != nil {
			if berrors.Is(err, berrors.NotFound) {
				notFound()
			} else {
				wfe.sendError(response, logEvent, probs.ServerInternal("Problem getting authorization"), err)
			}
			return
		}
	}

	// After expiring, challenges are inaccessible
	if authz.Expires == nil || authz.Expires.Before(wfe.clk.Now()) {
		wfe.sendError(response, logEvent, probs.NotFound("Expired authorization"), nil)
		return
	}

	// Check that the requested challenge exists within the authorization
	var challengeIndex int
	if authz.V2 {
		challengeIndex = authz.FindChallengeByStringID(challengeID.(string))
	} else {
		challengeIndex = authz.FindChallenge(challengeID.(int64))
	}
	if challengeIndex == -1 {
		notFound()
		return
	}
	challenge := authz.Challenges[challengeIndex]

	if authz.Identifier.Type == identifier.DNS {
		logEvent.DNSName = authz.Identifier.Value
	}
	logEvent.Status = string(authz.Status)

	switch request.Method {
	case "GET", "HEAD":
		wfe.getChallenge(ctx, response, request, authz, &challenge, logEvent)

	case "POST":
		logEvent.ChallengeType = challenge.Type
		wfe.postChallenge(ctx, response, request, authz, challengeIndex, logEvent)
	}
}

// prepChallengeForDisplay takes a core.Challenge and prepares it for display to
// the client by filling in its URI field and clearing its ID field.
func (wfe *WebFrontEndImpl) prepChallengeForDisplay(request *http.Request, authz core.Authorization, challenge *core.Challenge) {
	// Update the challenge URI to be relative to the HTTP request Host
	if authz.V2 {
		challenge.URI = web.RelativeEndpoint(request, fmt.Sprintf("%s%s/%s/%s", challengePath, authz2Prefix, authz.ID, challenge.StringID()))
	} else {
		challenge.URI = web.RelativeEndpoint(request, fmt.Sprintf("%s%s/%d", challengePath, authz.ID, challenge.ID))
	}
	// Ensure the challenge ID isn't written. 0 is considered "empty" for the purpose of the JSON omitempty tag.
	challenge.ID = 0

	// Historically the Type field of a problem was always prefixed with a static
	// error namespace. To support the V2 API and migrating to the correct IETF
	// namespace we now prefix the Type with the correct namespace at runtime when
	// we write the problem JSON to the user. We skip this process if the
	// challenge error type has already been prefixed with the V1ErrorNS.
	if challenge.Error != nil && !strings.HasPrefix(string(challenge.Error.Type), probs.V1ErrorNS) {
		challenge.Error.Type = probs.V1ErrorNS + challenge.Error.Type
	}

	// If the authz has been marked invalid, consider all challenges on that authz
	// to be invalid as well.
	if authz.Status == core.StatusInvalid {
		challenge.Status = authz.Status
	}
}

// prepAuthorizationForDisplay takes a core.Authorization and prepares it for
// display to the client by clearing its ID and RegistrationID fields, and
// preparing all its challenges.
func (wfe *WebFrontEndImpl) prepAuthorizationForDisplay(request *http.Request, authz *core.Authorization) {
	for i := range authz.Challenges {
		wfe.prepChallengeForDisplay(request, *authz, &authz.Challenges[i])
		authz.Combinations = append(authz.Combinations, []int{i})
	}
	authz.ID = ""
	authz.RegistrationID = 0
}

func (wfe *WebFrontEndImpl) getChallenge(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	authz core.Authorization,
	challenge *core.Challenge,
	logEvent *web.RequestEvent) {

	wfe.prepChallengeForDisplay(request, authz, challenge)

	authzURL := urlForAuthz(authz, request)
	response.Header().Add("Location", challenge.URI)
	response.Header().Add("Link", link(authzURL, "up"))

	err := wfe.writeJsonResponse(response, logEvent, http.StatusAccepted, challenge)
	if err != nil {
		// InternalServerError because this is a failure to decode data passed in
		// by the caller, which got it from the DB.
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to marshal challenge"), err)
		return
	}
}

func (wfe *WebFrontEndImpl) postChallenge(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	authz core.Authorization,
	challengeIndex int,
	logEvent *web.RequestEvent) {
	body, _, currReg, prob := wfe.verifyPOST(ctx, logEvent, request, true, core.ResourceChallenge)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		// verifyPOST handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}
	// Any version of the agreement is acceptable here. Version match is enforced in
	// wfe.Registration when agreeing the first time. Agreement updates happen
	// by mailing subscribers and don't require a registration update.
	if currReg.Agreement == "" {
		wfe.sendError(response, logEvent, probs.Unauthorized("Registration didn't agree to subscriber agreement before any further actions"), nil)
		return
	}

	// Check that the registration ID matching the key used matches
	// the registration ID on the authz object
	if currReg.ID != authz.RegistrationID {
		wfe.sendError(response,
			logEvent,
			probs.Unauthorized("User registration ID doesn't match registration ID in authorization"),
			fmt.Errorf("User registration id: %d != Authorization registration id: %v", currReg.ID, authz.RegistrationID),
		)
		return
	}

	// We can expect some clients to try and update a challenge for an authorization
	// that is already valid. In this case we don't need to process the challenge
	// update. It wouldn't be helpful, the overall authorization is already good! We
	// increment a stat for this case and return early.
	var returnAuthz core.Authorization
	if authz.Status == core.StatusValid {
		wfe.stats.Inc("ReusedValidAuthzChallengeWFE", 1)
		returnAuthz = authz
	} else {
		var challengeUpdate core.Challenge
		if err := json.Unmarshal(body, &challengeUpdate); err != nil {
			wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling challenge response"), err)
			return
		}

		authzPB, err := bgrpc.AuthzToPB(authz)
		if err != nil {
			wfe.sendError(response, logEvent, web.ProblemDetailsForError(err, "Unable to serialize authz"), err)
			return
		}
		challIndex := int64(challengeIndex)

		authzPB, err = wfe.RA.PerformValidation(ctx, &rapb.PerformValidationRequest{
			Authz:          authzPB,
			ChallengeIndex: &challIndex})
		if err != nil {
			wfe.sendError(
				response,
				logEvent,
				web.ProblemDetailsForError(err, "Unable to perform validation for challenge"),
				err)
			return
		}
		updatedAuthz, err := bgrpc.PBToAuthz(authzPB)
		if err != nil {
			wfe.sendError(response, logEvent, web.ProblemDetailsForError(err, "Unable to deserialize authz"), err)
			return
		}
		returnAuthz = updatedAuthz
	}

	// assumption: PerformValidation does not modify order of challenges
	challenge := returnAuthz.Challenges[challengeIndex]
	wfe.prepChallengeForDisplay(request, authz, &challenge)

	authzURL := urlForAuthz(authz, request)
	response.Header().Add("Location", challenge.URI)
	response.Header().Add("Link", link(authzURL, "up"))

	err := wfe.writeJsonResponse(response, logEvent, http.StatusAccepted, challenge)
	if err != nil {
		// ServerInternal because we made the challenges, they should be OK
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to marshal challenge"), err)
		return
	}
}

// Registration is used by a client to submit an update to their registration.
func (wfe *WebFrontEndImpl) Registration(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {

	body, _, currReg, prob := wfe.verifyPOST(ctx, logEvent, request, true, core.ResourceRegistration)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		// verifyPOST handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	// Requests to this handler should have a path that leads to a known
	// registration
	idStr := request.URL.Path
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Registration ID must be an integer"), err)
		return
	} else if id <= 0 {
		msg := fmt.Sprintf("Registration ID must be a positive non-zero integer, was %d", id)
		wfe.sendError(response, logEvent, probs.Malformed(msg), nil)
		return
	} else if id != currReg.ID {
		wfe.sendError(response, logEvent, probs.Unauthorized("Request signing key did not match registration key"), nil)
		return
	}

	var update core.Registration
	err = json.Unmarshal(body, &update)
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling registration"), err)
		return
	}

	// People *will* POST their full registrations to this endpoint, including
	// the 'valid' status, to avoid always failing out when that happens only
	// attempt to deactivate if the provided status is different from their current
	// status.
	//
	// If a user tries to send both a deactivation request and an update to their
	// contacts or subscriber agreement URL the deactivation will take place and
	// return before an update would be performed.
	if update.Status != "" && update.Status != currReg.Status {
		if update.Status != core.StatusDeactivated {
			wfe.sendError(response, logEvent, probs.Malformed("Invalid value provided for status field"), nil)
			return
		}
		wfe.deactivateRegistration(ctx, currReg, response, request, logEvent)
		return
	}

	// If a user POSTs their registration object including a previously valid
	// agreement URL but that URL has since changed we will fail out here
	// since the update agreement URL doesn't match the current URL. To fix that we
	// only fail if the sent URL doesn't match the currently valid agreement URL
	// and it doesn't match the URL currently stored in the registration
	// in the database. The RA understands the user isn't actually trying to
	// update the agreement but since we do an early check here in order to prevent
	// extraneous requests to the RA we have to add this bypass.
	if len(update.Agreement) > 0 && update.Agreement != currReg.Agreement &&
		update.Agreement != wfe.SubscriberAgreementURL {
		problem := probs.Malformed("Provided agreement URL [%s] does not match current agreement URL [%s]", update.Agreement, wfe.SubscriberAgreementURL)
		wfe.sendError(response, logEvent, problem, nil)
		return
	}

	// Registration objects contain a JWK object which are merged in UpdateRegistration
	// if it is different from the existing registration key. Since this isn't how you
	// update the key we just copy the existing one into the update object here. This
	// ensures the key isn't changed and that we can cleanly serialize the update as
	// JSON to send via RPC to the RA.
	update.Key = currReg.Key

	updatedReg, err := wfe.RA.UpdateRegistration(ctx, currReg, update)
	if err != nil {
		wfe.sendError(response, logEvent, web.ProblemDetailsForError(err, "Unable to update registration"), err)
		return
	}

	response.Header().Add("Link", link(web.RelativeEndpoint(request, newAuthzPath), "next"))
	if len(wfe.SubscriberAgreementURL) > 0 {
		response.Header().Add("Link", link(wfe.SubscriberAgreementURL, "terms-of-service"))
	}

	err = wfe.writeJsonResponse(response, logEvent, http.StatusAccepted, updatedReg)
	if err != nil {
		// ServerInternal because we just generated the reg, it should be OK
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to marshal registration"), err)
		return
	}
}

func (wfe *WebFrontEndImpl) deactivateAuthorization(ctx context.Context, authz *core.Authorization, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) bool {
	body, _, reg, prob := wfe.verifyPOST(ctx, logEvent, request, true, core.ResourceAuthz)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		wfe.sendError(response, logEvent, prob, nil)
		return false
	}
	if reg.ID != authz.RegistrationID {
		wfe.sendError(response, logEvent, probs.Unauthorized("Registration ID doesn't match ID for authorization"), nil)
		return false
	}
	var req struct {
		Status core.AcmeStatus
	}
	err := json.Unmarshal(body, &req)
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling JSON"), err)
		return false
	}
	if req.Status != core.StatusDeactivated {
		wfe.sendError(response, logEvent, probs.Malformed("Invalid status value"), err)
		return false
	}
	err = wfe.RA.DeactivateAuthorization(ctx, *authz)
	if err != nil {
		wfe.sendError(response, logEvent, web.ProblemDetailsForError(err, "Error deactivating authorization"), err)
		return false
	}
	// Since the authorization passed to DeactivateAuthorization isn't
	// mutated locally by the function we must manually set the status
	// here before displaying the authorization to the user
	authz.Status = core.StatusDeactivated
	return true
}

// Authorization is used by clients to submit an update to one of their
// authorizations.
func (wfe *WebFrontEndImpl) Authorization(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	// Requests to this handler should have a path that leads to a known authz
	id := request.URL.Path
	var authz core.Authorization
	var err error
	if features.Enabled(features.NewAuthorizationSchema) && strings.HasPrefix(id, authz2Prefix) {
		authzID, err := strconv.ParseInt(strings.TrimPrefix(id, authz2Prefix+"/"), 10, 64)
		if err != nil {
			wfe.sendError(response, logEvent, probs.NotFound("No such authorization"), nil)
			return
		}
		authzPB, err := wfe.SA.GetAuthorization2(ctx, &sapb.AuthorizationID2{Id: &authzID})
		if err != nil {
			if berrors.Is(err, berrors.NotFound) {
				wfe.sendError(response, logEvent, probs.NotFound("No such authorization"), nil)
			} else {
				wfe.sendError(response, logEvent, probs.ServerInternal("Problem getting authorization"), err)
			}
			return
		}
		authz, err = bgrpc.PBToAuthz(authzPB)
		if err != nil {
			wfe.sendError(response, logEvent, probs.ServerInternal("Problem getting authorization"), err)
			return
		}
	} else {
		authz, err = wfe.SA.GetAuthorization(ctx, id)
		if err != nil {
			if berrors.Is(err, berrors.NotFound) {
				wfe.sendError(response, logEvent, probs.NotFound("No such authorization"), nil)
			} else {
				wfe.sendError(response, logEvent, probs.ServerInternal("Problem getting authorization"), err)
			}
			return
		}
	}

	if authz.Identifier.Type == identifier.DNS {
		logEvent.DNSName = authz.Identifier.Value
	}
	logEvent.Status = string(authz.Status)

	// After expiring, authorizations are inaccessible
	if authz.Expires == nil || authz.Expires.Before(wfe.clk.Now()) {
		wfe.sendError(response, logEvent, probs.NotFound("Expired authorization"), nil)
		return
	}

	if wfe.AllowAuthzDeactivation && request.Method == "POST" {
		// If the deactivation fails return early as errors and return codes
		// have already been set. Otherwise continue so that the user gets
		// sent the deactivated authorization.
		if !wfe.deactivateAuthorization(ctx, &authz, logEvent, response, request) {
			return
		}
	}

	wfe.prepAuthorizationForDisplay(request, &authz)

	response.Header().Add("Link", link(web.RelativeEndpoint(request, newCertPath), "next"))

	err = wfe.writeJsonResponse(response, logEvent, http.StatusOK, authz)
	if err != nil {
		// InternalServerError because this is a failure to decode from our DB.
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to JSON marshal authz"), err)
		return
	}
}

var allHex = regexp.MustCompile("^[0-9a-f]+$")

// Certificate is used by clients to request a copy of their current certificate, or to
// request a reissuance of the certificate.
func (wfe *WebFrontEndImpl) Certificate(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {

	serial := request.URL.Path
	// Certificate paths consist of the CertBase path, plus exactly sixteen hex
	// digits.
	if !core.ValidSerial(serial) {
		wfe.sendError(response, logEvent, probs.NotFound("Certificate not found"), nil)
		return
	}
	logEvent.Extra["RequestedSerial"] = serial

	cert, err := wfe.SA.GetCertificate(ctx, serial)
	// TODO(#991): handle db errors
	if err != nil {
		ierr := fmt.Errorf("unable to get certificate by serial id %#v: %s", serial, err)
		if strings.HasPrefix(err.Error(), "gorp: multiple rows returned") {
			wfe.sendError(response, logEvent, probs.Conflict("Multiple certificates with same short serial"), ierr)
		} else {
			wfe.sendError(response, logEvent, probs.NotFound("Certificate not found"), ierr)
		}
		return
	}

	// TODO Content negotiation
	response.Header().Set("Content-Type", "application/pkix-cert")
	relativeIssuerPath := web.RelativeEndpoint(request, issuerPath)
	response.Header().Add("Link", link(relativeIssuerPath, "up"))
	response.WriteHeader(http.StatusOK)
	if _, err = response.Write(cert.DER); err != nil {
		wfe.log.Warningf("Could not write response: %s", err)
	}
	return
}

// Terms is used by the client to obtain the current Terms of Service /
// Subscriber Agreement to which the subscriber must agree.
func (wfe *WebFrontEndImpl) Terms(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	http.Redirect(response, request, wfe.SubscriberAgreementURL, http.StatusFound)
}

// Issuer obtains the issuer certificate used by this instance of Boulder.
func (wfe *WebFrontEndImpl) Issuer(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	// TODO Content negotiation
	response.Header().Set("Content-Type", "application/pkix-cert")
	response.WriteHeader(http.StatusOK)
	if _, err := response.Write(wfe.IssuerCert); err != nil {
		wfe.log.Warningf("Could not write response: %s", err)
	}
}

// BuildID tells the requestor what build we're running.
func (wfe *WebFrontEndImpl) BuildID(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "text/plain")
	response.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprintf(response, "Boulder=(%s %s)\n", core.GetBuildID(), core.GetBuildTime()); err != nil {
		wfe.log.Warningf("Could not write response: %s", err)
	}
}

// Options responds to an HTTP OPTIONS request.
func (wfe *WebFrontEndImpl) Options(response http.ResponseWriter, request *http.Request, methodsStr string, methodsMap map[string]bool) {
	// Every OPTIONS request gets an Allow header with a list of supported methods.
	response.Header().Set("Allow", methodsStr)

	// CORS preflight requests get additional headers. See
	// http://www.w3.org/TR/cors/#resource-preflight-requests
	reqMethod := request.Header.Get("Access-Control-Request-Method")
	if reqMethod == "" {
		reqMethod = "GET"
	}
	if methodsMap[reqMethod] {
		wfe.setCORSHeaders(response, request, methodsStr)
	}
}

// setCORSHeaders() tells the client that CORS is acceptable for this
// request. If allowMethods == "" the request is assumed to be a CORS
// actual request and no Access-Control-Allow-Methods header will be
// sent.
func (wfe *WebFrontEndImpl) setCORSHeaders(response http.ResponseWriter, request *http.Request, allowMethods string) {
	reqOrigin := request.Header.Get("Origin")
	if reqOrigin == "" {
		// This is not a CORS request.
		return
	}

	// Allow CORS if the current origin (or "*") is listed as an
	// allowed origin in config. Otherwise, disallow by returning
	// without setting any CORS headers.
	allow := false
	for _, ao := range wfe.AllowOrigins {
		if ao == "*" {
			response.Header().Set("Access-Control-Allow-Origin", "*")
			allow = true
			break
		} else if ao == reqOrigin {
			response.Header().Set("Vary", "Origin")
			response.Header().Set("Access-Control-Allow-Origin", ao)
			allow = true
			break
		}
	}
	if !allow {
		return
	}

	if allowMethods != "" {
		// For an OPTIONS request: allow all methods handled at this URL.
		response.Header().Set("Access-Control-Allow-Methods", allowMethods)
	}
	response.Header().Set("Access-Control-Expose-Headers", "Link, Replay-Nonce")
	response.Header().Set("Access-Control-Max-Age", "86400")
}

// KeyRollover allows a user to change their signing key
func (wfe *WebFrontEndImpl) KeyRollover(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	body, _, reg, prob := wfe.verifyPOST(ctx, logEvent, request, true, core.ResourceKeyChange)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	// Parse as JWS
	newKey, parsedJWS, err := wfe.extractJWSKey(string(body))
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed(err.Error()), err)
		return
	}
	payload, err := parsedJWS.Verify(newKey)
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("JWS verification error"), err)
		return
	}
	var rolloverRequest struct {
		NewKey  jose.JSONWebKey
		Account string
	}
	err = json.Unmarshal(payload, &rolloverRequest)
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Request payload did not parse as JSON"), nil)
		return
	}

	if web.RelativeEndpoint(request, fmt.Sprintf("%s%d", regPath, reg.ID)) != rolloverRequest.Account {
		wfe.sendError(response, logEvent, probs.Malformed("Incorrect account URL provided in payload"), nil)
		return
	}

	keysEqual, err := core.PublicKeysEqual(rolloverRequest.NewKey.Key, newKey.Key)
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Unable to marshal new JWK"), nil)
		return
	}
	if !keysEqual {
		wfe.sendError(response, logEvent, probs.Malformed("New JWK in inner payload doesn't match key used to sign inner JWS"), nil)
		return
	}

	// Update registration key
	updatedReg, err := wfe.RA.UpdateRegistration(ctx, reg, core.Registration{Key: newKey})
	if err != nil {
		wfe.sendError(response, logEvent, web.ProblemDetailsForError(err, "Unable to update registration"), err)
		return
	}

	jsonReply, err := marshalIndent(updatedReg)
	if err != nil {
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to marshal registration"), err)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	response.Write(jsonReply)
}

func (wfe *WebFrontEndImpl) deactivateRegistration(ctx context.Context, reg core.Registration, response http.ResponseWriter, request *http.Request, logEvent *web.RequestEvent) {
	err := wfe.RA.DeactivateRegistration(ctx, reg)
	if err != nil {
		wfe.sendError(response, logEvent, web.ProblemDetailsForError(err, "Error deactivating registration"), err)
		return
	}
	reg.Status = core.StatusDeactivated

	err = wfe.writeJsonResponse(response, logEvent, http.StatusOK, reg)
	if err != nil {
		// ServerInternal because registration is from DB and should be fine
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to marshal registration"), err)
		return
	}
}

// addIssuingCertificateURLs() adds Issuing Certificate URLs (AIA) from a
// X.509 certificate to the HTTP response. If the IssuingCertificateURL
// in a certificate is not https://, it will be upgraded to https://
func (wfe *WebFrontEndImpl) addIssuingCertificateURLs(response http.ResponseWriter, issuingCertificateURL []string) error {
	for _, rawURL := range issuingCertificateURL {
		parsedURI, err := url.ParseRequestURI(rawURL)
		if err != nil {
			return err
		}
		parsedURI.Scheme = "https"
		response.Header().Add("Link", link(parsedURI.String(), "up"))
	}
	return nil
}

func urlForAuthz(authz core.Authorization, request *http.Request) string {
	if authz.V2 {
		return web.RelativeEndpoint(request, fmt.Sprintf("%s%s/%s", authzPath, authz2Prefix, authz.ID))
	}
	return web.RelativeEndpoint(request, authzPath+string(authz.ID))
}
