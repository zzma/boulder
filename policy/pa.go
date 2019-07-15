package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"

	"github.com/zzma/boulder/core"
	berrors "github.com/zzma/boulder/errors"
	"github.com/zzma/boulder/features"
	"github.com/zzma/boulder/iana"
	"github.com/zzma/boulder/identifier"
	blog "github.com/zzma/boulder/log"
	"github.com/zzma/boulder/reloader"
	"gopkg.in/yaml.v2"
)

// AuthorityImpl enforces CA policy decisions.
type AuthorityImpl struct {
	log blog.Logger

	blocklist              map[string]bool
	exactBlocklist         map[string]bool
	wildcardExactBlocklist map[string]bool
	blocklistMu            sync.RWMutex

	enabledChallenges map[string]bool
	pseudoRNG         *rand.Rand
	rngMu             sync.Mutex
}

// New constructs a Policy Authority.
func New(challengeTypes map[string]bool) (*AuthorityImpl, error) {

	pa := AuthorityImpl{
		log:               blog.Get(),
		enabledChallenges: challengeTypes,
		// We don't need real randomness for this.
		pseudoRNG: rand.New(rand.NewSource(99)),
	}

	return &pa, nil
}

// blockedNamesPolicy is a struct holding lists of blocked domain names. One for
// exact blocks and one for blocks including all subdomains.
type blockedNamesPolicy struct {
	// ExactBlockedNames is a list of domain names. Issuance for names exactly
	// matching an entry in the list will be forbidden. (e.g. `ExactBlockedNames`
	// containing `www.example.com` will not block `example.com` or
	// `mail.example.com`).
	ExactBlockedNames []string `yaml:"ExactBlockedNames"`
	// HighRiskBlockedNames is like ExactBlockedNames except that issuance is
	// blocked for subdomains as well. (e.g. BlockedNames containing `example.com`
	// will block `www.example.com`).
	//
	// This list typically doesn't change with much regularity.
	HighRiskBlockedNames []string `yaml:"HighRiskBlockedNames"`

	// AdminBlockedNames operates the same as BlockedNames but is changed with more
	// frequency based on administrative blocks/revocations that are added over
	// time above and beyond the high-risk domains. Managing these entries separately
	// from HighRiskBlockedNames makes it easier to vet changes accurately.
	AdminBlockedNames []string `yaml:"AdminBlockedNames"`
}

// SetHostnamePolicyFile will load the given policy file, returning error if it
// fails. It will also start a reloader in case the file changes
func (pa *AuthorityImpl) SetHostnamePolicyFile(f string) error {
	if _, err := reloader.New(f, pa.loadHostnamePolicy, pa.hostnamePolicyLoadError); err != nil {
		return err
	}
	return nil
}

func (pa *AuthorityImpl) hostnamePolicyLoadError(err error) {
	pa.log.AuditErrf("error loading hostname policy: %s", err)
}

// loadHostnamePolicy is a callback suitable for use with reloader.New() that
// will unmarshal a YAML hostname policy.
func (pa *AuthorityImpl) loadHostnamePolicy(contents []byte) error {
	hash := sha256.Sum256(contents)
	pa.log.Infof("loading hostname policy, sha256: %s", hex.EncodeToString(hash[:]))
	var policy blockedNamesPolicy
	err := yaml.Unmarshal(contents, &policy)
	if err != nil {
		return err
	}
	if len(policy.HighRiskBlockedNames) == 0 {
		return fmt.Errorf("No entries in HighRiskBlockedNames.")
	}
	if len(policy.ExactBlockedNames) == 0 {
		return fmt.Errorf("No entries in ExactBlockedNames.")
	}
	return pa.processHostnamePolicy(policy)
}

// processHostnamePolicy handles loading a new blockedNamesPolicy into the PA.
// All of the policy.ExactBlockedNames will be added to the
// wildcardExactBlocklist by processHostnamePolicy to ensure that wildcards for
// exact blocked names entries are forbidden.
func (pa *AuthorityImpl) processHostnamePolicy(policy blockedNamesPolicy) error {
	nameMap := make(map[string]bool)
	for _, v := range policy.HighRiskBlockedNames {
		nameMap[v] = true
	}
	for _, v := range policy.AdminBlockedNames {
		nameMap[v] = true
	}
	exactNameMap := make(map[string]bool)
	wildcardNameMap := make(map[string]bool)
	for _, v := range policy.ExactBlockedNames {
		exactNameMap[v] = true
		// Remove the leftmost label of the exact blocked names entry to make an exact
		// wildcard block list entry that will prevent issuing a wildcard that would
		// include the exact blocklist entry. e.g. if "highvalue.example.com" is on
		// the exact blocklist we want "example.com" to be in the
		// wildcardExactBlocklist so that "*.example.com" cannot be issued.
		//
		// First, split the domain into two parts: the first label and the rest of the domain.
		parts := strings.SplitN(v, ".", 2)
		// if there are less than 2 parts then this entry is malformed! There should
		// at least be a "something." and a TLD like "com"
		if len(parts) < 2 {
			return fmt.Errorf(
				"Malformed ExactBlockedNames entry, only one label: %q", v)
		}
		// Add the second part, the domain minus the first label, to the
		// wildcardNameMap to block issuance for `*.`+parts[1]
		wildcardNameMap[parts[1]] = true
	}
	pa.blocklistMu.Lock()
	pa.blocklist = nameMap
	pa.exactBlocklist = exactNameMap
	pa.wildcardExactBlocklist = wildcardNameMap
	pa.blocklistMu.Unlock()
	return nil
}

const (
	maxLabels = 10

	// RFC 1034 says DNS labels have a max of 63 octets, and names have a max of 255
	// octets: https://tools.ietf.org/html/rfc1035#page-10. Since two of those octets
	// are taken up by the leading length byte and the trailing root period the actual
	// max length becomes 253.
	// TODO(#3237): Right now our schema for the authz table only allows 255 characters
	// for identifiers, including JSON wrapping, which takes up 25 characters. For
	// now, we only allow identifiers up to 230 characters in length. When we are
	// able to do a migration to update this table, we can allow DNS names up to
	// 253 characters in length.
	maxLabelLength         = 63
	maxDNSIdentifierLength = 230
)

var dnsLabelRegexp = regexp.MustCompile("^[a-z0-9][a-z0-9-]{0,62}$")
var punycodeRegexp = regexp.MustCompile("^xn--")
var idnReservedRegexp = regexp.MustCompile("^[a-z0-9]{2}--")

func isDNSCharacter(ch byte) bool {
	return ('a' <= ch && ch <= 'z') ||
		('A' <= ch && ch <= 'Z') ||
		('0' <= ch && ch <= '9') ||
		ch == '.' || ch == '-'
}

var (
	errInvalidIdentifier    = berrors.MalformedError("Invalid identifier type")
	errNonPublic            = berrors.MalformedError("Name does not end in a public suffix")
	errICANNTLD             = berrors.MalformedError("Name is an ICANN TLD")
	errPolicyForbidden      = berrors.RejectedIdentifierError("Policy forbids issuing for name")
	errInvalidDNSCharacter  = berrors.MalformedError("Invalid character in DNS name")
	errNameTooLong          = berrors.MalformedError("DNS name too long")
	errIPAddress            = berrors.MalformedError("Issuance for IP addresses not supported")
	errTooManyLabels        = berrors.MalformedError("DNS name has too many labels")
	errEmptyName            = berrors.MalformedError("DNS name was empty")
	errNameEndsInDot        = berrors.MalformedError("DNS name ends in a period")
	errTooFewLabels         = berrors.MalformedError("DNS name does not have enough labels")
	errLabelTooShort        = berrors.MalformedError("DNS label is too short")
	errLabelTooLong         = berrors.MalformedError("DNS label is too long")
	errMalformedIDN         = berrors.MalformedError("DNS label contains malformed punycode")
	errInvalidRLDH          = berrors.RejectedIdentifierError("DNS name contains a R-LDH label")
	errTooManyWildcards     = berrors.MalformedError("DNS name had more than one wildcard")
	errMalformedWildcard    = berrors.MalformedError("DNS name had a malformed wildcard label")
	errICANNTLDWildcard     = berrors.MalformedError("DNS name was a wildcard for an ICANN TLD")
	errWildcardNotSupported = berrors.MalformedError("Wildcard names not supported")
)

// WillingToIssue determines whether the CA is willing to issue for the provided
// identifier. It expects domains in id to be lowercase to prevent mismatched
// cases breaking queries.
//
// We place several criteria on identifiers we are willing to issue for:
//
//  * MUST self-identify as DNS identifiers
//  * MUST contain only bytes in the DNS hostname character set
//  * MUST NOT have more than maxLabels labels
//  * MUST follow the DNS hostname syntax rules in RFC 1035 and RFC 2181
//    In particular:
//    * MUST NOT contain underscores
//  * MUST NOT match the syntax of an IP address
//  * MUST end in a public suffix
//  * MUST have at least one label in addition to the public suffix
//  * MUST NOT be a label-wise suffix match for a name on the block list,
//    where comparison is case-independent (normalized to lower case)
//
// If WillingToIssue returns an error, it will be of type MalformedRequestError
// or RejectedIdentifierError
func (pa *AuthorityImpl) WillingToIssue(id identifier.ACMEIdentifier) error {
	if id.Type != identifier.DNS {
		return errInvalidIdentifier
	}
	domain := id.Value

	if domain == "" {
		return errEmptyName
	}

	if strings.HasPrefix(domain, "*.") {
		return errWildcardNotSupported
	}

	for _, ch := range []byte(domain) {
		if !isDNSCharacter(ch) {
			return errInvalidDNSCharacter
		}
	}

	if len(domain) > maxDNSIdentifierLength {
		return errNameTooLong
	}

	if ip := net.ParseIP(domain); ip != nil {
		return errIPAddress
	}

	if strings.HasSuffix(domain, ".") {
		return errNameEndsInDot
	}

	labels := strings.Split(domain, ".")
	if len(labels) > maxLabels {
		return errTooManyLabels
	}
	if len(labels) < 2 {
		return errTooFewLabels
	}
	for _, label := range labels {
		if len(label) < 1 {
			return errLabelTooShort
		}
		if len(label) > maxLabelLength {
			return errLabelTooLong
		}

		if !dnsLabelRegexp.MatchString(label) {
			return errInvalidDNSCharacter
		}

		if label[len(label)-1] == '-' {
			return errInvalidDNSCharacter
		}

		if punycodeRegexp.MatchString(label) {
			// We don't care about script usage, if a name is resolvable it was
			// registered with a higher power and they should be enforcing their
			// own policy. As long as it was properly encoded that is enough
			// for us.
			ulabel, err := idna.ToUnicode(label)
			if err != nil {
				return errMalformedIDN
			}
			if !norm.NFC.IsNormalString(ulabel) {
				return errMalformedIDN
			}
		} else if idnReservedRegexp.MatchString(label) {
			return errInvalidRLDH
		}
	}

	// Names must end in an ICANN TLD, but they must not be equal to an ICANN TLD.
	icannTLD, err := iana.ExtractSuffix(domain)
	if err != nil {
		return errNonPublic
	}
	if icannTLD == domain {
		return errICANNTLD
	}

	// Require no match against hostname block lists
	if err := pa.checkHostLists(domain); err != nil {
		return err
	}

	return nil
}

// WillingToIssueWildcards is an extension of WillingToIssue that accepts DNS
// identifiers for well formed wildcard domains in addition to regular
// identifiers.
//
// All provided identifiers are run through WillingToIssue and any errors are
// returned. In addition to the regular WillingToIssue checks this function
// also checks each wildcard identifier to enforce that:
//
// * The identifer is a DNS type identifier
// * There is at most one `*` wildcard character
// * That the wildcard character is the leftmost label
// * That the wildcard label is not immediately adjacent to a top level ICANN
//   TLD
// * That the wildcard wouldn't cover an exact blocklist entry (e.g. an exact
//   blocklist entry for "foo.example.com" should prevent issuance for
//   "*.example.com")
//
// If any of the identifiers are not valid then an error with suberrors specific
// to the rejected identifiers will be returned.
func (pa *AuthorityImpl) WillingToIssueWildcards(idents []identifier.ACMEIdentifier) error {
	var subErrors []berrors.SubBoulderError
	var firstBadIdent *identifier.ACMEIdentifier
	for _, ident := range idents {
		if err := pa.willingToIssueWildcard(ident); err != nil {
			if firstBadIdent == nil {
				firstBadIdent = &ident
			}
			if bErr, ok := err.(*berrors.BoulderError); ok {
				subErrors = append(subErrors, berrors.SubBoulderError{
					Identifier:   ident,
					BoulderError: bErr})
			} else {
				subErrors = append(subErrors, berrors.SubBoulderError{
					Identifier: ident,
					BoulderError: &berrors.BoulderError{
						Type:   berrors.RejectedIdentifier,
						Detail: err.Error(),
					}})
			}
		}
	}
	if len(subErrors) > 0 {
		// If there was only one error, then use it as the top level error that is
		// returned.
		if len(subErrors) == 1 {
			return berrors.RejectedIdentifierError(
				"Cannot issue for %q: %s",
				subErrors[0].Identifier.Value,
				subErrors[0].BoulderError.Detail,
			)
		}

		detail := fmt.Sprintf(
			"Cannot issue for %q: %s (and %d more problems. Refer to sub-problems for more information.)",
			firstBadIdent.Value,
			subErrors[0].BoulderError.Detail,
			len(subErrors)-1,
		)
		return (&berrors.BoulderError{
			Type:   berrors.RejectedIdentifier,
			Detail: detail,
		}).WithSubErrors(subErrors)
	}
	return nil
}

// willingToIssueWildcard vets a single identifier. It is used by
// the plural WillingToIssueWildcards when evaluating a list of identifiers.
func (pa *AuthorityImpl) willingToIssueWildcard(ident identifier.ACMEIdentifier) error {
	// We're only willing to process DNS identifiers
	if ident.Type != identifier.DNS {
		return errInvalidIdentifier
	}
	rawDomain := ident.Value

	// If there is more than one wildcard in the domain the ident is invalid
	if strings.Count(rawDomain, "*") > 1 {
		return errTooManyWildcards
	}

	// If there is exactly one wildcard in the domain we need to do some special
	// processing to ensure that it is a well formed wildcard request and to
	// translate the identifer to its base domain for use with WillingToIssue
	if strings.Count(rawDomain, "*") == 1 {
		// If the rawDomain has a wildcard character, but it isn't the first most
		// label of the domain name then the wildcard domain is malformed
		if !strings.HasPrefix(rawDomain, "*.") {
			return errMalformedWildcard
		}
		// The base domain is the wildcard request with the `*.` prefix removed
		baseDomain := strings.TrimPrefix(rawDomain, "*.")
		// Names must end in an ICANN TLD, but they must not be equal to an ICANN TLD.
		icannTLD, err := iana.ExtractSuffix(baseDomain)
		if err != nil {
			return errNonPublic
		}
		// Names must have a non-wildcard label immediately adjacent to the ICANN
		// TLD. No `*.com`!
		if baseDomain == icannTLD {
			return errICANNTLDWildcard
		}
		// The base domain can't be in the wildcard exact blocklist
		if err := pa.checkWildcardHostList(baseDomain); err != nil {
			return err
		}
		// Check that the PA is willing to issue for the base domain
		// Since the base domain without the "*." may trip the exact hostname policy
		// blocklist when the "*." is removed we replace it with a single "x"
		// character to differentiate "*.example.com" from "example.com" for the
		// exact hostname check.
		//
		// NOTE(@cpu): This is pretty hackish! Boulder issue #3323[0] describes
		// a better follow-up that we should land to replace this code.
		// [0] https://github.com/letsencrypt/boulder/issues/3323
		return pa.WillingToIssue(identifier.ACMEIdentifier{
			Type:  identifier.DNS,
			Value: "x." + baseDomain,
		})
	}

	return pa.WillingToIssue(ident)
}

// checkWildcardHostList checks the wildcardExactBlocklist for a given domain.
// If the domain is not present on the list nil is returned, otherwise
// errPolicyForbidden is returned.
func (pa *AuthorityImpl) checkWildcardHostList(domain string) error {
	pa.blocklistMu.RLock()
	defer pa.blocklistMu.RUnlock()

	if pa.blocklist == nil {
		return fmt.Errorf("Hostname policy not yet loaded.")
	}

	if pa.wildcardExactBlocklist[domain] {
		return errPolicyForbidden
	}

	return nil
}

func (pa *AuthorityImpl) checkHostLists(domain string) error {
	pa.blocklistMu.RLock()
	defer pa.blocklistMu.RUnlock()

	if pa.blocklist == nil {
		return fmt.Errorf("Hostname policy not yet loaded.")
	}

	labels := strings.Split(domain, ".")
	for i := range labels {
		joined := strings.Join(labels[i:], ".")
		if pa.blocklist[joined] {
			return errPolicyForbidden
		}
	}

	if pa.exactBlocklist[domain] {
		return errPolicyForbidden
	}
	return nil
}

// ChallengesFor makes a decision of what challenges are acceptable for
// the given identifier.
func (pa *AuthorityImpl) ChallengesFor(identifier identifier.ACMEIdentifier) ([]core.Challenge, error) {
	challenges := []core.Challenge{}

	// If we are using the new authorization storage schema we only use a single
	// token for all challenges rather than a unique token per challenge.
	var token string
	if features.Enabled(features.NewAuthorizationSchema) {
		token = core.NewToken()
	}

	// If the identifier is for a DNS wildcard name we only
	// provide a DNS-01 challenge as a matter of CA policy.
	if strings.HasPrefix(identifier.Value, "*.") {
		// We must have the DNS-01 challenge type enabled to create challenges for
		// a wildcard identifier per LE policy.
		if !pa.ChallengeTypeEnabled(core.ChallengeTypeDNS01) {
			return nil, fmt.Errorf(
				"Challenges requested for wildcard identifier but DNS-01 " +
					"challenge type is not enabled")
		}
		// Only provide a DNS-01-Wildcard challenge
		challenges = []core.Challenge{core.DNSChallenge01(token)}
	} else {
		// Otherwise we collect up challenges based on what is enabled.
		if pa.ChallengeTypeEnabled(core.ChallengeTypeHTTP01) {
			challenges = append(challenges, core.HTTPChallenge01(token))
		}

		if pa.ChallengeTypeEnabled(core.ChallengeTypeTLSALPN01) {
			challenges = append(challenges, core.TLSALPNChallenge01(token))
		}

		if pa.ChallengeTypeEnabled(core.ChallengeTypeDNS01) {
			challenges = append(challenges, core.DNSChallenge01(token))
		}
	}

	// We shuffle the challenges to prevent ACME clients from relying on the
	// specific order that boulder returns them in.
	shuffled := make([]core.Challenge, len(challenges))

	pa.rngMu.Lock()
	defer pa.rngMu.Unlock()
	for i, challIdx := range pa.pseudoRNG.Perm(len(challenges)) {
		shuffled[i] = challenges[challIdx]
	}

	return shuffled, nil
}

// ChallengeTypeEnabled returns whether the specified challenge type is enabled
func (pa *AuthorityImpl) ChallengeTypeEnabled(t string) bool {
	pa.blocklistMu.RLock()
	defer pa.blocklistMu.RUnlock()
	return pa.enabledChallenges[t]
}
