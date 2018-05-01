package challsrv

import (
	"fmt"
	"sync"
)

type ChallSrv struct {
	// httpOneAddr is the HTTP-01 challenge server bind address/port
	httpOneAddr string
	// hoMu is a RWMutex used to control concurrent updates to the HTTP-01
	// challenges in httpOne
	hoMu sync.RWMutex
	// httpOne is a map of token values to key authorizations used for HTTP-01
	// responses
	httpOne map[string]string

	// dnsOneAddr is the DNS-01 challenge server bind address/port
	dnsOneAddr string
	// dnsMu is a RWMutex used to control concurrent updates to the DNS-01
	// challenges in dnsOne
	dnsMu sync.RWMutex
	// dnsOne is a map of DNS host values to key authorizations used for DNS-01
	// responses
	dnsOne map[string][]string
}

type Config struct {
	// HTTPOneAddr is the HTTP-01 challenge server bind address/port
	HTTPOneAddr string
	// DNSOneAddr is the DNS-01 challenge server bind address/port
	DNSOneAddr string
}

func (c Config) validate() error {
	// There needs to be at least one challenge time with a bind address
	if c.HTTPOneAddr == "" && c.DNSOneAddr == "" {
		return fmt.Errorf("config specified empty HTTPOneAddr and DNSOneAddr values")
	}
	return nil
}

// New constructs and returns a new ChallSrv instance with the given Config.
func New(config Config) (*ChallSrv, error) {
	// Validate the provided configuration
	if err := config.validate(); err != nil {
		return nil, err
	}
	// Construct and return a challenge server
	return &ChallSrv{
		httpOne:     make(map[string]string),
		httpOneAddr: config.HTTPOneAddr,

		dnsOneAddr: config.DNSOneAddr,
		dnsOne:     make(map[string][]string),
	}, nil
}

// Run runs the challenge server on the configured address
func (s *ChallSrv) Run() {
	wg := new(sync.WaitGroup)

	if s.httpOneAddr != "" {
		wg.Add(1)
		s.httpOneServer(wg)
	}

	if s.dnsOneAddr != "" {
		wg.Add(1)
		s.dnsOneServer(wg)
	}

	wg.Wait()
}
