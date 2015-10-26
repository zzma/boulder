package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	"github.com/letsencrypt/boulder/cmd"

	"github.com/letsencrypt/boulder/core"
)

type registration struct {
	key   *rsa.PrivateKey
	iMu   *sync.RWMutex
	auths []core.Authorization
	certs [][]byte
}

type state struct {
	rMu     *sync.RWMutex
	regs    []*registration
	maxRegs int
	client  *http.Client
	apiBase string

	nMu       *sync.Mutex
	noncePool []string

	throughput int64

	hoMu              *sync.RWMutex
	httpOneChallenges map[string]string

	certKey *rsa.PrivateKey
}

func (s *state) signWithNonce(payload []byte, signer jose.Signer) ([]byte, error) {
	nonce, err := s.getNonce()
	if err != nil {
		return nil, err
	}
	jws, err := signer.Sign(payload, nonce)
	if err != nil {
		return nil, err
	}
	// into JSON
	return json.Marshal(jws)
}

func (s *state) post(endpoint string, payload []byte) (*http.Response, error) {
	resp, err := s.client.Post(
		endpoint,
		"application/json",
		bytes.NewBuffer(payload),
	)
	if resp != nil {
		if newNonce := resp.Header.Get("Replay-Nonce"); newNonce != "" {
			s.addNonce(newNonce)
		}
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *state) getNonce() (string, error) {
	s.nMu.Lock()
	defer s.nMu.Unlock()
	if len(s.noncePool) == 0 {
		resp, err := s.client.Head(fmt.Sprintf("%s/directory", s.apiBase))
		if err != nil {
			return "", err
		}
		if nonce := resp.Header.Get("Replay-Nonce"); nonce != "" {
			return nonce, nil
		}
		return "", fmt.Errorf("Nonce header not supplied!")
	}
	nonce := s.noncePool[0]
	s.noncePool = s.noncePool[1:]
	return nonce, nil
}

func (s *state) addNonce(nonce string) {
	s.nMu.Lock()
	defer s.nMu.Unlock()
	s.noncePool = append(s.noncePool, nonce)
}

func (s *state) addReg(reg *registration) {
	s.rMu.Lock()
	defer s.rMu.Unlock()
	s.regs = append(s.regs, reg)
}

func (s *state) getRandReg() (*registration, bool) {
	regsLength := len(s.regs)
	if regsLength == 0 {
		return nil, false
	}
	return s.regs[mrand.Intn(regsLength)], true
}

func (s *state) getReg() (*registration, bool) {
	s.rMu.RLock()
	defer s.rMu.RUnlock()
	return s.getRandReg()
}

func (s *state) sendCall() {
	actions := []func(*registration){}
	s.rMu.RLock()
	if len(s.regs) < s.maxRegs || s.maxRegs == 0 {
		actions = append(actions, s.newRegistration)
	}
	s.rMu.RUnlock()

	reg, found := s.getReg()
	if found {
		fmt.Printf("reg: auths %d -- certs %d\n", len(reg.auths), len(reg.certs))
		actions = append(actions, s.newAuthorization)
		reg.iMu.RLock()
		if len(reg.auths) > 0 {
			actions = append(actions, s.newCertificate)
		}
		if len(reg.certs) > 0 {
			actions = append(actions, s.revokeCertificate)
		}
		reg.iMu.RUnlock()
	}

	if len(actions) > 0 {
		actions[mrand.Intn(len(actions))](reg)
	} else {
		fmt.Println("wat")
	}
}

func main() {
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	cmd.FailOnError(err, "Failed to generate certificate key")
	s := state{
		rMu:               new(sync.RWMutex),
		nMu:               new(sync.Mutex),
		hoMu:              new(sync.RWMutex),
		httpOneChallenges: make(map[string]string),
		client:            new(http.Client),
		apiBase:           "http://localhost:4000",
		throughput:        5,
		maxRegs:           250,
		certKey:           certKey,
	}
	go s.httpOneServer()

	for {
		go s.sendCall()
		time.Sleep(time.Duration(time.Second.Nanoseconds() / atomic.LoadInt64(&s.throughput)))
	}

	// s.newRegistration(nil)
	// reg, found := s.getReg()
	// if found {
	// 	s.newAuthorization(reg)
	// 	s.newCertificate(reg)
	// 	forever := make(chan bool)
	// 	<-forever
	// }
}
