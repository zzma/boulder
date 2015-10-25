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
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"

	"github.com/letsencrypt/boulder/core"
)

type registration struct {
	key   *rsa.PrivateKey
	iMu   *sync.RWMutex
	auths []core.Authorization
	certs []core.Certificate
}

type state struct {
	rMu     *sync.RWMutex
	regs    []*registration
	maxRegs int
	client  *http.Client
	apiBase string

	nMu       *sync.Mutex
	noncePool []string
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
	s.noncePool = s.noncePool[0:]
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

func (s *state) getRegWithAuths() (*registration, bool) {
	s.rMu.RLock()
	defer s.rMu.RUnlock()
	for {
		element, exists := s.getRandReg()
		if !exists {
			return nil, exists
		}
		element.iMu.RLock()
		if len(element.auths) > 0 {
			element.iMu.Unlock()
			return element, exists
		}
		element.iMu.Unlock()
	}
}

func (s *state) getRegWithCerts() (*registration, bool) {
	s.rMu.RLock()
	defer s.rMu.RUnlock()
	for {
		element, exists := s.getRandReg()
		if !exists {
			return nil, exists
		}
		element.iMu.RLock()
		if len(element.certs) > 0 {
			element.iMu.Unlock()
			return element, exists
		}
		element.iMu.Unlock()
	}
}

func (s *state) newRegistration(_ *registration) {
	// create the registration object
	regStr := `{"resource":"new-reg","contact":[]}`

	signKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
		return
	}

	// build the JWS object
	payload := []byte(regStr)
	signer, err := jose.NewSigner(jose.RS256, signKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	// send a POST request
	nonce, err := s.getNonce()
	if err != nil {
		fmt.Println(err)
		return
	}
	jws, err := signer.Sign(payload, nonce)
	if err != nil {
		fmt.Println(err)
		return
	}
	// into JSON
	requestPayload, _ := json.Marshal(jws)

	resp, err := s.client.Post(
		fmt.Sprintf("%s/acme/new-reg", s.apiBase),
		"application/json",
		bytes.NewBuffer(requestPayload),
	)
	if err != nil {
		// something
		fmt.Println(err)
		return
	}
	if resp.StatusCode != 201 {
		// something
		fmt.Printf("%#v\n", resp)
		return
	}
	// add nonce to nonce pool!
	if newNonce := resp.Header.Get("Replay-Nonce"); newNonce != "" {
		s.addNonce(newNonce)
	}

	reg := registration{
		key: signKey,
	}
	s.addReg(&reg)
}

func (s *state) newAuthorization(reg *registration) {

}

func (s *state) newCertificate(reg *registration) {

}

func (s *state) revokeCertificate(reg *registration) {

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

	actions[mrand.Intn(len(actions)-1)](reg)
}

func main() {
	s := state{
		rMu:     new(sync.RWMutex),
		nMu:     new(sync.Mutex),
		client:  new(http.Client),
		apiBase: "http://localhost:4000",
	}
	for {
		go s.newRegistration(nil)
		time.Sleep(250 * time.Millisecond)
	}
}
