package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"net/http"
	"sync"
	"sync/atomic"
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

	throughput int64
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

var termsURL = "http://127.0.0.1:4001/terms/v1"

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

	resp, err := s.post(fmt.Sprintf("%s/acme/new-reg", s.apiBase), requestPayload)
	if err != nil {
		fmt.Printf("[FAILED] new-reg: %s\n", err)
		return
	}
	if resp.StatusCode != 201 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// just fail
			return
		}
		fmt.Printf("[FAILED] new-reg: %s\n", string(body))
		return
	}

	// agree to terms
	regStr = fmt.Sprintf(`{"resource":"reg","agreement":"%s"}`, termsURL)

	// build the JWS object
	payload = []byte(regStr)
	// send a POST request
	nonce, err = s.getNonce()
	if err != nil {
		fmt.Println(err)
		return
	}
	jws, err = signer.Sign(payload, nonce)
	if err != nil {
		fmt.Println(err)
		return
	}
	// into JSON
	requestPayload, _ = json.Marshal(jws)

	resp, err = s.post(resp.Header.Get("Location"), requestPayload)
	if err != nil {
		fmt.Printf("[FAILED] reg: %s\n", err)
		return
	}
	if resp.StatusCode != 202 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// just fail
			return
		}
		fmt.Printf("[FAILED] reg: %s\n", string(body))
		return
	}

	s.addReg(&registration{key: signKey, iMu: new(sync.RWMutex)})
}

var dnsLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func (s *state) newAuthorization(reg *registration) {
	// generate a random domain name (should come up with some fun names... THE NEXT GOOGLE PERHAPS?)
	var buff bytes.Buffer
	mrand.Seed(time.Now().UnixNano())
	randLen := mrand.Intn(61-3) + 1
	for i := 0; i < randLen; i++ {
		buff.WriteByte(dnsLetters[mrand.Intn(len(dnsLetters))])
	}
	randomDomain := fmt.Sprintf("%s.com", buff.String())

	// create the registration object
	initAuth := fmt.Sprintf(`{"resource":"new-authz","identifier":{"type":"dns","value":"%s"}}`, randomDomain)

	// build the JWS object
	payload := []byte(initAuth)
	signer, err := jose.NewSigner(jose.RS256, reg.key)
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
	resp, err := s.post(fmt.Sprintf("%s/acme/new-authz", s.apiBase), requestPayload)
	if err != nil {
		fmt.Printf("[FAILED] new-authz: %s\n", err)
		return
	}
	if resp.StatusCode != 201 {
		// something
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// just fail
			return
		}
		fmt.Printf("[FAILED] new-authz: %s\n", string(body))
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// just fail
		return
	}

	var authz core.Authorization
	err = json.Unmarshal(body, authz)
	if err != nil {
		fmt.Println(err)
		return
	}

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

	if len(actions) > 0 {
		actions[mrand.Intn(len(actions))](reg)
	} else {
		fmt.Println("wat")
	}
}

func main() {
	s := state{
		rMu:        new(sync.RWMutex),
		nMu:        new(sync.Mutex),
		client:     new(http.Client),
		apiBase:    "http://localhost:4000",
		throughput: 5,
		maxRegs:    250,
	}
	for {
		go s.sendCall()
		time.Sleep(time.Duration(time.Second.Nanoseconds() / atomic.LoadInt64(&s.throughput)))
	}
	// s.newRegistration(nil)
	// reg, found := s.getReg()
	// if found {
	// 	s.newAuthorization(reg)
	// }
}
