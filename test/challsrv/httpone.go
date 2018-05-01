package challsrv

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const wellKnownPath = "/.well-known/acme-challenge/"

func (s *ChallSrv) AddHTTPOneChallenge(token, content string) {
	s.hoMu.Lock()
	defer s.hoMu.Unlock()
	s.httpOne[token] = content
}

func (s *ChallSrv) DeleteHTTPOneChallenge(token string) {
	s.hoMu.Lock()
	defer s.hoMu.Unlock()
	if _, ok := s.httpOne[token]; ok {
		delete(s.httpOne, token)
	}
}

func (s *ChallSrv) GetHTTPOneChallenge(token string) (string, bool) {
	s.hoMu.RLock()
	defer s.hoMu.RUnlock()
	content, present := s.httpOne[token]
	return content, present
}

func (s *ChallSrv) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestPath := r.URL.Path
	if strings.HasPrefix(requestPath, wellKnownPath) {
		token := requestPath[len(wellKnownPath):]
		if auth, found := s.GetHTTPOneChallenge(token); found {
			fmt.Fprintf(w, "%s", auth)
		}
	}
}

func (s *ChallSrv) httpOneServer(wg *sync.WaitGroup) {
	fmt.Printf("Starting HTTP-01 challenge server on %s\n", s.httpOneAddr)
	srv := &http.Server{
		Addr:         s.httpOneAddr,
		Handler:      s,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	srv.SetKeepAlivesEnabled(false)
	wg.Done()
	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			log.Fatal(err)
		}
	}()
}
