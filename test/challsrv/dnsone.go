package challsrv

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func (s *ChallSrv) AddDNSOneChallenge(host, content string) {
	s.dnsMu.Lock()
	defer s.dnsMu.Unlock()
	s.dnsOne[host] = append(s.dnsOne[host], content)
}

func (s *ChallSrv) DeleteDNSOneChallenge(host string) {
	s.dnsMu.Lock()
	defer s.dnsMu.Unlock()
	if _, ok := s.dnsOne[host]; ok {
		delete(s.dnsOne, host)
	}
}

func (s *ChallSrv) GetDNSOneChallenge(host string) ([]string, bool) {
	s.dnsMu.RLock()
	defer s.dnsMu.RUnlock()
	content, present := s.dnsOne[host]
	return content, present
}

func (s *ChallSrv) dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	// Normally this test DNS server will return 127.0.0.1 for everything.
	// However, in some situations (for instance Docker), it's useful to return a
	// different hardcoded host. You can do so by setting the FAKE_DNS environment
	// variable.
	fakeDNS := os.Getenv("FAKE_DNS")
	if fakeDNS == "" {
		fakeDNS = "127.0.0.1"
	}
	for _, q := range r.Question {
		fmt.Printf("dns-srv: Query -- [%s] %s\n", q.Name, dns.TypeToString[q.Qtype])
		switch q.Qtype {
		case dns.TypeA:
			record := new(dns.A)
			record.Hdr = dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    0,
			}
			record.A = net.ParseIP(fakeDNS)

			m.Answer = append(m.Answer, record)
		case dns.TypeMX:
			record := new(dns.MX)
			record.Hdr = dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    0,
			}
			record.Mx = "mail." + q.Name
			record.Preference = 10

			m.Answer = append(m.Answer, record)
		case dns.TypeTXT:
			values, present := s.GetDNSOneChallenge(q.Name)
			if !present {
				continue
			}
			fmt.Printf("dns-srv: Returning %d TXT records: %#v\n", len(values), values)
			for _, name := range values {
				record := new(dns.TXT)
				record.Hdr = dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    0,
				}
				record.Txt = []string{name}
				m.Answer = append(m.Answer, record)
			}
		case dns.TypeCAA:
			if q.Name == "bad-caa-reserved.com." || q.Name == "good-caa-reserved.com." {
				record := new(dns.CAA)
				record.Hdr = dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeCAA,
					Class:  dns.ClassINET,
					Ttl:    0,
				}
				record.Tag = "issue"
				if q.Name == "bad-caa-reserved.com." {
					record.Value = "sad-hacker-ca.invalid"
				} else if q.Name == "good-caa-reserved.com." {
					record.Value = "happy-hacker-ca.invalid"
				}
				m.Answer = append(m.Answer, record)
			}
		}
	}

	auth := new(dns.SOA)
	auth.Hdr = dns.RR_Header{Name: "boulder.invalid.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 0}
	auth.Ns = "ns.boulder.invalid."
	auth.Mbox = "master.boulder.invalid."
	auth.Serial = 1
	auth.Refresh = 1
	auth.Retry = 1
	auth.Expire = 1
	auth.Minttl = 1
	m.Ns = append(m.Ns, auth)

	w.WriteMsg(m)
	return
}

func (srv *ChallSrv) dnsOneServer(wg *sync.WaitGroup) {
	fmt.Printf("Starting TCP and UDP DNS-01 challenge server on %s\n", srv.dnsOneAddr)
	dns.HandleFunc(".", srv.dnsHandler)

	type dnsServer interface {
		ListenAndServe() error
	}

	udpServer := dnsServer(&dns.Server{
		Addr:         srv.dnsOneAddr,
		Net:          "udp",
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	})
	tcpServer := dnsServer(&dns.Server{
		Addr:         srv.dnsOneAddr,
		Net:          "tcp",
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	})

	wg.Done()
	for _, s := range []dnsServer{udpServer, tcpServer} {
		go func(s dnsServer) {
			err := s.ListenAndServe()
			if err != nil {
				log.Fatal(err)
			}
		}(s)
	}
}
