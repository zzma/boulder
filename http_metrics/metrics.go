package main

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

type Stats struct {
	tracer                 httptrace.ClientTrace
	scope                  metrics.Scope
	getConnCount           prometheus.Counter
	gotConnCount           *prometheus.CounterVec
	dnsStartCount          prometheus.Counter
	dnsDoneCount           prometheus.Counter
	connectStartCount      prometheus.Counter
	connectDoneCount       *prometheus.CounterVec
	tlsHandshakeStartCount prometheus.Counter
	tlsHandshakeDoneCount  *prometheus.CounterVec
	wroteHeadersCount      prometheus.Counter
	wroteRequestCount      *prometheus.CounterVec
}

func New(scope metrics.Scope) *Stats {
	result := &Stats{
		scope: scope,

		getConnCount: prometheus.NewCounter(
			prometheus.CounterOpts{Name: "golang_http_get_connection",
				Help: "attempts to get an HTTP connection (pooled or otherwise)",
			}),
		gotConnCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "golang_http_got_connection",
				Help: "results of getting an HTTP connection",
			},
			[]string{"reused", "was_idle"},
		),
		dnsStartCount: prometheus.NewCounter(
			prometheus.CounterOpts{Name: "golang_http_dns_start",
				Help: "attempts to get an address from DNS for an HTTP request",
			}),
		dnsDoneCount: prometheus.NewCounter(
			prometheus.CounterOpts{Name: "golang_http_dns_done",
				Help: "completed attempts to get an address from DNS for an HTTP request",
			}),
		connectStartCount: prometheus.NewCounter(
			prometheus.CounterOpts{Name: "golang_http_connect_start",
				Help: "attempts to dial a new connection for an HTTP request",
			}),
		connectDoneCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "golang_http_connect_done",
				Help: "completed attempts to dial a new connection for an HTTP request",
			},
			[]string{"error"},
		),
		tlsHandshakeStartCount: prometheus.NewCounter(
			prometheus.CounterOpts{Name: "golang_http_tls_handshake_start",
				Help: "attempts to do a TLS handshake on an HTTP connection",
			}),
		tlsHandshakeDoneCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "golang_http_tls_handshake_done",
				Help: "completed attempts to do a TLS handshake on an HTTP connection",
			},
			[]string{"error"},
		),
		wroteHeadersCount: prometheus.NewCounter(
			prometheus.CounterOpts{Name: "golang_http_wrote_headers",
				Help: "times that an HTTP request wrote all its headers",
			}),
		wroteRequestCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "golang_http_wrote_request",
				Help: "times that an HTTP request wrote its body",
			},
			[]string{"error"},
		),
	}
	scope.MustRegister(result.getConnCount)
	scope.MustRegister(result.gotConnCount)
	scope.MustRegister(result.dnsStartCount)
	scope.MustRegister(result.dnsDoneCount)
	scope.MustRegister(result.connectStartCount)
	scope.MustRegister(result.connectDoneCount)
	scope.MustRegister(result.tlsHandshakeStartCount)
	scope.MustRegister(result.tlsHandshakeDoneCount)
	scope.MustRegister(result.wroteHeadersCount)
	scope.MustRegister(result.wroteRequestCount)

	result.tracer = httptrace.ClientTrace{
		GetConn:           result.getConn,
		GotConn:           result.gotConn,
		DNSStart:          result.dnsStart,
		DNSDone:           result.dnsDone,
		ConnectStart:      result.connectStart,
		ConnectDone:       result.connectDone,
		TLSHandshakeStart: result.tlsHandshakeStart,
		TLSHandshakeDone:  result.tlsHandshakeDone,
		WroteHeaders:      result.wroteHeaders,
		WroteRequest:      result.wroteRequest,
	}
	return result
}

func (s *Stats) getConn(_ string) {
	s.getConnCount.Inc()
}

func (s *Stats) gotConn(info httptrace.GotConnInfo) {
	s.gotConnCount.With(prometheus.Labels{
		"reused":   strconv.FormatBool(info.Reused),
		"was_idle": strconv.FormatBool(info.WasIdle),
	}).Inc()
}

func (s *Stats) dnsStart(_ httptrace.DNSStartInfo) {
	s.dnsStartCount.Inc()
}

func (s *Stats) dnsDone(_ httptrace.DNSDoneInfo) {
	s.dnsDoneCount.Inc()
}

func (s *Stats) connectStart(_, _ string) {
	s.connectStartCount.Inc()
}

func (s *Stats) connectDone(_, _ string, err error) {
	s.connectDoneCount.With(prometheus.Labels{
		"error": strconv.FormatBool(err != nil),
	}).Inc()
}

func (s *Stats) tlsHandshakeStart() {
	s.tlsHandshakeStartCount.Inc()
}

func (s *Stats) tlsHandshakeDone(_ tls.ConnectionState, err error) {
	s.tlsHandshakeDoneCount.With(prometheus.Labels{
		"error": strconv.FormatBool(err != nil),
	}).Inc()
}

func (s *Stats) wroteHeaders() {
	s.wroteHeadersCount.Inc()
}

func (s *Stats) wroteRequest(info httptrace.WroteRequestInfo) {
	s.wroteRequestCount.With(prometheus.Labels{
		"error": strconv.FormatBool(info.Err != nil),
	}).Inc()
}

func WithHTTPMetrics(ctx context.Context, stats *Stats) context.Context {
	return httptrace.WithClientTrace(ctx, &stats.tracer)
}

func do(measure *Stats, client *http.Client) {
	req, err := http.NewRequest("GET", "https://jacob.hoffman-andrews.com/", nil)
	if err != nil {
		log.Fatal(err)
	}
	req = req.WithContext(WithHTTPMetrics(context.Background(), measure))
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	ioutil.ReadAll(resp.Body)
	resp.Body.Close()
}

func main() {
	scope, _ := cmd.StatsAndLogging(cmd.SyslogConfig{}, ":7777")
	measure := New(scope)
	do(measure, &http.Client{})
	do(measure, &http.Client{})
	time.Sleep(time.Hour)
}
