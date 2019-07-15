package wfe2

import (
	"github.com/zzma/boulder/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

type wfe2Stats struct {
	// httpErrorCount counts client errors at the HTTP level
	// e.g. failure to provide a Content-Length header, no POST body, etc
	httpErrorCount *prometheus.CounterVec
	// joseErrorCount counts client errors at the JOSE level
	// e.g. bad JWS, broken JWS signature, invalid JWK, etc
	joseErrorCount *prometheus.CounterVec
	// csrSignatureAlgs counts the signature algorithms in use for order
	// finalization CSRs
	csrSignatureAlgs *prometheus.CounterVec
	// improperECFieldLengths counts the number of ACME account EC JWKs we see
	// with improper X and Y lengths for their curve
	improperECFieldLengths prometheus.Counter
}

func initStats(scope metrics.Scope) wfe2Stats {
	httpErrorCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "httpErrors",
			Help: "client request errors at the HTTP level",
		},
		[]string{"type"})
	scope.MustRegister(httpErrorCount)

	joseErrorCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "joseErrors",
			Help: "client request errors at the JOSE level",
		},
		[]string{"type"})
	scope.MustRegister(joseErrorCount)

	csrSignatureAlgs := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "csrSignatureAlgs",
			Help: "Number of CSR signatures by algorithm",
		},
		[]string{"type"},
	)
	scope.MustRegister(csrSignatureAlgs)

	improperECFieldLengths := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "improperECFieldLengths",
			Help: "Number of account EC keys with improper X and Y lengths",
		},
	)
	scope.MustRegister(improperECFieldLengths)

	return wfe2Stats{
		httpErrorCount:         httpErrorCount,
		joseErrorCount:         joseErrorCount,
		csrSignatureAlgs:       csrSignatureAlgs,
		improperECFieldLengths: improperECFieldLengths,
	}
}
