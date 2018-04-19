package grpc

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"

	"github.com/letsencrypt/boulder/cmd"
	bcreds "github.com/letsencrypt/boulder/grpc/creds"
)

// ClientSetup creates a gRPC TransportCredentials that presents
// a client certificate and validates the the server certificate based
// on the provided *tls.Config.
// It dials the remote service and returns a grpc.ClientConn if successful.
func ClientSetup(c *cmd.GRPCClientConfig, tls *tls.Config, clientMetrics *grpc_prometheus.ClientMetrics) (*grpc.ClientConn, error) {
	if len(c.ServerAddresses) == 0 {
		return nil, fmt.Errorf("boulder/grpc: ServerAddresses is empty")
	}
	if tls == nil {
		return nil, errNilTLS
	}

	var addresses []resolver.Address
	for _, addr := range c.ServerAddresses {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, resolver.Address{
			Addr:       addr,
			Type:       resolver.Backend,
			ServerName: host,
		})
	}
	mr, _ := manual.GenerateAndRegisterManualResolver()
	mr.InitialAddrs(addresses)
	ci := clientInterceptor{c.Timeout.Duration, clientMetrics}
	// HACK: Just pick the first hostname as the servername. Won't work when there
	// are multiple hostnames.
	creds := bcreds.NewClientCredentials(tls.RootCAs, tls.Certificates)
	resolver.SetDefaultScheme(mr.Scheme())
	return grpc.Dial(
		mr.Scheme()+"://manual-resolver-doesnt-matter/"+addresses[0].ServerName,
		grpc.WithTransportCredentials(creds),
		grpc.WithBalancerName("round_robin"),
		grpc.WithUnaryInterceptor(ci.intercept),
	)
}

type registry interface {
	MustRegister(...prometheus.Collector)
}

// NewClientMetrics constructs a *grpc_prometheus.ClientMetrics, registered with
// the given registry, with timing histogram enabled. It must be called a
// maximum of once per registry, or there will be conflicting names.
func NewClientMetrics(stats registry) *grpc_prometheus.ClientMetrics {
	metrics := grpc_prometheus.NewClientMetrics()
	metrics.EnableClientHandlingTimeHistogram()
	stats.MustRegister(metrics)
	return metrics
}
