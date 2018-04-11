package main

import (
	"context"
	"log"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/grpc/test_proto"
	"github.com/letsencrypt/boulder/metrics"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

// testServer is used to implement TestTimeouts, and will attempt to sleep for
// the given amount of time (unless it hits a timeout or cancel).
type testServer struct{}

// Chill implements ChillerServer.Chill
func (s *testServer) Chill(ctx context.Context, in *test_proto.Time) (*test_proto.Time, error) {
	start := time.Now()
	// Sleep for either the requested amount of time, or the context times out or
	// is canceled.
	select {
	case <-time.After(time.Duration(*in.Time) * time.Nanosecond):
		spent := int64(time.Since(start) / time.Nanosecond)
		return &test_proto.Time{Time: &spent}, nil
	case <-ctx.Done():
		return nil, grpc.Errorf(codes.DeadlineExceeded, "the chiller overslept")
	}
}

func main() {
	serverMetrics := bgrpc.NewServerMetrics(metrics.NewNoopScope())

	certFile := "chiller.server.example/cert.pem"
	keyFile := "chiller.server.example/key.pem"
	caCertFile := "minica.pem"
	cmdTLSConfig := cmd.TLSConfig{&certFile, &keyFile, &caCertFile}
	tlsConfig, err := cmdTLSConfig.Load()
	if err != nil {
		log.Fatal(err)
	}
	grpcConfig := cmd.GRPCServerConfig{
		Address:     ":3344",
		ClientNames: []string{"chiller.client.example"},
	}
	srv, lis, err := bgrpc.NewServer(&grpcConfig, tlsConfig, serverMetrics)
	if err != nil {
		log.Fatal(err)
	}

	test_proto.RegisterChillerServer(srv, &testServer{})
	if err := srv.Serve(lis); err != nil {
		log.Fatal(err)
	}
}
