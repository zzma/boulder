// chill client
package main

import (
	"context"
	"log"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/grpc/test_proto"
	"github.com/letsencrypt/boulder/metrics"
)

func main() {
	certFile := "../chillsrv/chiller.client.example/cert.pem"
	keyFile := "../chillsrv/chiller.client.example/key.pem"
	caCertFile := "../chillsrv/minica.pem"
	cmdTLSConfig := cmd.TLSConfig{&certFile, &keyFile, &caCertFile}
	tlsConfig, err := cmdTLSConfig.Load()
	if err != nil {
		log.Fatal(err)
	}
	grpcConfig := &cmd.GRPCClientConfig{
		ServerAddresses: []string{"chiller.server.example:3344"},
		Timeout:         cmd.ConfigDuration{90 * time.Second},
	}

	clientMetrics := bgrpc.NewClientMetrics(metrics.NewNoopScope())
	conn, err := bgrpc.ClientSetup(grpcConfig, tlsConfig, clientMetrics)
	if err != nil {
		log.Fatal(err)
	}

	c := test_proto.NewChillerClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 1000000*time.Millisecond)
	defer cancel()
	for i := 0; i < 600; i++ {
		go func(i int) {
			var time int64 = (time.Duration(i) * time.Millisecond).Nanoseconds()
			log.Printf("Sent chills (%d)", time)
			_, err = c.Chill(ctx, &test_proto.Time{Time: &time})
			if err != nil {
				log.Fatal(err)
			}
			//log.Print("done")
		}(i)
	}
	select {}
}
