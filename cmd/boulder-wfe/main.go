package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/jmhodges/clock"
	"github.com/zzma/boulder/cmd"
	"github.com/zzma/boulder/core"
	"github.com/zzma/boulder/features"
	"github.com/zzma/boulder/goodkey"
	bgrpc "github.com/zzma/boulder/grpc"
	blog "github.com/zzma/boulder/log"
	"github.com/zzma/boulder/metrics"
	noncepb "github.com/zzma/boulder/nonce/proto"
	rapb "github.com/zzma/boulder/ra/proto"
	sapb "github.com/zzma/boulder/sa/proto"
	"github.com/zzma/boulder/wfe"
)

type config struct {
	WFE struct {
		cmd.ServiceConfig
		ListenAddress    string
		TLSListenAddress string

		ServerCertificatePath string
		ServerKeyPath         string

		AllowOrigins []string

		ShutdownStopTimeout cmd.ConfigDuration

		SubscriberAgreementURL string

		AcceptRevocationReason bool
		AllowAuthzDeactivation bool

		TLS cmd.TLSConfig

		RAService *cmd.GRPCClientConfig
		SAService *cmd.GRPCClientConfig
		// GetNonceService contains a gRPC config for any nonce-service instances
		// which we want to retrieve nonces from. In a multi-DC deployment this
		// should refer to any local nonce-service instances.
		GetNonceService *cmd.GRPCClientConfig
		// RedeemNonceServices contains a map of nonce-service prefixes to
		// gRPC configs we want to use to redeem nonces. In a multi-DC deployment
		// this should contain all nonce-services from all DCs as we want to be
		// able to redeem nonces generated at any DC.
		RedeemNonceServices map[string]cmd.GRPCClientConfig

		Features map[string]bool

		// DirectoryCAAIdentity is used for the /directory response's "meta"
		// element's "caaIdentities" field. It should match the VA's "issuerDomain"
		// configuration value (this value is the one used to enforce CAA)
		DirectoryCAAIdentity string
		// DirectoryWebsite is used for the /directory response's "meta" element's
		// "website" field.
		DirectoryWebsite string
	}

	Syslog cmd.SyslogConfig

	Common struct {
		IssuerCert string
	}
}

func setupWFE(c config, logger blog.Logger, stats metrics.Scope, clk clock.Clock) (core.RegistrationAuthority, core.StorageAuthority, noncepb.NonceServiceClient, map[string]noncepb.NonceServiceClient) {
	tlsConfig, err := c.WFE.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	clientMetrics := bgrpc.NewClientMetrics(stats)
	raConn, err := bgrpc.ClientSetup(c.WFE.RAService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to RA")
	rac := bgrpc.NewRegistrationAuthorityClient(rapb.NewRegistrationAuthorityClient(raConn))

	saConn, err := bgrpc.ClientSetup(c.WFE.SAService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := bgrpc.NewStorageAuthorityClient(sapb.NewStorageAuthorityClient(saConn))

	var rns noncepb.NonceServiceClient
	npm := map[string]noncepb.NonceServiceClient{}
	if c.WFE.GetNonceService != nil {
		rnsConn, err := bgrpc.ClientSetup(c.WFE.GetNonceService, tlsConfig, clientMetrics, clk)
		cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to get nonce service")
		rns = noncepb.NewNonceServiceClient(rnsConn)
		for prefix, serviceConfig := range c.WFE.RedeemNonceServices {
			conn, err := bgrpc.ClientSetup(&serviceConfig, tlsConfig, clientMetrics, clk)
			cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to redeem nonce service")
			npm[prefix] = noncepb.NewNonceServiceClient(conn)
		}
	}

	return rac, sac, rns, npm
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	err = features.Set(c.WFE.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.WFE.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	clk := cmd.Clock()

	kp, err := goodkey.NewKeyPolicy("") // don't load any weak keys
	cmd.FailOnError(err, "Unable to create key policy")
	rac, sac, rns, npm := setupWFE(c, logger, scope, clk)
	wfe, err := wfe.NewWebFrontEndImpl(scope, clk, kp, rns, npm, logger)
	cmd.FailOnError(err, "Unable to create WFE")
	wfe.RA = rac
	wfe.SA = sac

	wfe.SubscriberAgreementURL = c.WFE.SubscriberAgreementURL
	wfe.AllowOrigins = c.WFE.AllowOrigins
	wfe.AcceptRevocationReason = c.WFE.AcceptRevocationReason
	wfe.AllowAuthzDeactivation = c.WFE.AllowAuthzDeactivation
	wfe.DirectoryCAAIdentity = c.WFE.DirectoryCAAIdentity
	wfe.DirectoryWebsite = c.WFE.DirectoryWebsite

	wfe.IssuerCert, err = cmd.LoadCert(c.Common.IssuerCert)
	cmd.FailOnError(err, fmt.Sprintf("Couldn't read issuer cert [%s]", c.Common.IssuerCert))

	logger.Infof("WFE using key policy: %#v", kp)

	logger.Infof("Server running, listening on %s...", c.WFE.ListenAddress)
	handler := wfe.Handler()
	srv := &http.Server{
		Addr:    c.WFE.ListenAddress,
		Handler: handler,
	}

	go func() {
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			cmd.FailOnError(err, "Running HTTP server")
		}
	}()

	var tlsSrv *http.Server
	if c.WFE.TLSListenAddress != "" {
		tlsSrv = &http.Server{
			Addr:    c.WFE.TLSListenAddress,
			Handler: handler,
		}
		go func() {
			err := tlsSrv.ListenAndServeTLS(c.WFE.ServerCertificatePath, c.WFE.ServerKeyPath)
			if err != nil && err != http.ErrServerClosed {
				cmd.FailOnError(err, "Running TLS server")
			}
		}()
	}

	done := make(chan bool)
	go cmd.CatchSignals(logger, func() {
		ctx, cancel := context.WithTimeout(context.Background(),
			c.WFE.ShutdownStopTimeout.Duration)
		defer cancel()
		_ = srv.Shutdown(ctx)
		if tlsSrv != nil {
			_ = tlsSrv.Shutdown(ctx)
		}
		done <- true
	})

	// https://godoc.org/net/http#Server.Shutdown:
	// When Shutdown is called, Serve, ListenAndServe, and ListenAndServeTLS
	// immediately return ErrServerClosed. Make sure the program doesn't exit and
	// waits instead for Shutdown to return.
	<-done
}
