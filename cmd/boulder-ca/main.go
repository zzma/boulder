package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"os"

	"github.com/beeker1121/goque"

	"github.com/zzma/boulder/ca"
	"github.com/zzma/boulder/ca/config"
	caPB "github.com/zzma/boulder/ca/proto"
	"github.com/zzma/boulder/cmd"
	"github.com/zzma/boulder/features"
	"github.com/zzma/boulder/goodkey"
	bgrpc "github.com/zzma/boulder/grpc"
	"github.com/zzma/boulder/policy"
	sapb "github.com/zzma/boulder/sa/proto"
)

type config struct {
	CA ca_config.CAConfig

	PA cmd.PAConfig

	Syslog cmd.SyslogConfig
}

func main() {
	caAddr := flag.String("ca-addr", "", "CA gRPC listen address override")
	ocspAddr := flag.String("ocsp-addr", "", "OCSP gRPC listen address override")
	debugAddr := flag.String("debug-addr", "", "Debug server address override")
	runFuzz := flag.Bool("fuzz", false, "Run CA in fuzz mode")
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	err = features.Set(c.CA.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	if *caAddr != "" {
		c.CA.GRPCCA.Address = *caAddr
	}
	if *ocspAddr != "" {
		c.CA.GRPCOCSPGenerator.Address = *ocspAddr
	}
	if *debugAddr != "" {
		c.CA.DebugAddr = *debugAddr
	}

	if c.CA.MaxNames == 0 {
		cmd.Fail(fmt.Sprintf("Error in CA config: MaxNames must not be 0"))
	}

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.CA.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	cmd.FailOnError(c.PA.CheckChallenges(), "Invalid PA configuration")

	pa, err := policy.New(c.PA.Challenges)
	cmd.FailOnError(err, "Couldn't create PA")

	if c.CA.HostnamePolicyFile == "" {
		cmd.FailOnError(fmt.Errorf("HostnamePolicyFile was empty."), "")
	}
	err = pa.SetHostnamePolicyFile(c.CA.HostnamePolicyFile)
	cmd.FailOnError(err, "Couldn't load hostname policy file")

	issuers, err := ca.LoadIssuers(c.CA)
	cmd.FailOnError(err, "Couldn't load issuers")

	kp, err := goodkey.NewKeyPolicy(c.CA.WeakKeyFile)
	cmd.FailOnError(err, "Unable to create key policy")

	tlsConfig, err := c.CA.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	clk := cmd.Clock()

	clientMetrics := bgrpc.NewClientMetrics(scope)
	conn, err := bgrpc.ClientSetup(c.CA.SAService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sa := bgrpc.NewStorageAuthorityClient(sapb.NewStorageAuthorityClient(conn))

	var orphanQueue *goque.Queue
	if c.CA.OrphanQueueDir != "" {
		orphanQueue, err = goque.OpenQueue(c.CA.OrphanQueueDir)
		cmd.FailOnError(err, "Failed to open orphaned certificate queue")
		defer func() { _ = orphanQueue.Close() }()
	}

	cai, err := ca.NewCertificateAuthorityImpl(
		*configFile,
		c.CA,
		sa,
		pa,
		clk,
		scope,
		issuers,
		kp,
		logger,
		orphanQueue)
	cmd.FailOnError(err, "Failed to create CA impl")

	if orphanQueue != nil {
		go cai.OrphanIntegrationLoop()
	}

	serverMetrics := bgrpc.NewServerMetrics(scope)
	caSrv, caListener, err := bgrpc.NewServer(c.CA.GRPCCA, tlsConfig, serverMetrics, clk)
	cmd.FailOnError(err, "Unable to setup CA gRPC server")
	caWrapper := bgrpc.NewCertificateAuthorityServer(cai)
	caPB.RegisterCertificateAuthorityServer(caSrv, caWrapper)
	go func() {
		cmd.FailOnError(cmd.FilterShutdownErrors(caSrv.Serve(caListener)), "CA gRPC service failed")
	}()

	ocspSrv, ocspListener, err := bgrpc.NewServer(c.CA.GRPCOCSPGenerator, tlsConfig, serverMetrics, clk)
	cmd.FailOnError(err, "Unable to setup CA gRPC server")
	ocspWrapper := bgrpc.NewCertificateAuthorityServer(cai)
	caPB.RegisterOCSPGeneratorServer(ocspSrv, ocspWrapper)
	go func() {
		cmd.FailOnError(cmd.FilterShutdownErrors(ocspSrv.Serve(ocspListener)),
			"OCSPGenerator gRPC service failed")
	}()

	go cmd.CatchSignals(logger, func() {
		caSrv.GracefulStop()
		ocspSrv.GracefulStop()
	})

	if *runFuzz {
		issueReq := &caPB.IssueCertificateRequest{
			Csr: x509.CertificateRequest{}.Raw,
		}

		ctx := context.Background()

		resp, err := cai.IssuePrecertificate(ctx, issueReq)
		cmd.FailOnError(err, "Unable to generate certificate")
		fmt.Println(resp.GetDER())
	}

	select {}
}
