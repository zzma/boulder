package main

import (
	"context"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"os/user"
	"sort"
	"strconv"

	"gopkg.in/go-gorp/gorp.v2"

	"github.com/zzma/boulder/cmd"
	"github.com/zzma/boulder/core"
	berrors "github.com/zzma/boulder/errors"
	"github.com/zzma/boulder/features"
	bgrpc "github.com/zzma/boulder/grpc"
	blog "github.com/zzma/boulder/log"
	"github.com/zzma/boulder/metrics"
	rapb "github.com/zzma/boulder/ra/proto"
	"github.com/zzma/boulder/revocation"
	"github.com/zzma/boulder/sa"
	sapb "github.com/zzma/boulder/sa/proto"
)

const usageString = `
usage:
admin-revoker serial-revoke --config <path> <serial> <reason-code>
admin-revoker reg-revoke --config <path> <registration-id> <reason-code>
admin-revoker list-reasons --config <path>

command descriptions:
  serial-revoke   Revoke a single certificate by the hex serial number
  reg-revoke      Revoke all certificates associated with a registration ID
  list-reasons    List all revocation reason codes

args:
  config    File path to the configuration file for this service
`

type config struct {
	Revoker struct {
		cmd.DBConfig
		// Similarly, the Revoker needs a TLSConfig to set up its GRPC client certs,
		// but doesn't get the TLS field from ServiceConfig, so declares its own.
		TLS cmd.TLSConfig

		RAService *cmd.GRPCClientConfig
		SAService *cmd.GRPCClientConfig

		Features map[string]bool
	}

	Syslog cmd.SyslogConfig
}

func setupContext(c config) (core.RegistrationAuthority, blog.Logger, *gorp.DbMap, core.StorageAuthority) {
	logger := cmd.NewLogger(c.Syslog)

	tlsConfig, err := c.Revoker.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	clk := cmd.Clock()

	clientMetrics := bgrpc.NewClientMetrics(metrics.NewNoopScope())
	raConn, err := bgrpc.ClientSetup(c.Revoker.RAService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to RA")
	rac := bgrpc.NewRegistrationAuthorityClient(rapb.NewRegistrationAuthorityClient(raConn))

	dbURL, err := c.Revoker.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, c.Revoker.DBConfig.MaxDBConns)
	cmd.FailOnError(err, "Couldn't setup database connection")

	saConn, err := bgrpc.ClientSetup(c.Revoker.SAService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := bgrpc.NewStorageAuthorityClient(sapb.NewStorageAuthorityClient(saConn))

	return rac, logger, dbMap, sac
}

func revokeBySerial(ctx context.Context, serial string, reasonCode revocation.Reason, rac core.RegistrationAuthority, logger blog.Logger, tx *gorp.Transaction) (err error) {
	if reasonCode < 0 || reasonCode == 7 || reasonCode > 10 {
		panic(fmt.Sprintf("Invalid reason code: %d", reasonCode))
	}

	certObj, err := sa.SelectCertificate(tx, "WHERE serial = ?", serial)
	if err == sql.ErrNoRows {
		return berrors.NotFoundError("certificate with serial %q not found", serial)
	}
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certObj.DER)
	if err != nil {
		return
	}

	u, err := user.Current()
	err = rac.AdministrativelyRevokeCertificate(ctx, *cert, reasonCode, u.Username)
	if err != nil {
		return
	}

	logger.Infof("Revoked certificate %s with reason '%s'", serial, revocation.ReasonToString[reasonCode])
	return
}

func revokeByReg(ctx context.Context, regID int64, reasonCode revocation.Reason, rac core.RegistrationAuthority, logger blog.Logger, tx *gorp.Transaction) (err error) {
	var certs []core.Certificate
	_, err = tx.Select(&certs, "SELECT serial FROM certificates WHERE registrationID = :regID", map[string]interface{}{"regID": regID})
	if err != nil {
		return
	}

	for _, cert := range certs {
		err = revokeBySerial(ctx, cert.Serial, reasonCode, rac, logger, tx)
		if err != nil {
			return
		}
	}

	return
}

// This abstraction is needed so that we can use sort.Sort below
type revocationCodes []revocation.Reason

func (rc revocationCodes) Len() int           { return len(rc) }
func (rc revocationCodes) Less(i, j int) bool { return rc[i] < rc[j] }
func (rc revocationCodes) Swap(i, j int)      { rc[i], rc[j] = rc[j], rc[i] }

func main() {
	usage := func() {
		fmt.Fprintf(os.Stderr, usageString)
		os.Exit(1)
	}
	if len(os.Args) <= 2 {
		usage()
	}

	command := os.Args[1]
	flagSet := flag.NewFlagSet(command, flag.ContinueOnError)
	configFile := flagSet.String("config", "", "File path to the configuration file for this service")
	err := flagSet.Parse(os.Args[2:])
	cmd.FailOnError(err, "Error parsing flagset")

	if *configFile == "" {
		usage()
	}

	var c config
	err = cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")
	err = features.Set(c.Revoker.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	ctx := context.Background()
	args := flagSet.Args()
	switch {
	case command == "serial-revoke" && len(args) == 2:
		// 1: serial,  2: reasonCode
		serial := args[0]
		reasonCode, err := strconv.Atoi(args[1])
		cmd.FailOnError(err, "Reason code argument must be an integer")

		rac, logger, dbMap, _ := setupContext(c)

		tx, err := dbMap.Begin()
		if err != nil {
			cmd.FailOnError(sa.Rollback(tx, err), "Couldn't begin transaction")
		}

		err = revokeBySerial(ctx, serial, revocation.Reason(reasonCode), rac, logger, tx)
		if err != nil {
			cmd.FailOnError(sa.Rollback(tx, err), "Couldn't revoke certificate")
		}

		err = tx.Commit()
		cmd.FailOnError(err, "Couldn't cleanly close transaction")

	case command == "reg-revoke" && len(args) == 2:
		// 1: registration ID,  2: reasonCode
		regID, err := strconv.ParseInt(args[0], 10, 64)
		cmd.FailOnError(err, "Registration ID argument must be an integer")
		reasonCode, err := strconv.Atoi(args[1])
		cmd.FailOnError(err, "Reason code argument must be an integer")

		rac, logger, dbMap, sac := setupContext(c)
		defer logger.AuditPanic()

		tx, err := dbMap.Begin()
		if err != nil {
			cmd.FailOnError(sa.Rollback(tx, err), "Couldn't begin transaction")
		}

		_, err = sac.GetRegistration(ctx, regID)
		if err != nil {
			cmd.FailOnError(err, "Couldn't fetch registration")
		}

		err = revokeByReg(ctx, regID, revocation.Reason(reasonCode), rac, logger, tx)
		if err != nil {
			cmd.FailOnError(sa.Rollback(tx, err), "Couldn't revoke certificate")
		}

		err = tx.Commit()
		cmd.FailOnError(err, "Couldn't cleanly close transaction")

	case command == "list-reasons":
		var codes revocationCodes
		for k := range revocation.ReasonToString {
			codes = append(codes, k)
		}
		sort.Sort(codes)
		fmt.Printf("Revocation reason codes\n-----------------------\n\n")
		for _, k := range codes {
			fmt.Printf("%d: %s\n", k, revocation.ReasonToString[k])
		}

	default:
		usage()
	}
}
