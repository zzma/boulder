package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	netmail "net/mail"
	"os"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/mail"
	"github.com/letsencrypt/boulder/sa"
)

type mailer struct {
	clk           clock.Clock
	log           blog.Logger
	dbMap         *gorp.DbMap
	mailer        mail.Mailer
	subject       string
	emailTemplate string
	destinations  []string
	begin, end    int // The first and (last + 1) destination to actually send mail to.
	sleepInterval time.Duration
}

func (m *mailer) run() error {
	for i, dest := range m.destinations {
		if i < m.begin || i >= m.end {
			continue
		}
		err := m.mailer.SendMail([]string{dest}, m.subject, m.emailTemplate)
		if err != nil {
			return err
		}
		time.Sleep(m.sleepInterval)
	}
	return nil
}

func main() {
	var from = flag.String("from", "", "From header for emails. Must be a bare email address.")
	var subject = flag.String("subject", "", "Subject of emails")
	var toFile = flag.String("toFile", "", "File containing a list of email addresses to send to, one per file.")
	var template = flag.String("template", "", "Email template in Golang template format. Can be plain text.")
	var dryRun = flag.Bool("dryRun", true, "Whether to do a dry run.")
	var maxSleep = flag.Duration("maxSleep", 60*time.Second, "How long to sleep between emails to start out.")
	var minSleep = flag.Duration("maxSleep", 100*time.Millisecond, "How long to sleep between emails to start out.")
	var start = flag.Int("start", 0, "Line of input file to start from.")
	var end = flag.Int("end", 99999999, "Line of input file to end before.")
	type config struct {
		NotifyMailer struct {
			cmd.DBConfig
			cmd.PasswordConfig
			cmd.SMTPConfig
		}
	}
	var configFile = flag.String("configFile", "", "File containing a JSON config.")

	flag.Parse()
	if from == nil || subject == nil || template == nil || configFile == nil {
		flag.Usage()
		os.Exit(1)
	}

	seven := 7
	_, log := cmd.StatsAndLogging(cmd.StatsdConfig{}, cmd.SyslogConfig{StdoutLevel: &seven})

	configData, err := ioutil.ReadFile(*configFile)
	cmd.FailOnError(err, fmt.Sprintf("Reading %s", *configFile))
	var cfg config
	err = json.Unmarshal(configData, &cfg)
	cmd.FailOnError(err, "Unmarshaling config")

	dbURL, err := cfg.NotifyMailer.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, 10)
	cmd.FailOnError(err, "Could not connect to database")

	// Load email template
	emailTemplate, err := ioutil.ReadFile(*template)
	cmd.FailOnError(err, fmt.Sprintf("Reading %s", *template))

	address, err := netmail.ParseAddress(*from)
	cmd.FailOnError(err, fmt.Sprintf("Parsing %s", *from))

	toBody, err := ioutil.ReadFile(*toFile)
	cmd.FailOnError(err, fmt.Sprintf("Reading %s", *toFile))
	destinations := strings.Split(string(toBody), "\n")

	var mailClient mail.Mailer
	if *dryRun {
		mailClient = mail.NewDryRun(address.Address, log)
	} else {
		smtpPassword, err := cfg.NotifyMailer.PasswordConfig.Pass()
		cmd.FailOnError(err, "Failed to load SMTP password")
		mailClient = mail.New(
			cfg.NotifyMailer.Server,
			cfg.NotifyMailer.Port,
			cfg.NotifyMailer.Username,
			smtpPassword,
			address.Address)
	}
	err = mailClient.Connect()
	cmd.FailOnError(err, fmt.Sprintf("Connecting to %s:%s",
		cfg.NotifyMailer.Server, cfg.NotifyMailer.Port))
	defer func() {
		err = mailClient.Close()
		cmd.FailOnError(err, "Closing mail client")
	}()

	m := mailer{
		clk:           cmd.Clock(),
		log:           log,
		dbMap:         dbMap,
		mailer:        mailClient,
		subject:       *subject,
		destinations:  destinations,
		emailTemplate: emailTemplate,
		begin:         *begin,
		end:           *end,
		sleepInterval: *maxSleep,
	}

	err = m.run()
	cmd.FailOnError(err, "mailer.send returned error")
}
