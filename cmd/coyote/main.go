// coyote is a tool designed to orchestrate tests of boulder that include failures
// of peripheral services or of the network itself.
//
// Things it'd be nice to have:
//   * Network
//     * Partition services from each other / from MariaDB/RabbitMQ
//
//   * MariaDB
//     * Drop table / contents
//     * Drop databases
//     * Drop users
//     * Change permissions
//     * Lock tables / databases
//     * Create failing transactions(?)
//
//   * RabbitMQ
//     * Drop queues
//     * Purge queues
//     * Drop exchanges
//     * Drop users
//     * Change permissions
//     * Inject trash(?)
//     * Inject duplicate calls/responses
//     * Kill all open connections
//
//   * Boulder instances + RabbitMQ/MariaDB
//     * Duplicate services (boulder only)
//     * Kill services
//     * Halt & resume services
//     * Hard restart services
//     * Soft restart services
//

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/codegangsta/cli"
	"gopkg.in/yaml.v2"

	"github.com/letsencrypt/boulder/cmd"
)

var (
	rabbitBin    = "/usr/bin/rabbitadmin"
	rabbitErrata = []string{""}

	mariaBin    = "/usr/bin/mysql"
	mariaErrata = []string{""}
)

func splitIntoArgs(args string) []string {
	lastQuote := rune(0)
	f := func(c rune) bool {
		switch {
		case c == lastQuote:
			lastQuote = rune(0)
			return false
		case lastQuote != rune(0):
			return false
		case unicode.In(c, unicode.Quotation_Mark):
			lastQuote = c
			return false
		default:
			return unicode.IsSpace(c)
		}
	}
	return strings.FieldsFunc(args, f)
}

func execCommand(bin string, args []string) error {
	cmd := exec.Command(bin, args...)
	buf := new(bytes.Buffer)
	cmd.Stdout = buf
	cmd.Stderr = buf
	err := cmd.Run()
	fmt.Println(buf.String())
	return err
}

func (c *coyote) rabbitTool(action string) error {
	return execCommand(c.rabbitBin, append(c.rabbitErrata, splitIntoArgs(action)...))
}

func (c *coyote) parseRabbitCommand(cmd string) (func() error, string, error) {
	fields := strings.SplitN(cmd, " ", 2)
	if len(fields) != 2 {
		return nil, "", fmt.Errorf("Invalid action format")
	}
	cmd = fields[0]
	args := fields[1]
	switch {
	case cmd == "admin":
		return func() error {
			return c.rabbitTool(fmt.Sprintf("%s", args))
		}, fmt.Sprintf("Executing admin tool statement \"%s\"", args), nil
	default:
		return nil, "", fmt.Errorf("Invalid rabbit subcommand")
	}
}

func (c *coyote) mariaTool(args []string) error {
	return execCommand(c.mariaBin, append(c.mariaErrata, args...))
}

func (c *coyote) parseMariaCommand(cmd string) (func() error, string, error) {
	fields := strings.SplitN(cmd, " ", 2)
	if len(fields) != 2 {
		return nil, "", fmt.Errorf("Invalid action format")
	}
	cmd = fields[0]
	args := fields[1]
	switch {
	case cmd == "exec":
		return func() error {
			return c.mariaTool([]string{"-e", args})
		}, fmt.Sprintf("Executing statement \"%s\"", args), nil
	default:
		return nil, "", fmt.Errorf("Invalid maria subcommand")
	}
}

type action struct {
	do      func() error
	after   time.Duration
	desc    string
	section string
}

func (c *coyote) loadActionPlan(actionStrings []string) error {
	var actions []action
	for _, a := range actionStrings {
		fields := strings.SplitN(a, " ", 3)
		if len(fields) != 3 {
			return fmt.Errorf("Invalid action format")
		}
		after, err := time.ParseDuration(fields[0])
		if err != nil {
			return err
		}
		if after >= c.runtime {
			return fmt.Errorf("Cannot run action after finishing")
		}
		var do func() error
		var desc string
		switch fields[1] {
		case "rabbit":
			do, desc, err = c.parseRabbitCommand(fields[2])
			if err != nil {
				return err
			}
		case "maria":
			do, desc, err = c.parseMariaCommand(fields[2])
			if err != nil {
				return err
			}
		case "command":
			desc = fmt.Sprintf("Executing %s", fields[2])
			do = func() error {
				parts := strings.SplitN(fields[2], " ", 2)
				return execCommand(parts[0], splitIntoArgs(parts[1]))
			}
		default:
			return fmt.Errorf("Invalid command")
		}
		actions = append(actions, action{
			after:   after,
			do:      do,
			desc:    desc,
			section: fields[1],
		})
	}

	if len(actions) == 0 {
		return fmt.Errorf("At least one action is required!")
	}

	c.plan = actions
	return nil
}

type planFile struct {
	Rabbit struct {
		Bin    string `yaml:"bin"`
		Errata string `yaml:"errata"`
	} `yaml:"rabbit"`
	Maria struct {
		Bin    string `yaml:"bin"`
		Errata string `yaml:"errata"`
	} `yaml:"maria"`
	Runtime cmd.ConfigDuration `yaml:"runtime"`
	Actions []string           `yaml:"actions"`
}

type coyote struct {
	plan    []action
	runtime time.Duration

	rabbitBin    string
	rabbitErrata []string

	mariaBin    string
	mariaErrata []string
}

func (c *coyote) printPlan() {
	fmt.Println("Test plan")
	fmt.Printf("#########\n\n")
	fmt.Printf("Runtime: %s\n", c.runtime)

	fmt.Println()
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 0, '\t', 0)
	fmt.Fprintln(w, " \tAfter\tSection\tDo")
	fmt.Fprintln(w, " \t-----\t-------\t--")
	for _, a := range c.plan {
		fmt.Fprintf(w, " \t%s\t%s\t%s\n", a.after, a.section, a.desc)
	}
	w.Flush()
	fmt.Println()
}

func (c *coyote) executePlan() {
	for _, a := range c.plan {
		go func(a action) {
			<-time.After(a.after)
			s := time.Now()
			err := a.do()
			if err != nil {
				a.desc = fmt.Sprintf("%s. ERROR: %s", a.desc, err)
			}

			fmt.Printf("%s -- %s -- took %s\n", s, a.desc, time.Since(s))
		}(a)
	}
	time.Sleep(c.runtime)
}

func main() {
	app := cli.NewApp()
	app.Name = "coyote"
	app.Usage = "Boulder injected failure framework"
	app.Version = cmd.Version()
	app.Author = "Boulder contributors"
	app.Email = "ca-dev@letsencrypt.org"

	app.Flags = []cli.Flag{}

	app.Action = func(c *cli.Context) {
		// Load plan
		content, err := ioutil.ReadFile("another-test.yml")
		cmd.FailOnError(err, "Failed to load test plan")
		var plan planFile
		err = yaml.Unmarshal(content, &plan)
		cmd.FailOnError(err, "Failed to parse test plan")

		// Parse plan
		wile := coyote{
			runtime:      plan.Runtime.Duration,
			mariaBin:     plan.Maria.Bin,
			mariaErrata:  splitIntoArgs(plan.Maria.Errata),
			rabbitBin:    plan.Rabbit.Bin,
			rabbitErrata: splitIntoArgs(plan.Rabbit.Errata),
		}
		err = wile.loadActionPlan(plan.Actions)
		cmd.FailOnError(err, "Couldn't parse action plan")

		wile.printPlan()

		fmt.Printf("%s -- starting plan\n", time.Now())
		wile.executePlan()
		fmt.Printf("%s -- finished plan\n", time.Now())
	}

	err := app.Run(os.Args)
	cmd.FailOnError(err, "Failed to run application")
}
