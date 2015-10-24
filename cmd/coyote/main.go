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
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/codegangsta/cli"
	"github.com/letsencrypt/boulder/cmd"
)

var (
	rabbitBin    = "/usr/bin/rabbitadmin"
	rabbitErrata = []string{""}

	mariaBin    = "/usr/bin/mysql"
	mariaErrata = []string{""}
)

func execCommand(bin string, args []string) error {
	cmd := exec.Command(bin, args...)
	return cmd.Run()
}

func rabbitTool(action string) error {
	return nil
}

func parseRabbitCommand(cmd string) (func() string, error) {
	fields := strings.SplitN(cmd, " ", 1)
	if len(fields) < 2 {
		return nil, fmt.Errorf("invalid action")
	}
	cmd = fields[0]
	args := fields[1]
	switch {
	case strings.HasPrefix(cmd, "delete-"):
	case cmd == "purge":
		return func() string {
			desc := fmt.Sprintf("[RabbitMQ] Purged queue %s", args)
			err := rabbitTool(fmt.Sprintf("purge %s", args))
			if err != nil {
				desc = fmt.Sprintf("%s. ERROR: %s", desc, err)
			}
			return desc
		}, nil
	}
	return nil, nil
}

func mariaTool(action string) error {
	return nil
}

func parseMariaCommand(cmd string) (func() string, error) {
	fields := strings.SplitN(cmd, " ", 1)
	if len(fields) < 2 {
		return nil, fmt.Errorf("invalid action")
	}
	cmd = fields[0]
	args := fields[1]
	switch {
	case cmd == "exec":
		desc := fmt.Sprintf("[MariaDB] Executed '%s'", args)
		err := mariaTool(fmt.Sprintf("-e '%s'", args))
		if err != nil {
			desc = fmt.Sprintf("%s. ERROR: %s", desc, err)
		}
	}
	return nil, nil
}

func parseNetworkCommand(cmd string) (func() string, error) {
	return nil, nil
}

type action struct {
	do    func() string
	after time.Duration
}

type event struct {
	action string
	at     time.Time
	took   time.Duration
}

type coyote struct {
	eventLog chan event
	plan     []action
	wg       sync.WaitGroup
}

func (c *coyote) loadActionPlan(actionStrings []string) error {
	var actions []action
	for _, a := range actionStrings {
		fields := strings.SplitN(a, " ", 2)
		if len(fields) != 3 {
			return fmt.Errorf("Invalid action format")
		}
		after, err := time.ParseDuration(fields[0])
		if err != nil {
			return err
		}
		var do func() string
		switch fields[1] {
		case "rabbit":
			do, err = parseRabbitCommand(fields[2])
			if err != nil {
				return err
			}
		case "maria":
			do, err = parseMariaCommand(fields[2])
			if err != nil {
				return err
			}
		case "network":
			do, err = parseNetworkCommand(fields[2])
			if err != nil {
				return err
			}
		}
		actions = append(actions, action{
			after: after,
			do:    do,
		})
	}

	if len(actions) == 0 {
		return fmt.Errorf("At least one action is required!")
	}

	c.plan = actions
	return nil
}

func (c *coyote) executePlan() {
	for _, a := range c.plan {
		c.wg.Add(1)
		go func(a action) {
			<-time.After(a.after)
			s := time.Now()
			eventDesc := a.do()
			c.eventLog <- event{
				action: eventDesc,
				at:     time.Now(),
				took:   time.Since(s),
			}
			c.wg.Done()
		}(a)
	}
}

func (c *coyote) printEventLog() {
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 0, '\t', 0)
	fmt.Fprintln(w, "\tEvent\tTook")
	for e := range c.eventLog {
		fmt.Fprintf(w, "%s\t%s\t%s\t", e.at, e.action, e.took)
	}
	w.Flush()
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
		wile := coyote{}
		err := wile.loadActionPlan([]string{})
		cmd.FailOnError(err, "Couldn't parse action plan")

		fmt.Printf("%s -- started plan\n", time.Now())
		wile.executePlan()
		wile.wg.Wait()
		fmt.Printf("%s -- finished plan\n", time.Now())

		wile.printEventLog()
	}

	err := app.Run(os.Args)
	cmd.FailOnError(err, "Failed to run application")
}
