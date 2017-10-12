package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/sa"
)

type fillerConfig struct {
	Filler struct {
		cmd.DBConfig
		Parallelism uint
	}
}

/*
	wg := new(sync.WaitGroup)
	work := make(chan string, len(ids))
	for _, id := range ids {
		work <- id
	}
	close(work)
	for i := 0; i < parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range work {
				err := deleteAuthorization(p.db, table, id)
				if err != nil {
					p.log.AuditErr(fmt.Sprintf("Deleting %s: %s", id, err))
				}
			}
		}()
	}
	wg.Wait()
*/

type model struct {
	core.Authorization

	LockCol int
}

func main() {
	configPath := flag.String("config", "config.json", "Path to Boulder configuration file")
	flag.Parse()

	configJSON, err := ioutil.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read config file '%s': %s\n", *configPath, err)
		os.Exit(1)
	}

	var config fillerConfig
	err = json.Unmarshal(configJSON, &config)
	cmd.FailOnError(err, "Failed to parse config")

	// Configure DB
	dbURL, err := config.Filler.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, int(config.Filler.Parallelism))
	cmd.FailOnError(err, "Could not connect to database")

	dbMap.AddTableWithName(model{}, "pendingAuthorizations").SetKeys(false, "ID")
	span := 24 * time.Hour * 365
	start := time.Now().Add(-span)
	increment := time.Hour

	work := make(chan time.Time, 1000)
	go func() {
		for i := 0; i < int(span)/int(increment); i++ {
			expires := start.Add(time.Duration(i) * increment)
			for j := 0; j < 30000; j++ {
				work <- expires
			}
		}
	}()

	for i := 0; i < int(config.Filler.Parallelism); i++ {
		go func() {
			for expires := range work {
				err = dbMap.Insert(&model{
					core.Authorization{
						ID:             core.NewToken(),
						RegistrationID: 1,
						Expires:        &expires,
						Combinations:   [][]int{[]int{1, 2, 3}},
						Status:         "pending",
						Identifier: core.AcmeIdentifier{
							Type:  "dns",
							Value: "example.com",
						},
					},
					0,
				})
				if err != nil {
					log.Print(err)
				}
			}
		}()
	}

	select {}
}
