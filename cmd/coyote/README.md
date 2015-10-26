# `coyote`

![](https://i.imgur.com/CALYCro.gif)

`coyote` is a tool for running tests that simulate or inject failures in boulder,
peripheral services, and the underlying network. In order to fully control network
flows between services Docker containers are used for each boulder service and each
peripheral service.

## Peripheral services to break

* MariaDB
* RabbitMQ
* DNS resolver (Unbound/dnsmasq or something?)
* CT log server

## Plan file format

`coyote` takes one argument, the filename of a YAML plan file which describes what should be done and
when. The description file contains a number of

```
rabbit:
  bin: /usr/bin/rabbitadmin
  errata:

maria:
  bin: /usr/bin/mysql
  errata: -uroot

runtime: 6m

actions:
  - 0m command ./ca-bench -issuance=10 -benchTime=6m -chartDataPath=coyote-test.json
  - 2m rabbit admin delete queue name=CA.server
  - 4m rabbit admin delete queue name=CA.server

```

The `actions` section of the file should contain a list of events in the following format

```
{after} {command} {subcommand} {arguments}

# e.g. after ten minutes execute a SQL statement that kills all open connections
10m maria exec select concat('KILL ',id,';') from information_schema.processlist where id != CONNECTION_ID() into outfile '/tmp/evil'; source /tmp/evil;
```

### Commands

#### General

* `command {bin} {args...}`
		This command is used to execute other commands like `ca-bench`, `load-generator`,
		or `softhsm`

#### Docker

* `docker`
		This command is used to interact with the docker containers holding the services

	* `run`
			Runs the container
	* `stop`
			Stops the container
	* `halt-process`
			Sends a `SIGTSTP` to the main command running in the container
	* `resume-process`
			Sends a `SIGCONT` to the main command running in the container

#### Network

* `network`
		This command is used to cause failures and interruptions in the network connecting the various
		docker containers

		* `partition {container} ?{direction} ?{container}`
				Partitions a container from the rest of the network, or two containers in a specific direction
		* `heal-partition`
		* `lossy {percent loss}`
		* `lag {lag duration}`
		* `rate-limit {throughput}`

#### Peripheral services

* `maria`
		* `start`
		* `stop`
		* `restart`
		* `exec {statement}`

* `rabbit`
		* `start`
		    * `stop`
		    * `restart`
		    * `admin {statement}`
