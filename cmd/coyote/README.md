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

## Test description format

`coyote` takes one argument, the filename of a YAML test plan which describes what should be done and
when. The description file contains a number of

```
initialLoad: 10 #/s

plan:
	- 5m docker halt-process boulder-sa
	- 10m docker resume-process boulder-sa
	- 15m end

expected:
	alive: all
```

The `plan` section of the file should contain a list of events in the following format

```
{after} {command} {subcommand} {arguments}

# e.g. after ten minutes execute a SQL statement that kills all open transactions
10m maria exec call eval('SELECT sql_kill_query FROM innodb_transactions')
```

### Commands

#### General

* `load-generator`
	This command is used to alter load on the system

	* `set {throughput}`
		Sets the throughput of the load generator, e.g. `set 15`
	* `pause {duration}`
		Pauses the load generator, e.g. `pause 1m`
	* `start`
		Starts the load generator
	* `stop`
		Stops the load generator

* `end`
	This command doesn't do anything itself but can be used to extend the runtime of a plan beyond
	executing the last meaningful command.

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
