# `load-generator`

`load-generator` is a load testing tool for generating load focused on the `WFE`
which exercises boulder in a similar fashion how it will be exercised under user
load (unlike `ca-bench`). `load-generator` is very useful when using `coyote` to
test service failures and their effect on boulder.

## Usage

```
$ ./load-generator --help
NAME:
   load-generator - boulder-wfe based load generator

USAGE:
   load-generator [global options] command [command options] [arguments...]

VERSION:
   0.1.0 [Unspecified]

AUTHOR(S):
   Boulder contributors <ca-dev@letsencrypt.org>

COMMANDS:
   help, h	Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --apiBase "http://localhost:4000"  The base URI of boulder-wfe
   --rate "1"                         The rate (per second) at which to send calls
   --maxRegs "100"                    Maximum number of registrations to generate
   --certKeySize "2048"               Bit size of the key to sign certificates with
   --help, -h				                  show help
   --version, -v                      print the version

```

That's about it for now...
