# `ca-bench`

`ca-bench` is a relatively simple tool for load-testing `boulder-ca` that works by sending N constant asyncronous
`IssueCertificate` and `GenerateOCSP` RPC calls per second and collecting/calculating the call latency and
throughput.

## Prerequisites

* To chart the latency data you'll need `python2.7` with `matplotlib` and `pandas`
* To view detailed heap/GC stats you'll want to run StatsD + some metric dashboard
  (if you don't already have this installed the quickest way is to use
  [kamon-io/docker-grafana-graphite](https://github.com/kamon-io/docker-grafana-graphite),
  a basic Grafana dashboard can be imported from `boulder-dashboard.json` to view various metrics,
  if your Graphite source is called `stats` the dashboard will import *perfectly*)

## Usage

In order to run `ca-bench` needs two pieces of information, the registration ID
(`-regID`) to associate issued certificates with, and the DNS name that the issued
certificates will be for (`-testCertName`).

Latency charting data (except latency histograms) will only be collected if the `-chartDataPath` is provided.
`latency-chart.py` can then be used to process the JSON chart data file. If you want the histograms
to be printed in the `HistogramLogProcessor` chartable format you can use the `-printHist` flag.

If `-benchTime` isn't provided `ca-bench` will run indefinitely until interrupted.

Throughput can be charged over time using the `-issuanceEvents` and `-ocspEvents`
flags. To set the issuance throughput to 25/s after 5 minutes of runtime the format
is `-issuanceEvents 25,5m` to then increase the throughput to 30/s after another 5
minutes the format is `-issuanceEvents 25,5m:30,5m`.

Progress stats can be hidden using `-hideStats` or the default print interval (5s)
can be changed using the `-statsInterval` flag.

```
$ ./ca-bench -mode async -issuance 35 -benchTime 15s -chartDataPath 35-15s.json
2015/10/12 17:32:01 [DEBUG] Parsed OID [2 23 140 1 2 1]
2015/10/12 17:32:01 [DEBUG] Parsed OID [1 2 3 4]
2015/10/12 17:32:01 Using default logging configuration.
Running for (approximately) 15m0s
running for: 5s, issuance calls: 131 (avg success rate: 26.20/s, errors: 0, timeouts: 0)
running for: 10s, issuance calls: 264 (avg success rate: 26.40/s, errors: 0, timeouts: 0)
running for: 15s, issuance calls: 415 (avg success rate: 27.67/s, errors: 0, timeouts: 0)

Stopped, ran for 15.914453405s

Certificate Issuance
Count: 450 (0 errors)
Latency: Max 3.9870464s, Min 13.230912ms, Avg 1.599913765s

# this will create bench-tests/35-15s-issuance.png since the JSON file only contains latency
# data for IssueCertificate (since -ocsp wasn't used above)
$ ./latency-chart.py 35-15s.json --outputDir bench-tests/
# if you want a different prefix to the generated images you can specific it with
# the --outputPrefix argument, the following will create short-test-issuance.png
$ ./latency-chart.py 35-15s.json --outputPrefix short-test
```
