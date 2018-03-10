package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/nonce"
)

var count = 50000
var goroutines = 80

func main() {
	runtime.SetBlockProfileRate(1)
	ns, err := nonce.NewNonceService(metrics.NewNoopScope())
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < 65536; i++ {
		n, err := ns.Nonce()
		if err != nil {
			log.Fatal(err)
		}
		_ = ns.Valid(n)
	}
	var wg sync.WaitGroup
	begin := time.Now()
	for j := 0; j < goroutines; j++ {
		wg.Add(1)
		go func() {
			for i := 0; i < count; i++ {
				n, err := ns.Nonce()
				if err != nil {
					log.Fatal(err)
				}
				_ = ns.Valid(n)
			}
			wg.Done()
		}()
	}
	wg.Wait()
	elapsed := time.Since(begin)
	fmt.Println("elapsed", elapsed)
	fmt.Println(float64(elapsed)/float64(count)/float64(time.Millisecond), "ms per op")
	p := pprof.Lookup("block")
	f, err := os.Create("x")
	if err != nil {
		log.Fatal(err)
	}
	err = p.WriteTo(f, 1)
	if err != nil {
		log.Fatal(err)
	}
}
