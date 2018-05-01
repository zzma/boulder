package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/test/challsrv"
)

type managementServer struct {
	*http.Server
	challSrv *challsrv.ChallSrv
}

func main() {
	httpOneBind := flag.String("http01", ":5002", "Bind address/port for HTTP-01 challenges. Set empty to disable.")
	dnsOneBind := flag.String("dns01", ":8053", "Bind address/port for DNS-01 challenges and fake DNS data. Set empty to disable.")
	managementBind := flag.String("management", ":8056", "Bind address/port for management HTTP interface")

	flag.Parse()

	go cmd.CatchSignals(nil, nil)

	srv, err := challsrv.New(challsrv.Config{
		HTTPOneAddr: *httpOneBind,
		DNSOneAddr:  *dnsOneBind,
	})
	cmd.FailOnError(err, "Unable to construct challenge server")
	srv.Run()

	fmt.Printf("Starting management server on %s\n", *managementBind)
	oobSrv := managementServer{
		Server: &http.Server{
			Addr: *managementBind,
		},
		challSrv: srv,
	}
	http.HandleFunc("/add-http01", oobSrv.addHTTP01)
	http.HandleFunc("/del-http01", oobSrv.delHTTP01)
	http.HandleFunc("/set-txt", oobSrv.addDNS01)
	http.HandleFunc("/clear-txt", oobSrv.delDNS01)
	if err := oobSrv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
