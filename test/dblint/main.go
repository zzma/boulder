package main

import (
	"flag"
	"log"

	"github.com/globalsign/certlint/asn1"
	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	_ "github.com/globalsign/certlint/checks/certificate/all"
	_ "github.com/globalsign/certlint/checks/extensions/all"
	"github.com/letsencrypt/boulder/sa"
)

func check(der []byte) error {
	al := new(asn1.Linter)
	errs := al.CheckStruct(der)
	if errs != nil {
		return errs.List()[0]
	}
	d, err := certdata.Load(der)
	if err != nil {
		return err
	}
	errs = checks.Certificate.Check(d)
	if errs != nil {
		return errs.List()[0]
	}
	return nil
}

func main() {
	dbURLFlag := flag.String("db", "", "URL of database")
	flag.Parse()

	dbMap, err := sa.NewDbMap(*dbURLFlag, 1)
	if err != nil {
		log.Fatal(err)
	}

	defer rows.Close()
	for rows.Next() {
		var der []byte
		err = rows.Scan(&der)
		if err != nil {
			log.Fatal(err)
		}
		check(der)
	}
}
