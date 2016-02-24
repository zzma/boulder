package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"

	"github.com/square/go-jose"
)

var file = flag.String("file", "", "file to read key rotation request from")
var keyfile = flag.String("keyfile", "", "file to read old jwk from")

type rotateRequest struct {
  Key *jose.JsonWebKey
}

func main() {
	flag.Parse()
	oldkeyBytes, err := ioutil.ReadFile(*keyfile)
	if err != nil {
		log.Fatal(err)
	}
	var oldkey jose.JsonWebKey
	err = json.Unmarshal(oldkeyBytes, &oldkey)
	if err != nil {
		log.Fatalf("unmarshal old key: %s", err)
	}
	body, err := ioutil.ReadFile(*file)
	if err != nil {
		log.Fatalf("read %s: %s", *file, err)
	}
	parsedJws, err := jose.ParseSigned(string(body))
	if err != nil {
		log.Fatalf("ParseSigned: %s", err)
	}

	payload, err := parsedJws.Verify(&oldkey)
	if err != nil {
		log.Fatalf("verify: %s", err)
	}
  var rr rotateRequest
  err = json.Unmarshal(payload, &rr)
  if err != nil {
    log.Fatalf("unmarshal payload: %s", err)
  }
  newkeyBytes, err := json.Marshal(rr.Key)
  if err != nil {
    log.Fatalf("marshal newkey: %s", err)
  }
  log.Printf("Verified new key: %s", string(newkeyBytes))
}
