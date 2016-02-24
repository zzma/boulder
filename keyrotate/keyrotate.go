package main

import (
	"crypto"
	"crypto/x509"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
  "fmt"
	"io/ioutil"
	"log"

	"database/sql"
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/go-sql-driver/mysql"
	"github.com/square/go-jose"
)

var file = flag.String("file", "", "file to read key rotation request from")
var keyfile = flag.String("keyfile", "", "file to read old jwk from")
var dburi = flag.String("dburi", "", "url of db to connect to")
var regid = flag.Int("regid", 0, "id of registration to modify")

type rotateRequest struct {
	Key *jose.JsonWebKey
}

// KeyDigest produces a padded, standard Base64-encoded SHA256 digest of a
// provided public key.
func KeyDigest(key crypto.PublicKey) (string, error) {
	switch t := key.(type) {
	case *jose.JsonWebKey:
		if t == nil {
			return "", fmt.Errorf("Cannot compute digest of nil key")
		}
		return KeyDigest(t.Key)
	case jose.JsonWebKey:
		return KeyDigest(t.Key)
	default:
		keyDER, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return "", err
		}
		spkiDigest := sha256.Sum256(keyDER)
		return base64.StdEncoding.EncodeToString(spkiDigest[0:32]), nil
	}
}

func main() {
	flag.Parse()

	if *regid == 0 {
		log.Fatal("id must be set")
	}

	db, err := sql.Open("mysql", *dburi)
	if err != nil {
		log.Fatalf("dbconnect: %s", err)
	}
	if err = db.Ping(); err != nil {
		log.Fatalf("dbping: %s", err)
	}

	row := db.QueryRow("SELECT jwk FROM registrations where id = ?", *regid)

	var oldkeyString string
	err = row.Scan(&oldkeyString)
	if err != nil {
		log.Fatalf("reading old key: %s", err)
	}

	var oldkey jose.JsonWebKey
	err = json.Unmarshal([]byte(oldkeyString), &oldkey)
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

	sha, err := KeyDigest(rr.Key)
	if err != nil {
		log.Fatalf("digest: %s", err)
	}

	db.Exec("UPDATE registrations SET jwk = ?, jwk_sha256 = ? WHERE id = ?", newkeyBytes, sha, *regid)
}
