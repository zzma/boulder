package main

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/go-sql-driver/mysql"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
)

var file = flag.String("file", "", "file to read key rotation request from")
var dbconnectfile = flag.String("dbconnectfile", "", "path to file containing dbconnect string")
var regid = flag.Int("regid", 0, "id of registration to modify")

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

	dbconnect, err := ioutil.ReadFile(*dbconnectfile)
	if err != nil {
		log.Fatalf("read dbconnect string: %s", err)
	}

	db, err := sql.Open("mysql", strings.TrimSpace(string(dbconnect)))
	if err != nil {
		log.Fatalf("dbconnect: %s", err)
	}
	if err = db.Ping(); err != nil {
		log.Fatalf("dbping: %s", err)
	}

	row := db.QueryRow("SELECT jwk_sha256, jwk FROM registrations where id = ?", *regid)

	var oldkeyString, oldkeyHash string
	err = row.Scan(&oldkeyHash, &oldkeyString)
	if err != nil {
		log.Fatalf("reading old key: %s", err)
	}
	log.Printf("old: jwk_sha256 = '%s', jwk = '%s'", oldkeyHash, oldkeyString)

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
	var rotateRequest struct {
		Key *jose.JsonWebKey
	}
	err = json.Unmarshal(payload, &rotateRequest)
	if err != nil {
		log.Fatalf("unmarshal payload: %s", err)
	}
	newkeyBytes, err := json.Marshal(rotateRequest.Key)
	if err != nil {
		log.Fatalf("marshal newkey: %s", err)
	}
	log.Printf("Verified new key: %s", string(newkeyBytes))

	sha, err := KeyDigest(rotateRequest.Key)
	if err != nil {
		log.Fatalf("digest: %s", err)
	}

	_, err = db.Exec("UPDATE registrations SET jwk = ?, jwk_sha256 = ? WHERE id = ?", newkeyBytes, sha, *regid)
	if err != nil {
		log.Fatalf("update: %s", err)
	}
	log.Printf("Updated to new key successfully")
}
