package debian

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Checker checks that RSA key moduli aren't in the OpenSSL format
// weak key blacklists
type Checker struct {
	fingerprints map[[10]byte]struct{}
}

// NewChecker initializes a Checker from a set of blacklist files
func NewChecker(inputs []string) (*Checker, error) {
	c := &Checker{}
	for _, input := range inputs {
		in, err := os.Open(input)
		if err != nil {
			return nil, err
		}
		defer func() {
			_ = in.Close()
		}()

		scanner := bufio.NewScanner(in)
		for scanner.Scan() {
			l := scanner.Text()
			if strings.HasPrefix(l, "#") {
				continue
			}
			var bytes [10]byte
			_, err := hex.Decode(bytes[:], []byte(l))
			if err != nil {
				return nil, err
			}
			if len(bytes) != 10 {
				return nil, fmt.Errorf("Invalid hash length: %d", len(bytes))
			}
			c.fingerprints[bytes] = struct{}{}
		}
	}
	return c, nil
}

// Check checks that the lower 80 bits of the SHA1 hash of the modulus
// isn't in the map of truncated weak key fingerprints
func (c *Checker) Check(modBytes []byte) error {
	hashed := sha1.Sum(modBytes)
	var trunc [10]byte
	copy(trunc[:], hashed[10:20])
	if _, present := c.fingerprints[trunc]; present {
		return errors.New("Key modulus matches key in Debian/OpenSSL weak key list")
	}
	return nil
}
