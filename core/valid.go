package core

import "errors"

const MaxJWKSize = 1024 // They are usually about 400 bytes, max seen: 714.

var ErrJWKTooLarge = errors.New("serialized JSON Web Key is too large to be handled by boulder")

func JWKSizeCheck(jwk []byte) error {
	if len(jwk) >= MaxJWKSize {
		return ErrJWKTooLarge
	}
	return nil
}
