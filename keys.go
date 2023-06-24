package main

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

func ExtractPublicKeyFromJWK(jwk map[string]string) (*rsa.PublicKey, error) {
	nStr := jwk["n"]
	eStr := jwk["e"]

	if nStr == "" || eStr == "" {
		return nil, fmt.Errorf("'n' or 'e' property not found in JWK")
	}

	// Decode the base64-encoded modulus and exponent values
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus 'n' from JWK: %v", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent 'e' from JWK: %v", err)
	}

	// Convert the modulus and exponent values to big integers
	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}
