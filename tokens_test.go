package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

type DummyClient struct {
	resp *http.Response
	err  error
}

func (c *DummyClient) Get(url string) (*http.Response, error) {
	return c.resp, c.err
}

func TestDecodeToken(t *testing.T) {
	// Generate RSA private key and encode modulus and exponent
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes())

	// Create a dummy HTTP client that returns a 200 OK response with the kid
	body := fmt.Sprintf(`{"keys": [{"kty": "RSA", "kid": "test", "n": "%s", "e": "%s"}]}`, n, e)
	resp := http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}
	client := DummyClient{resp: &resp}

	conf := AuthConfig{"", "", []string{"RS256"}}
	srv := NewTokenService(&conf, &client, 60)

	// Create a JWT token signed with the private key
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = "test"
	token.Claims.(jwt.MapClaims)["sub"] = "auth|1"
	tokenStr, _ := token.SignedString(privateKey)

	// Check that token was decoded, validated and contains the correct sub
	decoded, err := srv.DecodeToken(tokenStr)
	assert.Nil(t, err)
	assert.Equal(t, "auth|1", decoded["sub"])
}

func TestRefreshJWKs(t *testing.T) {
	// Create a dummy HTTP client that returns a 200 OK response with the kid
	body := `{"keys": [{"kty": "RSA", "kid": "test"}]}`
	resp := http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}
	client := DummyClient{resp: &resp}

	conf := AuthConfig{"", "", []string{"RS256"}}
	srv := NewTokenService(&conf, &client, 60)

	// Check that JWKs were assigned
	err := srv.RefreshJWKs()
	assert.Nil(t, err)
	assert.Equal(t, 1, len(srv.JWKs))

	// Check that JWKs were not refreshed
	client.err = fmt.Errorf("i wont be noticed")
	err = srv.RefreshJWKs()
	assert.Nil(t, err)
}

func TestGetJWK(t *testing.T) {
	srv := NewTokenService(&AuthConfig{"", "", []string{"RS256"}}, &DummyClient{}, 60)
	srv.JWKs = JWKs{{"kty": "RSA", "kid": "test1"}, {"kty": "RSA", "kid": "test2"}}

	assert.NotNil(t, srv.GetJWK("test1"))
	assert.Nil(t, srv.GetJWK("test3"))
}
