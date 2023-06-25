package gouth0

import (
	"encoding/json"
	"fmt"
	"time"

	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

type JWK map[string]string
type JWKs []JWK
type DecodedToken map[string]interface{}

type HTTPClient interface {
	Get(url string) (*http.Response, error)
}

type TokenService struct {
	Conf            *AuthConfig
	Client          HTTPClient
	JWKs            JWKs
	JWKsRefreshTime time.Time
	JWKsRefreshRate int // Seconds
}

func NewTokenService(config *AuthConfig, client HTTPClient, refreshRate int) *TokenService {
	return &TokenService{config, client, JWKs{}, time.Now(), refreshRate}
}

func (s *TokenService) DecodeToken(t string) (DecodedToken, error) {
	decoded, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		// Validate algorithm
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Refresh jwks if needed
		err := s.RefreshJWKs()
		if err != nil {
			return nil, err
		}
		// Get jwk for kid
		jwk := s.GetJWK(token.Header["kid"].(string))
		if jwk == nil {
			return nil, fmt.Errorf("jwk not found for kid: %v", token.Header["kid"])
		}

		// Extract public key from jwk
		return ExtractPublicKeyFromJWK(jwk)
	})
	if err != nil {
		return nil, err
	}
	return DecodedToken(decoded.Claims.(jwt.MapClaims)), err
}

func (s *TokenService) RefreshJWKs() error {
	if time.Now().Before(s.JWKsRefreshTime) {
		return nil
	}

	// Request jwks
	url := fmt.Sprintf("https://%s/%s", s.Conf.Domain, ".well-known/jwks.json")
	resp, err := s.Client.Get(url)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("wrong response when fetching jwks: %s", resp.Status)
	}

	// Read response
	defer resp.Body.Close()
	data := map[string]JWKs{}
	json.NewDecoder(resp.Body).Decode(&data)

	s.JWKs = data["keys"]
	s.JWKsRefreshTime = time.Now().Add(time.Duration(s.JWKsRefreshRate) * time.Second)
	return nil
}

func (s TokenService) GetJWK(kid string) JWK {
	var jwk JWK
	for _, jwk := range s.JWKs {
		if jwk["kid"] == kid {
			return jwk
		}
	}
	return jwk
}
