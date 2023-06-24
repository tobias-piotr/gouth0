package main

import (
	"os"
	"strings"
)

type AuthConfig struct {
	Domain     string
	Audience   string
	Algorithms []string
}

func ConfigFromEnv() *AuthConfig {
	algorithms := strings.Split(os.Getenv("AUTH_ALGORITHMS"), ",")
	return &AuthConfig{os.Getenv("AUTH_DOMAIN"), os.Getenv("AUTH_AUDIENCE"), algorithms}
}
