package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	KeycloakURL    string
	KeycloakRealm  string
	ClientID       string
	ClientSecret   string
	JWTInternalKey string
	JWTIssuer      string
	JWTAudience    string
}

func Load() *Config {
	_ = godotenv.Load()
	cfg := &Config{
		KeycloakURL:    os.Getenv("KEYCLOAK_URL"),
		KeycloakRealm:  os.Getenv("KEYCLOAK_REALM"),
		ClientID:       os.Getenv("KEYCLOAK_CLIENT_ID"),
		ClientSecret:   os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		JWTInternalKey: os.Getenv("JWT_INTERNAL_SECRET"),
		JWTIssuer:      os.Getenv("JWT_ISSUER"),
		JWTAudience:    os.Getenv("JWT_AUDIENCE"),
	}
	if cfg.KeycloakURL == "" || cfg.KeycloakRealm == "" {
		log.Fatal("❌ Variables Keycloak no configuradas correctamente")
	}
	return cfg
}
