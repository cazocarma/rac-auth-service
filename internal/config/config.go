package config

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	KeycloakInternalURL string
	KeycloakPublicURL   string
	KeycloakRealm       string
	ClientID            string
	ClientSecret        string
	JWTInternalKey      string
	JWTIssuer           string
	JWTAudience         string

	// Admin (crear usuarios / roles)
	KcAdminClientID     string
	KcAdminClientSecret string
	KcAdminUser         string
	KcAdminPass         string

	// OAuth
	EnabledProviders []string
	OAuthStateTTL    int // seconds
	// Frontend callback base (para devolver desde broker si quisieras cerrar ventanas; opcional)
	FrontendBaseURL string
}

func Load() *Config {
	_ = godotenv.Load()
	cfg := &Config{
		KeycloakInternalURL: os.Getenv("KEYCLOAK_INTERNAL_URL"),
		KeycloakPublicURL:   os.Getenv("KEYCLOAK_PUBLIC_URL"),
		KeycloakRealm:       os.Getenv("KEYCLOAK_REALM"),
		ClientID:            os.Getenv("KEYCLOAK_CLIENT_ID"),
		ClientSecret:        os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		JWTInternalKey:      os.Getenv("JWT_INTERNAL_SECRET"),
		JWTIssuer:           os.Getenv("JWT_ISSUER"),
		JWTAudience:         os.Getenv("JWT_AUDIENCE"),
		KcAdminClientID:     os.Getenv("KC_ADMIN_CLIENT_ID"),
		KcAdminClientSecret: os.Getenv("KC_ADMIN_CLIENT_SECRET"),
		KcAdminUser:         os.Getenv("KC_ADMIN_USER"),
		KcAdminPass:         os.Getenv("KC_ADMIN_PASS"),
		FrontendBaseURL:     os.Getenv("FRONTEND_BASE_URL"),
	}
	if cfg.KeycloakInternalURL == "" || cfg.KeycloakPublicURL == "" || cfg.KeycloakRealm == "" {
		log.Fatal("❌ KEYCLOAK_INTERNAL_URL, KEYCLOAK_PUBLIC_URL y KEYCLOAK_REALM son obligatorias")
	}

	ttlStr := os.Getenv("OAUTH_STATE_TTL_SECONDS")
	if ttlStr == "" {
		cfg.OAuthStateTTL = 180
	} else {
		if n, err := strconv.Atoi(ttlStr); err == nil {
			cfg.OAuthStateTTL = n
		} else {
			cfg.OAuthStateTTL = 180
		}
	}

	provs := strings.TrimSpace(os.Getenv("OAUTH_ENABLED_PROVIDERS"))
	if provs != "" {
		cfg.EnabledProviders = strings.Split(provs, ",")
	}
	return cfg
}
