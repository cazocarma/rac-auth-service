package util

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SignInternalJWT firma un token JWT interno con clave simétrica.
func SignInternalJWT(secret, sub, issuer, audience string, ttl time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": sub,
		"iss": issuer,
		"aud": audience,
		"exp": time.Now().Add(ttl).Unix(),
		"iat": time.Now().Unix(),
	})
	return token.SignedString([]byte(secret))
}
