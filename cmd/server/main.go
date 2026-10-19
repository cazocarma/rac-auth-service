package main

import (
	"context"
	"github.com/cazocarma/rac-auth-service/internal/platform"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"os"
	"time"
)

func router(security *platform.Security) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	platform.Observe(r, "rac-auth-service")
	platform.Health(r, nil, func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, os.Getenv("OIDC_JWKS_URL"), nil)
		if err != nil {
			return err
		}
		res, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return http.ErrServerClosed
		}
		return nil
	})
	r.GET("/api/auth/userinfo", security.Require(), func(c *gin.Context) { c.JSON(200, platform.Principal(c)) })
	return r
}
func main() {
	port := os.Getenv("SERVICE_PORT")
	if port == "" {
		port = "8080"
	}
	log.Fatal(router(platform.FromEnvironment()).Run(":" + port))
}
