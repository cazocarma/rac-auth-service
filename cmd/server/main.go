package main

import (
	"log"
	"os"

	"github.com/cazocarma/rac-auth-service/internal/config"
	"github.com/cazocarma/rac-auth-service/internal/http"

	"github.com/gin-gonic/gin"

	"time"

	"github.com/gin-contrib/cors"
)

func main() {
	cfg := config.Load()

	// Modo Gin
	mode := os.Getenv("GIN_MODE")
	if mode == "" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(mode)
	}

	r := gin.New()
	r.Use(gin.Logger()) // <— añade logger
	r.Use(gin.Recovery())

	// CORS (ajusta orígenes según tu frontend)
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost", "http://localhost:80", "http://localhost:8080"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	if err := r.SetTrustedProxies(nil); err != nil {
		log.Printf("⚠️ No se configuraron proxies de confianza: %v", err)
	}

	http.SetupRouter(r, cfg)

	port := os.Getenv("SERVICE_PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	log.Printf("✅ rac-auth-service iniciado en %s (modo: %s)", addr, gin.Mode())

	if err := r.Run(addr); err != nil {
		log.Fatalf("❌ Error iniciando servidor: %v", err)
	}
}
