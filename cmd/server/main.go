package main

import (
	"fmt"
	"log"
	"os"

	"github.com/cazocarma/rac-auth-service/internal/config"
	"github.com/cazocarma/rac-auth-service/internal/http"

	"github.com/gin-gonic/gin"
)

func main() {
	// === Cargar configuración ===
	cfg := config.Load()

	// === Configurar modo Gin ===
	mode := os.Getenv("GIN_MODE")
	if mode == "" {
		gin.SetMode(gin.ReleaseMode) // por defecto en release
	} else {
		gin.SetMode(mode)
	}

	r := gin.New()
	r.Use(gin.Recovery())

	// === Seguridad básica ===
	// No confiar en proxies externos por defecto
	if err := r.SetTrustedProxies(nil); err != nil {
		log.Printf("⚠️ No se configuraron proxies de confianza: %v", err)
	}

	// === Configurar rutas ===
	http.SetupRouter(r, cfg)

	// === Determinar puerto dinámicamente ===
	port := os.Getenv("SERVICE_PORT")
	if port == "" {
		port = "8080"
	}
	addr := fmt.Sprintf(":%s", port)

	log.Printf("✅ rac-auth-service iniciado en %s (modo: %s)", addr, gin.Mode())

	// === Iniciar servidor ===
	if err := r.Run(addr); err != nil {
		log.Fatalf("❌ Error iniciando servidor: %v", err)
	}
}
