package http

import (
	"github.com/cazocarma/rac-auth-service/internal/config"
	"github.com/cazocarma/rac-auth-service/internal/service"

	"github.com/gin-gonic/gin"
)

func SetupRouter(r *gin.Engine, cfg *config.Config) {
	authSvc := service.NewAuthService(cfg)

	api := r.Group("/api/auth")
	{
		api.POST("/login", authSvc.Login)
		api.POST("/refresh", authSvc.Refresh)
		api.POST("/logout", authSvc.Logout)
		api.GET("/userinfo", authSvc.UserInfo)
	}

	// Healthcheck
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "service": "rac-auth-service"})
	})
}
