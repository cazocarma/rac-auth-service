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
		// unificados (envelope {ok,data,error})
		api.POST("/login", authSvc.Login)       // ROPC (dev) o password grant
		api.POST("/refresh", authSvc.Refresh)   // refresh token
		api.POST("/logout", authSvc.Logout)     // revoca/termina sesión
		api.GET("/userinfo", authSvc.UserInfo)  // datos de usuario
		api.POST("/register", authSvc.Register) // crea usuario + rol base (cliente o compa)
		// social (start -> callback -> consume)
		api.POST("/oauth/:provider/start", authSvc.OAuthStart)      // devuelve {auth_url, state}
		api.GET("/oauth/:provider/callback", authSvc.OAuthCallback) // manejada por KC broker -> backend
		api.POST("/oauth/:provider/consume", authSvc.OAuthConsume)  // frontend obtiene tokens con state
	}

	// Health
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true, "data": gin.H{"service": "rac-auth-service"}, "error": nil})
	})
}
