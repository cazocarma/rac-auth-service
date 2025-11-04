import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// CORS mínimo
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Health
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "service": "rac-auth-service"})
	})

	// Fachada de Keycloak: endpoints mínimos de ejemplo
	api := r.Group("/api/auth")
	{
		api.POST("/login", Login)
		api.POST("/logout", Logout)
		api.POST("/refresh", Refresh)
		api.GET("/userinfo", UserInfo)
	}

	addr := ":8080"
	if v := os.Getenv("PORT"); v != "" {
		addr = ":" + v
	}
	log.Printf("auth service listening on %s", addr)
	_ = r.Run(addr)
}

// ==== Handlers mínimos (mock) ====

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid"})
		return
	}
	// TODO: intercambiar contra Keycloak (token endpoint)
	c.JSON(200, gin.H{"access_token": "mock", "refresh_token": "mock"})
}

func Logout(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) }
func Refresh(c *gin.Context) { c.JSON(200, gin.H{"access_token": "mock2"}) }
func UserInfo(c *gin.Context) { c.JSON(200, gin.H{"sub": "kc-user-id", "roles": []string{"cliente"}}) }