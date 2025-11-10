package service

import (
	"net/http"

	"github.com/cazocarma/rac-auth-service/internal/model"
	"github.com/gin-gonic/gin"
)

func respondOK(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, model.OK(data))
}

func respondErr(c *gin.Context, status int, code, msg string, details interface{}) {
	c.JSON(status, model.Fail(code, msg, details))
}
