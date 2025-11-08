package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cazocarma/rac-auth-service/internal/config"
	"github.com/cazocarma/rac-auth-service/internal/model"
	"github.com/cazocarma/rac-auth-service/internal/util"

	"github.com/gin-gonic/gin"
)

type AuthService struct {
	cfg        *config.Config
	httpClient *http.Client
}

func NewAuthService(cfg *config.Config) *AuthService {
	return &AuthService{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ---- helpers ----

func (s *AuthService) kcURL(path string) string {
	// path: e.g. "/protocol/openid-connect/token"
	return fmt.Sprintf("%s/realms/%s%s", s.cfg.KeycloakURL, s.cfg.KeycloakRealm, path)
}

func (s *AuthService) postForm(ctx context.Context, endpoint string, form url.Values) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, nil
}

// ---- handlers ----

func (s *AuthService) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Datos inválidos"})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Password = strings.TrimSpace(req.Password)
	if req.Username == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username/password requeridos"})
		return
	}

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", s.cfg.ClientID)
	if s.cfg.ClientSecret != "" {
		form.Set("client_secret", s.cfg.ClientSecret)
	}
	form.Set("username", req.Username)
	form.Set("password", req.Password)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	status, body, err := s.postForm(ctx, s.kcURL("/protocol/openid-connect/token"), form)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "Error conectando con Keycloak"})
		return
	}
	if status != http.StatusOK {
		var errResp model.ErrorResponse
		_ = json.Unmarshal(body, &errResp)
		if errResp.Error == "" {
			c.Data(status, "application/json", body)
			return
		}
		c.JSON(status, errResp)
		return
	}

	var tokenResp model.TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error parseando respuesta Keycloak"})
		return
	}

	// Generar JWT interno opcional
	internal, err := util.SignInternalJWT(s.cfg.JWTInternalKey, req.Username, s.cfg.JWTIssuer, s.cfg.JWTAudience, 24*time.Hour)
	if err != nil {
		internal = ""
	}

	var result model.CombinedLoginResponse
	result.Keycloak = tokenResp
	if internal != "" {
		result.Internal = &model.InternalToken{
			Token:     internal,
			TokenType: "Bearer",
			ExpiresIn: int64((24 * time.Hour) / time.Second),
			Iss:       s.cfg.JWTIssuer,
			Aud:       s.cfg.JWTAudience,
			Sub:       req.Username,
		}
	}

	c.JSON(http.StatusOK, result)
}

func (s *AuthService) Refresh(c *gin.Context) {
	var data struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&data); err != nil || strings.TrimSpace(data.RefreshToken) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "refresh_token requerido"})
		return
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", data.RefreshToken)
	form.Set("client_id", s.cfg.ClientID)
	if s.cfg.ClientSecret != "" {
		form.Set("client_secret", s.cfg.ClientSecret)
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	status, body, err := s.postForm(ctx, s.kcURL("/protocol/openid-connect/token"), form)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if status != http.StatusOK {
		c.Data(status, "application/json", body)
		return
	}

	var tokenResp model.TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error parseando respuesta Keycloak"})
		return
	}

	c.JSON(http.StatusOK, tokenResp)
}

func (s *AuthService) Logout(c *gin.Context) {
	var data struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&data); err != nil || strings.TrimSpace(data.RefreshToken) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "refresh_token requerido"})
		return
	}

	form := url.Values{}
	form.Set("client_id", s.cfg.ClientID)
	if s.cfg.ClientSecret != "" {
		form.Set("client_secret", s.cfg.ClientSecret)
	}
	// Con Keycloak 24, el logout por OIDC soporta refresh_token
	form.Set("refresh_token", data.RefreshToken)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	status, body, err := s.postForm(ctx, s.kcURL("/protocol/openid-connect/logout"), form)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	// Keycloak suele devolver 204/200
	if status >= 200 && status < 300 {
		c.Status(status)
		return
	}

	// Propaga cualquier error como lo envía KC
	c.Data(status, "application/json", body)
}

func (s *AuthService) UserInfo(c *gin.Context) {
	auth := c.GetHeader("Authorization")
	if strings.TrimSpace(auth) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token requerido"})
		return
	}

	req, _ := http.NewRequestWithContext(
		c.Request.Context(),
		http.MethodGet,
		s.kcURL("/protocol/openid-connect/userinfo"),
		nil,
	)
	req.Header.Set("Authorization", auth)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		c.Data(resp.StatusCode, "application/json", body)
		return
	}

	var info model.UserInfoResponse
	if err := json.Unmarshal(body, &info); err != nil {
		// Si KC cambia shape, devuelve tal cual
		c.Data(http.StatusOK, "application/json", body)
		return
	}

	c.JSON(http.StatusOK, info)
}
