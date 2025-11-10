package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cazocarma/rac-auth-service/internal/config"
	"github.com/cazocarma/rac-auth-service/internal/model"
	"github.com/cazocarma/rac-auth-service/internal/util"

	"github.com/gin-gonic/gin"
)

// =======================
// AuthService
// =======================

type AuthService struct {
	cfg        *config.Config
	httpClient *http.Client

	oauthStore *oauthStateStore
}

func NewAuthService(cfg *config.Config) *AuthService {
    ttl := time.Duration(cfg.OAuthStateTTL) * time.Second
    if ttl <= 0 {
        ttl = 5 * time.Minute
    }
    return &AuthService{
        cfg: cfg,
        httpClient: &http.Client{
            Timeout: 15 * time.Second,
        },
        oauthStore: newOAuthStateStore(ttl),
    }
}

// =======================
// URL helpers (KC)
// =======================

func (s *AuthService) kcInternal(path string) string {
	// para llamadas servidor→servidor (token, refresh, logout, userinfo, admin)
	return fmt.Sprintf("%s/realms/%s%s", s.cfg.KeycloakInternalURL, s.cfg.KeycloakRealm, path)
}

func (s *AuthService) kcPublic(path string) string {
	// para URLs que verá el navegador (broker/social)
	return fmt.Sprintf("%s/realms/%s%s", s.cfg.KeycloakPublicURL, s.cfg.KeycloakRealm, path)
}

func (s *AuthService) kcAdmin(path string) string {
	// Admin REST (server→server)
	return fmt.Sprintf("%s/admin/realms/%s%s", s.cfg.KeycloakInternalURL, s.cfg.KeycloakRealm, path)
}

// =======================
// HTTP helpers (KC)
// =======================

func (s *AuthService) postForm(ctx context.Context, endpoint string, form url.Values, hdr http.Header) (int, []byte, error) {
	bodyStr := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(bodyStr))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdr {
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, nil
}

func (s *AuthService) get(ctx context.Context, endpoint string, hdr http.Header) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range hdr {
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, nil
}

func (s *AuthService) postJSON(ctx context.Context, endpoint string, payload any, hdr http.Header) (int, []byte, error) {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(b)))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, nil
}

func (s *AuthService) putJSON(ctx context.Context, endpoint string, payload any, hdr http.Header) (int, []byte, error) {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, strings.NewReader(string(b)))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, nil
}

// =======================
// DTOs
// =======================

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"` // "cliente" | "compa"
}

type oauthStartResp struct {
	AuthURL string `json:"auth_url"`
	State   string `json:"state"`
}

// =======================
// ROPC / token endpoints
// =======================

func (s *AuthService) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondErr(c, http.StatusBadRequest, "AUTH.BAD_REQUEST", "Datos inválidos", nil)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Password = strings.TrimSpace(req.Password)
	if req.Username == "" || req.Password == "" {
		respondErr(c, http.StatusBadRequest, "AUTH.REQUIRED", "username/password requeridos", nil)
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

	status, body, err := s.postForm(ctx, s.kcInternal("/protocol/openid-connect/token"), form, nil)
	if err != nil {
		respondErr(c, http.StatusBadGateway, "AUTH.KC_UNREACHABLE", "Error conectando con Keycloak", err.Error())
		return
	}
	if status != http.StatusOK {
		var errResp model.ErrorResponse
		_ = json.Unmarshal(body, &errResp)
		code := "AUTH.INVALID_CREDENTIALS"
		msg := "Invalid client or Invalid client credentials"
		if errResp.Error != "" {
			msg = errResp.ErrorDescription
		}
		respondErr(c, http.StatusUnauthorized, code, msg, string(body))
		return
	}

	var tokenResp model.TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		respondErr(c, http.StatusInternalServerError, "AUTH.PARSE_ERROR", "Error parseando respuesta Keycloak", err.Error())
		return
	}

	internal, _ := util.SignInternalJWT(s.cfg.JWTInternalKey, req.Username, s.cfg.JWTIssuer, s.cfg.JWTAudience, 24*time.Hour)
	out := model.CombinedLoginResponse{Keycloak: tokenResp}
	if internal != "" {
		out.Internal = &model.InternalToken{
			Token:     internal,
			TokenType: "Bearer",
			ExpiresIn: int64((24 * time.Hour) / time.Second),
			Iss:       s.cfg.JWTIssuer,
			Aud:       s.cfg.JWTAudience,
			Sub:       req.Username,
		}
	}
	respondOK(c, out)
}

func (s *AuthService) Refresh(c *gin.Context) {
	var data struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&data); err != nil || strings.TrimSpace(data.RefreshToken) == "" {
		respondErr(c, http.StatusBadRequest, "AUTH.BAD_REQUEST", "refresh_token requerido", nil)
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

	status, body, err := s.postForm(ctx, s.kcInternal("/protocol/openid-connect/token"), form, nil)
	if err != nil {
		respondErr(c, http.StatusBadGateway, "AUTH.KC_UNREACHABLE", err.Error(), nil)
		return
	}
	if status != http.StatusOK {
		respondErr(c, status, "AUTH.REFRESH_FAILED", "No se pudo refrescar token", string(body))
		return
	}

	var tokenResp model.TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		respondErr(c, http.StatusInternalServerError, "AUTH.PARSE_ERROR", "Error parseando respuesta Keycloak", err.Error())
		return
	}
	respondOK(c, tokenResp)
}

func (s *AuthService) Logout(c *gin.Context) {
	var data struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&data); err != nil || strings.TrimSpace(data.RefreshToken) == "" {
		respondErr(c, http.StatusBadRequest, "AUTH.BAD_REQUEST", "refresh_token requerido", nil)
		return
	}

	form := url.Values{}
	form.Set("client_id", s.cfg.ClientID)
	if s.cfg.ClientSecret != "" {
		form.Set("client_secret", s.cfg.ClientSecret)
	}
	form.Set("refresh_token", data.RefreshToken)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	status, body, err := s.postForm(ctx, s.kcInternal("/protocol/openid-connect/logout"), form, nil)
	if err != nil {
		respondErr(c, http.StatusBadGateway, "AUTH.KC_UNREACHABLE", err.Error(), nil)
		return
	}
	if status >= 200 && status < 300 {
		respondOK(c, gin.H{"revoked": true})
		return
	}
	respondErr(c, status, "AUTH.LOGOUT_FAILED", "No se pudo cerrar sesión", string(body))
}

func (s *AuthService) UserInfo(c *gin.Context) {
	auth := c.GetHeader("Authorization")
	if strings.TrimSpace(auth) == "" {
		respondErr(c, http.StatusUnauthorized, "AUTH.TOKEN_REQUIRED", "token requerido", nil)
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	status, body, err := s.get(ctx, s.kcInternal("/protocol/openid-connect/userinfo"), http.Header{"Authorization": []string{auth}})
	if err != nil {
		respondErr(c, http.StatusBadGateway, "AUTH.KC_UNREACHABLE", err.Error(), nil)
		return
	}
	if status != http.StatusOK {
		respondErr(c, status, "AUTH.USERINFO_FAILED", "No se pudo obtener userinfo", string(body))
		return
	}

	var info model.UserInfoResponse
	if err := json.Unmarshal(body, &info); err != nil {
		// Devolver tal cual si el shape cambia
		respondOK(c, json.RawMessage(body))
		return
	}
	respondOK(c, info)
}

// =======================
// Register (Admin REST)
// =======================

func (s *AuthService) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondErr(c, http.StatusBadRequest, "AUTH.BAD_REQUEST", "payload inválido", nil)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	req.Password = strings.TrimSpace(req.Password)
	req.Role = strings.TrimSpace(req.Role)
	if req.Username == "" || req.Email == "" || req.Password == "" {
		respondErr(c, http.StatusBadRequest, "AUTH.REQUIRED", "username/email/password requeridos", nil)
		return
	}
	if req.Role == "" {
		req.Role = "cliente"
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()

	// 1) Obtener admin token via client_credentials (service account del cliente configurado)
	adminTok, err := s.clientCredentialsToken(ctx)
	if err != nil {
		respondErr(c, http.StatusBadGateway, "AUTH.ADMIN_TOKEN_FAILED", "No se pudo obtener token administrativo", err.Error())
		return
	}

	// 2) Crear usuario
	createPayload := map[string]any{
		"username":      req.Username,
		"email":         req.Email,
		"enabled":       true,
		"emailVerified": true,
		"attributes":    map[string][]string{},
	}
	status, body, err := s.postJSON(ctx, s.kcAdmin("/users"), createPayload, http.Header{"Authorization": []string{"Bearer " + adminTok}})
	if err != nil {
		respondErr(c, http.StatusBadGateway, "AUTH.USER_CREATE_FAILED", "Error conectando a KC Admin", err.Error())
		return
	}
	if status != http.StatusCreated && status != http.StatusNoContent {
		respondErr(c, status, "AUTH.USER_CREATE_FAILED", "KC no creó el usuario", string(body))
		return
	}

	// 3) Buscar ID del usuario recién creado
	getStatus, usersBody, err := s.get(ctx, s.kcAdmin("/users?exact=true&username="+url.QueryEscape(req.Username)), http.Header{"Authorization": []string{"Bearer " + adminTok}})
	if err != nil || getStatus != http.StatusOK {
		respondErr(c, http.StatusBadGateway, "AUTH.USER_LOOKUP_FAILED", "No se pudo obtener ID del usuario", map[string]any{"status": getStatus, "err": fmt.Sprint(err), "body": string(usersBody)})
		return
	}
	var usersFound []struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(usersBody, &usersFound)
	if len(usersFound) == 0 || usersFound[0].ID == "" {
		respondErr(c, http.StatusInternalServerError, "AUTH.USER_LOOKUP_EMPTY", "KC no devolvió ID", string(usersBody))
		return
	}
	uid := usersFound[0].ID

	// 4) Setear password
	passPayload := map[string]any{"type": "password", "value": req.Password, "temporary": false}
	putStatus, putBody, err := s.putJSON(ctx, s.kcAdmin("/users/"+uid+"/reset-password"), passPayload, http.Header{"Authorization": []string{"Bearer " + adminTok}})
	if err != nil || (putStatus != http.StatusNoContent && putStatus != http.StatusOK) {
		respondErr(c, http.StatusBadGateway, "AUTH.PASS_SET_FAILED", "No se pudo setear password", map[string]any{"status": putStatus, "err": fmt.Sprint(err), "body": string(putBody)})
		return
	}

	// 5) Asignar rol de realm (cliente/compa/admin)
	if err := s.assignRealmRole(ctx, adminTok, uid, req.Role); err != nil {
		respondErr(c, http.StatusBadGateway, "AUTH.ROLE_ASSIGN_FAILED", "No se pudo asignar rol", err.Error())
		return
	}

	respondOK(c, gin.H{"created": true, "user_id": uid, "role": req.Role})
}

func (s *AuthService) clientCredentialsToken(ctx context.Context) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", s.cfg.ClientID)
	if s.cfg.ClientSecret != "" {
		form.Set("client_secret", s.cfg.ClientSecret)
	}
	status, body, err := s.postForm(ctx, s.kcInternal("/protocol/openid-connect/token"), form, nil)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("kc token cc failed: %s", string(body))
	}
	var tr model.TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", err
	}
	return tr.AccessToken, nil
}

func (s *AuthService) assignRealmRole(ctx context.Context, adminToken, userID, roleName string) error {
	// 1) obtener rol
	status, body, err := s.get(ctx, s.kcAdmin("/roles/"+url.PathEscape(roleName)), http.Header{"Authorization": []string{"Bearer " + adminToken}})
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("get role failed: %v (%d) %s", err, status, string(body))
	}
	var role struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &role); err != nil {
		return err
	}
	// 2) asignar al usuario
	payload := []map[string]string{{"id": role.ID, "name": role.Name}}
	postStatus, postBody, err := s.postJSON(ctx, s.kcAdmin("/users/"+userID+"/role-mappings/realm"), payload, http.Header{"Authorization": []string{"Bearer " + adminToken}})
	if err != nil || (postStatus != http.StatusNoContent && postStatus != http.StatusOK) {
		return fmt.Errorf("assign role failed: %v (%d) %s", err, postStatus, string(postBody))
	}
	return nil
}

// =======================
// OAuth Social (Broker)
// start -> callback -> consume
// =======================

func (s *AuthService) OAuthStart(c *gin.Context) {
    provider := strings.ToLower(strings.TrimSpace(c.Param("provider")))
    if provider == "" {
        respondErr(c, http.StatusBadRequest, "OAUTH.PROVIDER_REQUIRED", "provider requerido", nil)
        return
    }

    if len(s.cfg.EnabledProviders) > 0 {
        allowed := false
        for _, p := range s.cfg.EnabledProviders {
            if strings.ToLower(strings.TrimSpace(p)) == provider {
                allowed = true
                break
            }
        }
        if !allowed {
            respondErr(c, http.StatusBadRequest, "OAUTH.PROVIDER_DISABLED", "provider no habilitado", nil)
            return
        }
    }

	state := randomState(24)
	redirectURI := s.publicCallbackURL(c, provider)
	log.Printf("oauth_start provider=%s state=%s frontend_base=%s xfp=%s xfh=%s host=%s redirect_uri=%s",
		provider,
		state,
		strings.TrimSpace(s.cfg.FrontendBaseURL),
		c.Request.Header.Get("X-Forwarded-Proto"),
		c.Request.Header.Get("X-Forwarded-Host"),
		c.Request.Host,
		redirectURI,
	)

	// KC broker login url:
	// /realms/{realm}/broker/{provider}/login?client_id=<client>&redirect_uri=<encoded>
	q := url.Values{}
	q.Set("client_id", s.cfg.ClientID) // el client que tiene registrado el redirect hacia nuestro callback
	q.Set("redirect_uri", redirectURI) // DEBE coincidir exactamente con Valid Redirect URIs del client
	authURL := s.kcPublic(fmt.Sprintf("/broker/%s/login?%s", provider, q.Encode()))
	log.Printf("oauth_start auth_url=%s", authURL)

	// guarda estado en memoria
	s.oauthStore.Put(state, oauthState{
		Provider:    provider,
		RedirectURI: redirectURI,
		CreatedAt:   time.Now(),
	})

	respondOK(c, oauthStartResp{AuthURL: authURL, State: state})
}

func (s *AuthService) OAuthCallback(c *gin.Context) {
    provider := strings.ToLower(strings.TrimSpace(c.Param("provider")))
    code := c.Query("code")
    state := c.Query("state")

    redactedCode := ""
    if len(code) > 8 {
        redactedCode = code[:4] + "..." + code[len(code)-4:]
    } else if code != "" {
        redactedCode = "len=" + fmt.Sprint(len(code))
    }
    log.Printf("oauth_callback provider=%s state=%s code=%s", provider, state, redactedCode)

	if provider == "" || code == "" || state == "" {
		respondErr(c, http.StatusBadRequest, "OAUTH.CALLBACK_INVALID", "provider/state/code requeridos", nil)
		return
	}

	st, ok := s.oauthStore.Get(state)
	if !ok || st.Provider != provider {
		respondErr(c, http.StatusBadRequest, "OAUTH.STATE_INVALID", "state inválido o expirado", nil)
		return
	}

	// persistimos el authorization code para que el frontend lo consuma después
	st.Code = code
	s.oauthStore.Put(state, st)

	// Respuesta mínima “humana” (por si abres en nueva pestaña)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(`
<!doctype html>
<meta charset="utf-8"/>
<title>Login OK</title>
<p>Autenticación realizada. Puedes cerrar esta ventana.</p>
`))
}

func (s *AuthService) OAuthConsume(c *gin.Context) {
	var data struct {
		State string `json:"state"`
	}
	if err := c.ShouldBindJSON(&data); err != nil || strings.TrimSpace(data.State) == "" {
		respondErr(c, http.StatusBadRequest, "OAUTH.STATE_REQUIRED", "state requerido", nil)
		return
	}

	st, ok := s.oauthStore.Get(data.State)
	if !ok || st.Code == "" {
		respondErr(c, http.StatusBadRequest, "OAUTH.STATE_INVALID", "state inválido o sin code", nil)
		return
	}

	// Intercambiar authorization_code por tokens en KC (URL interna)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", st.Code)
	form.Set("client_id", s.cfg.ClientID)
	if s.cfg.ClientSecret != "" {
		form.Set("client_secret", s.cfg.ClientSecret)
	}
	// IMPORTANTÍSIMO: redirect_uri debe ser **exactamente** el mismo que en /start
	form.Set("redirect_uri", st.RedirectURI)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	status, body, err := s.postForm(ctx, s.kcInternal("/protocol/openid-connect/token"), form, nil)
	if err != nil {
		respondErr(c, http.StatusBadGateway, "OAUTH.EXCHANGE_FAILED", "No se pudo contactar a KC", err.Error())
		return
	}
	if status != http.StatusOK {
		log.Printf("oauth_consume exchange_failed status=%d body=%s", status, string(body))
		respondErr(c, status, "OAUTH.EXCHANGE_FAILED", "KC rechazó el code", string(body))
		return
	}

	var tokenResp model.TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		respondErr(c, http.StatusInternalServerError, "OAUTH.PARSE_ERROR", "Error parseando tokens", err.Error())
		return
	}

	// opcional: emitir JWT interno
	internal, _ := util.SignInternalJWT(s.cfg.JWTInternalKey, "social-login", s.cfg.JWTIssuer, s.cfg.JWTAudience, 24*time.Hour)
	out := model.CombinedLoginResponse{Keycloak: tokenResp}
	if internal != "" {
		out.Internal = &model.InternalToken{
			Token:     internal,
			TokenType: "Bearer",
			ExpiresIn: int64((24 * time.Hour) / time.Second),
			Iss:       s.cfg.JWTIssuer,
			Aud:       s.cfg.JWTAudience,
			Sub:       "social-login",
		}
	}

	// invalidar el state para un solo uso
	s.oauthStore.Delete(data.State)

	respondOK(c, out)
}

// =======================
// OAuth in-memory store
// =======================

type oauthState struct {
	Provider    string
	Code        string
	RedirectURI string
	CreatedAt   time.Time
}

type oauthStateStore struct {
	ttl  time.Duration
	data sync.Map // state -> oauthState
	quit chan struct{}
	once sync.Once
}

func newOAuthStateStore(ttl time.Duration) *oauthStateStore {
	s := &oauthStateStore{ttl: ttl, quit: make(chan struct{})}
	go s.gc()
	return s
}

func (s *oauthStateStore) Put(state string, v oauthState) {
	s.data.Store(state, v)
}

func (s *oauthStateStore) Get(state string) (oauthState, bool) {
	if val, ok := s.data.Load(state); ok {
		v := val.(oauthState)
		if time.Since(v.CreatedAt) <= s.ttl {
			return v, true
		}
		s.data.Delete(state)
	}
	return oauthState{}, false
}

func (s *oauthStateStore) Delete(state string) {
	s.data.Delete(state)
}

func (s *oauthStateStore) gc() {
	ticker := time.NewTicker(s.ttl / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.data.Range(func(key, val any) bool {
				v := val.(oauthState)
				if now.Sub(v.CreatedAt) > s.ttl {
					s.data.Delete(key)
				}
				return true
			})
		case <-s.quit:
			return
		}
	}
}

// =======================
// Utils
// =======================

func randomState(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// publicCallbackURL construye el callback absoluto (público) hacia nosotros mismos
// p.ej. http(s)://<host>/api/auth/oauth/<provider>/callback
func (s *AuthService) publicCallbackURL(c *gin.Context, provider string) string {
    // Preferir base pública configurada (estable para el navegador)
    if strings.TrimSpace(s.cfg.FrontendBaseURL) != "" {
        base := strings.TrimRight(strings.TrimSpace(s.cfg.FrontendBaseURL), "/")
        cb := fmt.Sprintf("%s/api/auth/oauth/%s/callback", base, provider)
        log.Printf("public_callback using_frontend_base base=%s callback=%s", base, cb)
        return cb
    }

    // Fallback: inferir desde encabezados/proxy o conexión
    scheme := c.Request.Header.Get("X-Forwarded-Proto")
    if scheme == "" {
        if c.Request.TLS != nil {
            scheme = "https"
        } else {
            scheme = "http"
        }
    }
    host := c.Request.Header.Get("X-Forwarded-Host")
    if host == "" {
        host = c.Request.Host
    }
    base := fmt.Sprintf("%s://%s", scheme, host)
    cb := fmt.Sprintf("%s/api/auth/oauth/%s/callback", base, provider)
    log.Printf("public_callback inferred_base scheme=%s host=%s callback=%s", scheme, host, cb)
    return cb
}

// =======================
// Guard rails
// =======================

var errNotImplemented = errors.New("not implemented")
