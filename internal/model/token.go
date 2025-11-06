package model

type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token,omitempty"`
	NotBeforePolicy  int64  `json:"not-before-policy,omitempty"`
	SessionState     string `json:"session_state,omitempty"`
	Scope            string `json:"scope,omitempty"`
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type UserInfoResponse struct {
	Sub               string                 `json:"sub"`
	EmailVerified     bool                   `json:"email_verified,omitempty"`
	Name              string                 `json:"name,omitempty"`
	PreferredUsername string                 `json:"preferred_username,omitempty"`
	Email             string                 `json:"email,omitempty"`
	RealmAccess       *RealmAccess           `json:"realm_access,omitempty"`
	ResourceAccess    map[string]ClientRoles `json:"resource_access,omitempty"`
}

type RealmAccess struct {
	Roles []string `json:"roles"`
}

type ClientRoles struct {
	Roles []string `json:"roles"`
}

type CombinedLoginResponse struct {
	Keycloak TokenResponse  `json:"keycloak"`
	Internal *InternalToken `json:"internal_jwt,omitempty"`
}

type InternalToken struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"`
	TokenType string `json:"token_type"`
	Iss       string `json:"iss,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Role      string `json:"role,omitempty"`
}
