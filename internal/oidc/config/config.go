package config

import (
	"fmt"
	"net/http"
	"strings"
)

type Conf struct {
	DiscoveryUrl  string     `json:"discovery_url" validate:"required,min=1"`
	Scope         string     `json:"scope" validate:"required,min=1"`
	ClientId      string     `json:"client_id"  validate:"required,min=1"`
	ClientSecret  string     `json:"client_secret"  validate:"required,min=1"`
	BaseUrl       string     `json:"base_url"  validate:"required,min=1"`
	LoginPath     string     `json:"login_path"  validate:"required,min=1"`
	LogoutPath    string     `json:"logout_path"  validate:"required,min=1"`
	CallbackPath  string     `json:"callback_path"  validate:"required,min=1"`
	UserinfoPath  string     `json:"userinfo_path"  validate:"required,min=1"`
	PostLogoutUrl string     `json:"post_logout_url"  validate:"required,min=1"`
	PostLoginUrl  string     `json:"post_login_url"  validate:"required,min=1"`
	Leeway        int        `json:"leeway"`
	Cookie        CookieConf `json:"cookie" validate:"required"`
}

func (s Conf) GetRedirectUrl() string {
	return fmt.Sprintf("%s%s", s.BaseUrl, s.CallbackPath)
}

func (s Conf) GetPostLoginUrl() string {
	return fmt.Sprintf("%s%s", s.BaseUrl, s.PostLoginUrl)
}

func (s Conf) GetPostLogoutUrl() string {
	return fmt.Sprintf("%s%s", s.BaseUrl, s.PostLogoutUrl)
}

func (s Conf) GetCookieSameSite() http.SameSite {
	switch strings.ToLower(s.Cookie.SameSite) {
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}

type CookieConf struct {
	Name     string `json:"name" validate:"required,min=1"`
	Path     string `json:"path" validate:"required,min=1"`
	Secure   bool   `json:"secure" validate:"required"`
	HttpOnly bool   `json:"http_only" validate:"required"`
	SameSite string `json:"same_site"`
	Secret   string `json:"secret" validate:"required,len=32"`
}

type WellKnown struct {
	Issuer          string `json:"issuer" validate:"required,min=1"`
	AuthorizationEP string `json:"authorization_endpoint" validate:"required,min=1"`
	TokenEP         string `json:"token_endpoint" validate:"required,min=1"`
	UserinfoEP      string `json:"userinfo_endpoint" validate:"required,min=1"`
	RevocationEP    string `json:"revocation_endpoint" validate:"required,min=1"`
}
