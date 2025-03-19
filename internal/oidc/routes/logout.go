package routes

import (
	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"net/http"
	"service-apisix-oidc/internal/oidc/config"
	"service-apisix-oidc/internal/oidc/services/cookies"
	"service-apisix-oidc/internal/oidc/services/oidc"
)

func HandleLogout(config config.Conf, w http.ResponseWriter, r pkgHTTP.Request) {
	if r.Method() != "GET" && r.Method() != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	refreshToken, err := cookies.GetCookie(r, config, cookies.AuthRefreshCookieSuffix)
	cookies.DeleteCookies(w, config)
	if err != nil {
		onRedirect(w, config.PostLogoutUrl)
		return
	}
	_ = oidc.RevokeTokens(refreshToken, config)
	onRedirect(w, config.PostLogoutUrl)
}
