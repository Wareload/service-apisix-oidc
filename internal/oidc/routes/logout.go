package routes

import (
	"github.com/Wareload/service-apisix-oidc/internal/oidc/config"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/services/cookies"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/services/oidc"
	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"net/http"
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
