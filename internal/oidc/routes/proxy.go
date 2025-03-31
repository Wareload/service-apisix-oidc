package routes

import (
	"fmt"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/config"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/services/cookies"
	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"net/http"
)

func HandleProxy(config config.Conf, w http.ResponseWriter, r pkgHTTP.Request) {
	if r.Header().Get("Authorization") != "" {
		return
	}
	accessToken, errAcc := cookies.GetCookie(r, config, cookies.AuthAccessCookieSuffix)
	refreshToken, errRf := cookies.GetCookie(r, config, cookies.AuthRefreshCookieSuffix)
	if errAcc != nil || errRf != nil {
		onUnauthorized(w, config)
		return
	}
	err, currentAccessToken := updateTokensIfNeeded(w, config, accessToken, refreshToken)
	if err != nil {
		onUnauthorized(w, config)
		return
	}
	cookies.RemoveOwnCookiesFromHeader(r, config)
	r.Header().Set("Authorization", fmt.Sprintf("Bearer %s", currentAccessToken))
}
