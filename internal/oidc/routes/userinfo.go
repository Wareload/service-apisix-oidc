package routes

import (
	"github.com/Wareload/service-apisix-oidc/internal/oidc/config"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/services/cookies"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/services/oidc"
	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"net/http"
)

func HandleUserinfo(config config.Conf, w http.ResponseWriter, r pkgHTTP.Request) {
	if r.Method() != "GET" {
		onMethodNotAllowed(w)
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
	wk, err := oidc.GetWellKnown(config)
	if err != nil {
		onServiceUnavailable(w, err)
		return
	}
	response, err := oidc.GetUserInfo(currentAccessToken, wk.UserinfoEP)
	if err != nil {
		onServiceUnavailable(w, err)
		return
	}
	_, err = w.Write([]byte(response))
	if err != nil {
		onInternalServerError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}
