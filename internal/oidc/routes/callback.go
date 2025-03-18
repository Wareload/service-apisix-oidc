package routes

import (
	"encoding/json"
	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"net/http"
	"service-apisix-oidc/internal/oidc/config"
	"service-apisix-oidc/internal/oidc/services/cookies"
	"service-apisix-oidc/internal/oidc/services/oidc"
)

func HandleCallback(config config.Conf, w http.ResponseWriter, r pkgHTTP.Request) {
	if r.Method() != "GET" {
		onMethodNotAllowed(w)
		return
	}
	queryParams := r.Args()
	state := queryParams.Get("state")
	iss := queryParams.Get("iss")
	code := queryParams.Get("code")
	cookies.DeleteCookie(w, config, cookies.AuthFlowCookieSuffix)
	wk, err := oidc.GetWellKnown(config)
	if err != nil {
		onServiceUnavailable(w)
		return
	}
	cookie, err := cookies.GetCookie(r, config, cookies.AuthFlowCookieSuffix)
	if err != nil {
		onUnauthorized(w, config)
		return
	}
	var authFlow cookies.AuthFlow
	err = json.Unmarshal([]byte(cookie), &authFlow)
	if err != nil {
		onUnauthorized(w, config)
		return
	}
	if state != authFlow.State || iss != wk.Issuer {
		onUnauthorized(w, config)
		return
	}
	token, err := oidc.ExchangeCodeForToken(config, wk, code)
	if err != nil {
		onServiceUnavailable(w)
		return
	}
	if !isNonceMatching(token.IdToken, authFlow.Nonce) {
		onUnauthorized(w, config)
		return
	}
	errAcc := cookies.SetCookie(w, config, token.AccessToken, cookies.AuthAccessCookieSuffix)
	errRf := cookies.SetCookie(w, config, token.RefreshToken, cookies.AuthRefreshCookieSuffix)
	if errAcc != nil || errRf != nil {
		onInternalServerError(w)
		return
	}
	onRedirect(w, config.GetPostLoginUrl())
}
