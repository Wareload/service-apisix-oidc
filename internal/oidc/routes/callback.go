package routes

import (
	"encoding/json"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/config"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/services/cookies"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/services/oidc"
	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"github.com/apache/apisix-go-plugin-runner/pkg/log"
	"net/http"
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
		onServiceUnavailable(w, err)
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
		onServiceUnavailable(w, err)
		return
	}
	if !isNonceMatching(token.IdToken, authFlow.Nonce) {
		onUnauthorized(w, config)
		return
	}
	errAcc := cookies.SetCookie(w, config, token.AccessToken, cookies.AuthAccessCookieSuffix)
	errRf := cookies.SetCookie(w, config, token.RefreshToken, cookies.AuthRefreshCookieSuffix)
	if errAcc != nil || errRf != nil {
		log.Errorf("Failed to set cookies: %v, %v", errAcc, errRf)
		onInternalServerError(w, err)
		return
	}
	onRedirect(w, config.GetPostLoginUrl())
}
