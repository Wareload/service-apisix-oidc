package routes

import (
	"encoding/json"
	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"net/http"
	"service-apisix-oidc/internal/oidc/config"
	"service-apisix-oidc/internal/oidc/services/cookies"
	"service-apisix-oidc/internal/oidc/services/oidc"
)

func HandleLogin(config config.Conf, w http.ResponseWriter, r pkgHTTP.Request) {
	cookies.DeleteCookies(w, config)
	if r.Method() != "GET" {
		onMethodNotAllowed(w)
		return
	}
	wk, err := oidc.GetWellKnown(config)
	if err != nil {
		onServiceUnavailable(w, err)
		return
	}
	loginUrl, state, nonce, err := oidc.GenerateLoginURL(wk.AuthorizationEP, config.ClientId, config.Scope, config.GetRedirectUrl())
	if err != nil {
		onInternalServerError(w, err)
		return
	}
	marshal, err := json.Marshal(cookies.AuthFlow{
		State: state,
		Nonce: nonce,
	})
	if err != nil {
		onInternalServerError(w, err)
		return
	}
	err = cookies.SetCookie(w, config, string(marshal), cookies.AuthFlowCookieSuffix)
	if err != nil {
		onInternalServerError(w, err)
		return
	}
	onRedirect(w, loginUrl)
}
