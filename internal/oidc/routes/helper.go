package routes

import (
	"errors"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/config"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/services/cookies"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/services/oidc"
	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"github.com/apache/apisix-go-plugin-runner/pkg/log"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"time"
)

func updateTokensIfNeeded(w http.ResponseWriter, conf config.Conf, accessToken, refreshToken string) (err error, newAccessToken string, refreshed bool) {
	accExpired, err := isTokenExpired(accessToken, conf.Leeway)
	if err != nil {
		return err, "", false
	}
	if !accExpired {
		return nil, accessToken, false
	}
	newToken, err := oidc.RefreshTokens(refreshToken, conf)
	if err != nil {
		return err, accessToken, false
	}
	errAcc := cookies.SetCookie(w, conf, newToken.AccessToken, cookies.AuthAccessCookieSuffix)
	errRf := cookies.SetCookie(w, conf, newToken.RefreshToken, cookies.AuthRefreshCookieSuffix)
	return errors.Join(errAcc, errRf), newToken.AccessToken, true
}

func isTokenExpired(raw string, leeway int) (bool, error) {
	token, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		return false, err
	}
	date, err := token.Claims.GetExpirationTime()
	if err != nil {
		return false, err
	}
	return date.Before(time.Now().Add(-time.Second * time.Duration(leeway))), err
}

func isNonceMatching(idToken, nonce string) bool {
	token, _, err := jwt.NewParser().ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}
	nonceClaim, ok := claims["nonce"].(string)
	if !ok {
		return false
	}
	return nonceClaim == nonce
}

func onUnauthorized(w http.ResponseWriter, conf config.Conf) {
	cookies.DeleteCookies(w, conf)
	w.WriteHeader(http.StatusUnauthorized)
}

func onServiceUnavailable(w http.ResponseWriter, err error) {
	log.Warnf("Service unavailable: %v", err)
	w.WriteHeader(http.StatusServiceUnavailable)
}

func onInternalServerError(w http.ResponseWriter, err error) {
	log.Errorf("Internal server error: %v", err)
	w.WriteHeader(http.StatusInternalServerError)
}

func onMethodNotAllowed(w http.ResponseWriter) {
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func onRedirect(w http.ResponseWriter, redirectUrl string) {
	w.Header().Set("Location", redirectUrl)
	w.WriteHeader(http.StatusFound)
}

func onTemporaryRedirect(w http.ResponseWriter, r pkgHTTP.Request) {
	redirectURL := string(r.Path())
	query := r.Args()
	if query.Encode() != "" {
		redirectURL += "?" + query.Encode()
	}
	w.Header().Set("Location", redirectURL)
	w.WriteHeader(http.StatusTemporaryRedirect)
}
