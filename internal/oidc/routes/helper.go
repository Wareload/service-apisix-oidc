package routes

import (
	"errors"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/config"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/services/cookies"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/services/oidc"
	"github.com/apache/apisix-go-plugin-runner/pkg/log"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"time"
)

func updateTokensIfNeeded(w http.ResponseWriter, conf config.Conf, accessToken, refreshToken string) (error, string) {
	accExpired, err := isTokenExpired(accessToken, conf.Leeway)
	if err != nil {
		return err, ""
	}
	if !accExpired {
		return nil, accessToken
	}
	newToken, err := oidc.RefreshTokens(refreshToken, conf)
	if err != nil {
		return err, accessToken
	}
	errAcc := cookies.SetCookie(w, conf, newToken.AccessToken, cookies.AuthAccessCookieSuffix)
	errRf := cookies.SetCookie(w, conf, newToken.RefreshToken, cookies.AuthRefreshCookieSuffix)
	return errors.Join(errAcc, errRf), newToken.AccessToken
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
