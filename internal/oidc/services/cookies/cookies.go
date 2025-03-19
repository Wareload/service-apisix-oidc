package cookies

import (
	"fmt"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/config"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/services/crypto"
	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const AuthFlowCookieSuffix = "_flow" //state and nonce
const AuthAccessCookieSuffix = "_acc"
const AuthRefreshCookieSuffix = "_rf"

type AuthFlow struct {
	State string `json:"state"`
	Nonce string `json:"nonce"`
}

func SetCookie(w http.ResponseWriter, conf config.Conf, value, suffix string) error {
	aes, err := crypto.EncryptAES([]byte(value), []byte(conf.Cookie.Secret))
	if err != nil {
		return err
	}
	value = url.QueryEscape(string(aes))
	http.SetCookie(w, &http.Cookie{
		Name:     fmt.Sprintf("%s%s", conf.Cookie.Name, suffix),
		Value:    value,
		HttpOnly: conf.Cookie.HttpOnly,
		Secure:   conf.Cookie.Secure,
		Path:     conf.Cookie.Path,
		SameSite: conf.GetCookieSameSite(),
	})
	return nil
}

func DeleteCookies(w http.ResponseWriter, conf config.Conf) {
	cookieSuffixes := []string{
		AuthAccessCookieSuffix,
		AuthRefreshCookieSuffix,
	}
	for _, suffix := range cookieSuffixes {
		http.SetCookie(w, &http.Cookie{
			Name:     fmt.Sprintf("%s%s", conf.Cookie.Name, suffix),
			Value:    "",
			HttpOnly: conf.Cookie.HttpOnly,
			Secure:   conf.Cookie.Secure,
			Path:     conf.Cookie.Path,
			Expires:  time.Now().Add(-time.Hour),
		})
	}
}

func DeleteCookie(w http.ResponseWriter, conf config.Conf, suffix string) {
	http.SetCookie(w, &http.Cookie{
		Name:     fmt.Sprintf("%s%s", conf.Cookie.Name, suffix),
		Value:    "",
		HttpOnly: conf.Cookie.HttpOnly,
		Secure:   conf.Cookie.Secure,
		Path:     conf.Cookie.Path,
		Expires:  time.Now().Add(-time.Hour),
	})
}

func RemoveOwnCookiesFromHeader(r pkgHTTP.Request, config config.Conf) {
	cookiesToRemove := map[string]bool{
		fmt.Sprintf("%s%s", config.Cookie.Name, AuthFlowCookieSuffix):    true,
		fmt.Sprintf("%s%s", config.Cookie.Name, AuthAccessCookieSuffix):  true,
		fmt.Sprintf("%s%s", config.Cookie.Name, AuthRefreshCookieSuffix): true,
	}
	cookies := strings.Split(r.Header().Get("Cookie"), ";")
	var resultCookies []string
	for _, cookie := range cookies {
		cookie = strings.TrimSpace(cookie)
		parts := strings.SplitN(cookie, "=", 2)
		if len(parts) < 2 {
			continue
		}
		cookieName := parts[0]
		_, exists := cookiesToRemove[cookieName]
		if !exists {
			resultCookies = append(resultCookies, cookie)
		}
	}
	r.Header().Set("Cookie", strings.Join(resultCookies, "; "))
}

func GetCookie(r pkgHTTP.Request, conf config.Conf, suffix string) (string, error) {
	cookieHeader := r.Header().Get("Cookie")
	if cookieHeader == "" {
		return "", fmt.Errorf("no cookies found")
	}
	cookie, err := getCookieValue(cookieHeader, fmt.Sprintf("%s%s", conf.Cookie.Name, suffix))
	if err != nil {
		return "", err
	}
	value, err := url.QueryUnescape(cookie)
	if err != nil {
		return "", err
	}
	decrypt, err := crypto.DecryptAES([]byte(value), []byte(conf.Cookie.Secret))
	return string(decrypt), err
}

func getCookieValue(cookieHeader, cookieName string) (string, error) {
	for _, cookie := range strings.Split(cookieHeader, ";") {
		cookie = strings.TrimSpace(cookie)
		parts := strings.SplitN(cookie, "=", 2)
		if len(parts) == 2 && parts[0] == cookieName {
			value := parts[1]
			if len(value) > 1 && value[0] == '"' && value[len(value)-1] == '"' {
				return value[1 : len(value)-1], nil
			}
			return value, nil
		}
	}
	return "", fmt.Errorf("no cookie found")
}
