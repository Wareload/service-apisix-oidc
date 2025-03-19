package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/config"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
}

func GenerateLoginURL(authURL, clientID, scope, redirectURI string) (string, string, string, error) {
	state, errState := randomString(32)
	nonce, errNonce := randomString(32)
	if errState != nil || errNonce != nil {
		return "", "", "", fmt.Errorf("failed to generate random string")
	}
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("response_type", "code")
	params.Set("scope", scope)
	params.Set("redirect_uri", redirectURI)
	params.Set("state", state)
	params.Set("nonce", nonce)
	return fmt.Sprintf("%s?%s", authURL, params.Encode()), state, nonce, nil
}

func randomString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func ExchangeCodeForToken(conf config.Conf, wk config.WellKnown, code string) (TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", conf.GetRedirectUrl())
	data.Set("client_id", conf.ClientId)
	data.Set("client_secret", conf.ClientSecret)
	data.Set("scope", conf.Scope)
	req, err := http.NewRequest("POST", wk.TokenEP, strings.NewReader(data.Encode()))
	if err != nil {
		return TokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return TokenResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return TokenResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return TokenResponse{}, fmt.Errorf("failed to exchange code: %s", body)
	}
	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return TokenResponse{}, err
	}
	return tokenResponse, nil
}
