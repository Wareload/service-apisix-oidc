package oidc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"service-apisix-oidc/internal/oidc/config"
	"time"
)

func RefreshTokens(refreshToken string, conf config.Conf) (TokenResponse, error) {
	tokenResponse := TokenResponse{}
	wk, err := GetWellKnown(conf)
	if err != nil {
		return tokenResponse, err
	}
	data := url.Values{}
	data.Set("client_id", conf.ClientId)
	data.Set("client_secret", conf.ClientSecret)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)

	req, err := http.NewRequest("POST", wk.TokenEP, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return tokenResponse, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: time.Second * 5}
	resp, err := client.Do(req)
	if err != nil {
		return tokenResponse, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return tokenResponse, fmt.Errorf("failed to refresh token, status code: %d, response: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return tokenResponse, fmt.Errorf("error reading response body: %w", err)
	}
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return tokenResponse, fmt.Errorf("error unmarshaling response: %w", err)
	}
	return tokenResponse, nil
}
