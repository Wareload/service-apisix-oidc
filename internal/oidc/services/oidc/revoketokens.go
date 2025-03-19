package oidc

import (
	"fmt"
	"net/http"
	"net/url"
	"service-apisix-oidc/internal/oidc/config"
	"strings"
)

func RevokeTokens(refreshToken string, conf config.Conf) error {
	wk, err := GetWellKnown(conf)
	if err != nil {
		return err
	}
	data := url.Values{}
	data.Set("client_id", conf.ClientId)
	data.Set("client_secret", conf.ClientSecret)
	data.Set("token", refreshToken)
	req, err := http.NewRequest("POST", wk.RevocationEP, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to logout: %s", resp.Status)
	}
	return nil
}
