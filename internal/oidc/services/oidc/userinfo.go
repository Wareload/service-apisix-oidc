package oidc

import (
	"io"
	"net/http"
)

func GetUserInfo(accessToken string, userInfoEndpoint string) (string, error) {
	req, err := http.NewRequest("GET", userInfoEndpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}
