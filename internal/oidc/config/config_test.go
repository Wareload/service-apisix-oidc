package config

import (
	"encoding/json"
	"github.com/go-playground/validator/v10"
	"testing"
)

const validConfig = `{
"discovery_url": "http://localhost:8080",
"scope": "openid",
"client_id": "client-id",
"client_secret": "client-secret",
"base_url": "http://localhost:7070",
"login_path": "/login",
"logout_path": "/logout",
"callback_path": "/callback",
"userinfo_path": "/userinfo",
"post_logout_url": "/post-logout",
"post_login_url": "/post-login",
"cookie": {
	"name": "auth",
	"path": "/",
	"secure": true,
	"http_only": true,
	"same_site": "Lax",
	"secret": "mysecurefixedkey1234567890123456"
	}
}`

const invalidConfig = `{
"discovery_url": "http://localhost:8080",
"client_id": "client-id",
"client_secret": "client-secret",
"login_path": "/login",
"logout_path": "/logout",
"callback_path": "/callback",
"userinfo_path": "/userinfo",
"post_logout_url": "/post-logout",
"post_login_url": "/post-login"
}`

func TestValidConfig(t *testing.T) {
	config := Conf{}
	err := json.Unmarshal([]byte(validConfig), &config)
	if err != nil {
		t.Errorf("failed to unmarshal config: %s", err)
		return
	}
	validate := validator.New(validator.WithRequiredStructEnabled())
	err = validate.Struct(config)
	if err != nil {
		t.Errorf("failed to validate config: %s", err)
		return
	}
}

func TestInvalidConfig(t *testing.T) {
	config := Conf{}
	err := json.Unmarshal([]byte(invalidConfig), &config)
	if err != nil {
		t.Errorf("failed to unmarshal config: %s", err)
		return
	}
	validate := validator.New(validator.WithRequiredStructEnabled())
	err = validate.Struct(config)
	if err == nil {
		t.Errorf("invalid config should not pass validation")
		return
	}
}
