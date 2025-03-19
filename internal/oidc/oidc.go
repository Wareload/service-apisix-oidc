package oidc

import (
	"encoding/json"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/config"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/routes"
	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"github.com/apache/apisix-go-plugin-runner/pkg/plugin"
	"github.com/go-playground/validator/v10"
	"net/http"
)

type Oidc struct {
	plugin.DefaultPlugin
}

func (o Oidc) Name() string {
	return "oidc"
}

func (o Oidc) ParseConf(in []byte) (interface{}, error) {
	conf := config.Conf{}
	err := json.Unmarshal(in, &conf)
	if err != nil {
		return nil, err
	}
	validate := validator.New(validator.WithRequiredStructEnabled())
	err = validate.Struct(conf)
	return conf, err
}

func (o Oidc) RequestFilter(conf interface{}, w http.ResponseWriter, r pkgHTTP.Request) {
	switch string(r.Path()) {
	case conf.(config.Conf).LoginPath:
		routes.HandleLogin(conf.(config.Conf), w, r)
	case conf.(config.Conf).LogoutPath:
		routes.HandleLogout(conf.(config.Conf), w, r)
	case conf.(config.Conf).CallbackPath:
		routes.HandleCallback(conf.(config.Conf), w, r)
	case conf.(config.Conf).UserinfoPath:
		routes.HandleUserinfo(conf.(config.Conf), w, r)
	default:
		routes.HandleProxy(conf.(config.Conf), w, r)
	}
}
