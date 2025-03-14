package main

import (
	"encoding/json"
	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"github.com/apache/apisix-go-plugin-runner/pkg/log"
	"github.com/apache/apisix-go-plugin-runner/pkg/plugin"
	"github.com/apache/apisix-go-plugin-runner/pkg/runner"
	"net/http"
)

func main() {
	err := plugin.RegisterPlugin(&Oidc{})
	if err != nil {
		log.Fatalf("failed to register plugin oidc: %s", err)
	}
	log.Infof("plugin oidc registered")
	runner.Run(runner.RunnerConfig{})
}

type Oidc struct {
	plugin.DefaultPlugin
}
type OidcConf struct{}

func (o Oidc) Name() string {
	return "oidc"
}

func (o Oidc) ParseConf(in []byte) (interface{}, error) {
	conf := OidcConf{}
	err := json.Unmarshal(in, &conf)
	return conf, err
}

func (o Oidc) RequestFilter(conf interface{}, w http.ResponseWriter, r pkgHTTP.Request) {
	w.Header().Add("X-Resp-A6-Runner", "Go")
	_, err := w.Write([]byte("Hello, this is the oidc plugin"))
	if err != nil {
		log.Errorf("failed to write: %s", err)
	}
}
