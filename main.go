package main

import (
	"github.com/Wareload/service-apisix-oidc/internal/oidc"
	"github.com/apache/apisix-go-plugin-runner/pkg/log"
	"github.com/apache/apisix-go-plugin-runner/pkg/plugin"
	"github.com/apache/apisix-go-plugin-runner/pkg/runner"
)

func main() {
	err := plugin.RegisterPlugin(&oidc.Oidc{})
	if err != nil {
		log.Fatalf("failed to register plugin oidc: %s", err)
	}
	log.Infof("plugin oidc registered")
	runner.Run(runner.RunnerConfig{})
}
