package oidc

import (
	"encoding/json"
	"github.com/Wareload/service-apisix-oidc/internal/oidc/config"
	"github.com/apache/apisix-go-plugin-runner/pkg/log"
	"github.com/go-playground/validator/v10"
	"io"
	"net/http"
	"sync"
	"time"
)

var (
	timestamp    int64
	wellKnown    config.WellKnown
	wellKnownMu  sync.Mutex
	wellKnownUrl string
	interval     = 60 * 15 // 15 minutes
)

func GetWellKnown(conf config.Conf) (config.WellKnown, error) {
	now := time.Now().Unix()
	wellKnownMu.Lock()
	defer wellKnownMu.Unlock()
	if now-timestamp < int64(interval) && wellKnownUrl == conf.DiscoveryUrl {
		return wellKnown, nil
	}
	wk, err := fetchWellKnown(conf.DiscoveryUrl)
	if err != nil {
		log.Errorf("fetch well known url %s error: %v", conf.DiscoveryUrl, err)
		return config.WellKnown{}, err
	}
	wellKnownUrl = conf.DiscoveryUrl
	wellKnown = wk
	timestamp = now
	log.Infof("well known url refreshed: %s, timestamp: %d", conf.DiscoveryUrl, now)
	return wellKnown, nil
}

func fetchWellKnown(url string) (config.WellKnown, error) {
	resp, err := http.Get(url)
	if err != nil {
		return config.WellKnown{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return config.WellKnown{}, err
	}
	wk := config.WellKnown{}
	err = json.Unmarshal(body, &wk)
	if err != nil {
		return config.WellKnown{}, err
	}
	validate := validator.New(validator.WithRequiredStructEnabled())
	err = validate.Struct(wk)
	return wk, err
}
