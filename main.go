package main

import (
	"encoding/json"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/api"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/auth"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/communication"
	config "amritsingh374.bitbucket.org/cloud/auth/pkg/config"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/logger"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/monitor"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/persistence"
)

const (
	// SDKVersion version of the SDK
	SDKVersion = "0.0.1"
)

var (
	stopper   chan bool
	appConfig *config.CloudAuthConfig
	err       error
)

func init() {
	if os.Getenv("TZ") == "" || os.Getenv("TZ") != "UTC" {
		panic("Please set TZ=UTC for the application. Additional TIP: Always use epoch time for everything")
	}
	appConfig, err = config.ParseConfigFromOSEnv("CLOUDAUTHCFG")
	if err != nil {
		panic(err.Error())
	}
	validationErros := appConfig.Validate()
	if len(validationErros) > 0 {
		sm := &config.SampleCloudAuthConfig{}
		jCOnf, _ := json.Marshal(sm)
		log.Println("JSON should look like", string(jCOnf))
		log.Panicf("%+v", validationErros)
	}
	appConfig.OTPMeta.GenerateEndpoints()
	appConfig.HTTP.DialerTimeout = appConfig.HTTP.DialerTimeout * time.Second
	appConfig.HTTP.ExpectContinueTimeout = appConfig.HTTP.ExpectContinueTimeout * time.Second
	appConfig.HTTP.ResponseHeaderTimeout = appConfig.HTTP.ResponseHeaderTimeout * time.Second
	appConfig.HTTP.TLSHandshakeTimeout = appConfig.HTTP.TLSHandshakeTimeout * time.Second
	appConfig.Otp.TTL = appConfig.Otp.TTL * time.Second
	appConfig.AUC.TTL = appConfig.AUC.TTL * time.Second
	appConfig.Authjwt.TTL = appConfig.Authjwt.TTL * time.Second
	appConfig.Refreshjwt.TTL = appConfig.Refreshjwt.TTL * time.Second
	if appConfig.Monitoring.Redis.Enabled {
		appConfig.Monitoring.Redis.Interval = appConfig.Monitoring.Redis.Interval * time.Second
	}
	logger.Bootstrap(appConfig.Logs)
	persistence.Bootstrap(appConfig.Cache.Redis)
	auth.Bootstrap(appConfig.Otp, appConfig.AUC, appConfig.Authjwt, appConfig.Refreshjwt, appConfig.Error, appConfig.OTPMeta)
	communication.Bootstrap(appConfig.SMS, appConfig.HTTP, appConfig.Error, appConfig.OTPMeta)
}
func main() {
	go api.RestAPIStartServer(appConfig.API.Port, appConfig.API.Host)
	if appConfig.Profiler.Enabled || appConfig.Monitoring.Redis.Enabled {
		if appConfig.Monitoring.Redis.Enabled {
			stopper := make(chan bool)
			logger.Log("Setting up Redis monitoring at an interval of ", appConfig.Monitoring.Redis.Interval)
			go monitor.StartMonitoringRedis(appConfig.Monitoring.Redis.Interval, persistence.DB.Redis.Client, stopper)
			// go monitor.StartMonitoringPosgtres(appConfig.Monitoring.Redis.Interval, persistence.DB.Postgres.Pool, stopper)
		}
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
		<-stopper //wait indefinitely
	}
}
