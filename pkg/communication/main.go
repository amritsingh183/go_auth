package communication

import (
	"crypto/tls"
	"net"
	"net/http"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/config"
)

var hclient *http.Client
var errorConfig *config.Error

// Bootstrap Bootstrap SMS package
func Bootstrap(c *config.SMS, h *config.HTTP, e *config.Error, a *config.OTPMeta) {
	smsConfig = c
	httpConfig = h
	errorConfig = e
	otpMetaConfig = a
	hclient = &http.Client{
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout: httpConfig.DialerTimeout,
				// KeepAlive: 30 * time.Second,
			}).Dial,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: httpConfig.InsecureSkipVerify,
			},
			TLSHandshakeTimeout:   httpConfig.TLSHandshakeTimeout,
			ResponseHeaderTimeout: httpConfig.ResponseHeaderTimeout,
			ExpectContinueTimeout: httpConfig.ExpectContinueTimeout,
		},
	}
}
