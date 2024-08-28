package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"reflect"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// SampleCloudAuthConfig SampleCloudAuthConfig
type SampleCloudAuthConfig struct {
	Error      Error    `json:"error"`
	API        API      `json:"api"`
	Logs       Logs     `json:"logs"`
	Profiler   Profiler `json:"profiler"`
	Monitoring struct {
		Redis MonitorRedis
	} `json:"monitoring"`
	Cache struct {
		Redis Redis `json:"redis"`
	} `json:"cache"`
	Otp        Otp  `json:"otp"`
	SMS        SMS  `json:"sms"`
	HTTP       HTTP `json:"http"`
	AUC        AUC  `json:"auc"`
	Authjwt    JWT  `json:"authjwt"`
	Refreshjwt JWT  `json:"refreshjwt"`
}

// CloudAuthConfig CloudAuthConfig
type CloudAuthConfig struct {
	OTPMeta    *OTPMeta    `json:"otpMeta"`
	Error      *Error      `json:"error"`
	API        *API        `json:"api"`
	Logs       *Logs       `json:"logs"`
	Profiler   *Profiler   `json:"profiler"`
	Monitoring *Monitoring `json:"monitoring"`
	Cache      *Cache      `json:"cache"`
	Otp        *Otp        `json:"otp"`
	SMS        *SMS        `json:"sms"`
	HTTP       *HTTP       `json:"http"`
	AUC        *AUC        `json:"auc"`
	Authjwt    *JWT        `json:"authjwt"`
	Refreshjwt *JWT        `json:"refreshjwt"`
}

// Validate Validate
func (cfg CloudAuthConfig) Validate() url.Values {
	validationErrors := url.Values{}
	if cfg.OTPMeta == nil || !cfg.OTPMeta.validate() {
		validationErrors.Add("CloudAuthConfig.OTPMeta", "is invalid")
	}
	if cfg.API == nil || !cfg.API.validate() {
		validationErrors.Add("CloudAuthConfig.API", "is invalid")
	}
	if cfg.Monitoring == nil || !cfg.Monitoring.validate() {
		validationErrors.Add("CloudAuthConfig.Monitoring", "is invalid")
	}
	if cfg.Error == nil || !cfg.Error.validate() {
		validationErrors.Add("CloudAuthConfig.Error", "is invalid")
	}
	if cfg.Logs == nil || !cfg.Logs.validate() {
		validationErrors.Add("CloudAuthConfig.Logs", "is invalid")
	}
	if cfg.Cache == nil || !cfg.Cache.validate() {
		validationErrors.Add("CloudAuthConfig.Cache", "is invalid")
	}
	if cfg.Otp == nil || !cfg.Otp.validate() {
		validationErrors.Add("CloudAuthConfig.Otp", "is invalid")
	}
	if cfg.SMS == nil || !cfg.SMS.validate() {
		validationErrors.Add("CloudAuthConfig.SMS", "is invalid")
	}
	if cfg.HTTP == nil || !cfg.HTTP.validate() {
		validationErrors.Add("CloudAuthConfig.HTTP", "is invalid")
	}
	if cfg.AUC == nil || !cfg.AUC.validate() {
		validationErrors.Add("CloudAuthConfig.AUC", "is invalid")
	}
	if cfg.Authjwt == nil || !cfg.Authjwt.validate() {
		validationErrors.Add("CloudAuthConfig.Authjwt", "is invalid")
	}
	if cfg.Refreshjwt == nil || !cfg.Refreshjwt.validate() {
		validationErrors.Add("CloudAuthConfig.Refreshjwt", "is invalid")
	}
	return validationErrors
}

// Error Error
type Error struct {
	Delimiter           string `json:"delimiter"`
	InternalServerError string `json:"internalServerError"`
	RedisError          string `json:"redisError"`
	SmsGatewayError     string `json:"smsGatewayError"`
	UserNotFound        string `json:"userNotFound"`
	OtpQuotaExhausted   string `json:"otpQuotaExhausted"`
}

func (e Error) validate() bool {
	if e.Delimiter == "" || e.InternalServerError == "" || e.RedisError == "" || e.SmsGatewayError == "" || e.UserNotFound == "" || e.OtpQuotaExhausted == "" {
		return false
	}
	return true
}

// API API
type API struct {
	Port string `json:"port"`
	Host string `json:"host"`
}

func (e API) validate() bool {
	if e.Port == "" || e.Host == "" {
		return false
	}
	return true
}

// Logs Logs
type Logs struct {
	Enabled         bool
	LogFileName     string `json:"logFileName"`
	MaxSize         uint64 `json:"mazSize"`
	LogToStdErr     bool   `json:"logToStdErr"`
	AlsoLogToStdErr bool   `json:"alsoLogToStdErr"`
}

func (e Logs) validate() bool {
	if e.LogFileName == "" || e.MaxSize == 0 {
		return false
	}
	return true
}

// Profiler Profiler
type Profiler struct {
	Enabled bool `json:"enabled"`
}

// MonitorRedis MonitorRedis
type MonitorRedis struct {
	Enabled  bool          `json:"enabled"`
	Interval time.Duration `json:"interval"`
}

// Monitoring Monitoring
type Monitoring struct {
	Redis *MonitorRedis `json:"redis"`
}

func (e Monitoring) validate() bool {
	if e.Redis == nil || e.Redis.Interval == 0 {
		return false
	}
	return true
}

// SQL SQL
type SQL struct {
	Host     string `json:"host"`
	Port     uint   `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Database string `json:"database"`
}

func (e SQL) validate() bool {
	if reflect.DeepEqual(e, SQL{}) {
		return false
	}
	return true
}

// Redis Redis
type Redis struct {
	LockingKey       string   `json:"lockingKey"`
	MasterName       string   `json:"masterName"`
	SentinelAddress  []string `json:"sentinelAddress"`
	SentinelPassword string   `json:"sentinelPassword"`
	Password         string   `json:"password"`
	Database         int      `json:"database"`
	Prefix           string   `json:"prefix"`
	Delimiter        string   `json:"delimiter"`
}

// Cache Cache
type Cache struct {
	Redis *Redis `json:"redis"`
}

func (e Cache) validate() bool {
	if e.Redis == nil || reflect.DeepEqual(e.Redis, Redis{}) || e.Redis.LockingKey == "" || e.Redis.Prefix == "" || e.Redis.Delimiter == "" {
		return false
	}
	return true
}

// Otp Otp
//
// Limit: number of times, a user can request for Otp
type Otp struct {
	TTL                         time.Duration `json:"ttl"`
	Limit                       int           `json:"limit"`
	Length                      int           `json:"length"`
	LengthPasswordUserList      int           `json:"userListPasswordLength"`
	LengthPasswordOtpGenerate   int           `json:"otpGenerationPasswordLength"`
	StatusPending               string        `json:"statusPending"`
	StatusVerified              string        `json:"statusVerified"`
	StatusExpired               string        `json:"statusExpired"`
	DelimiterForSliceJoinNSplit string        `json:"delimiterForSliceJoinNSplit"`
}

func (e Otp) validate() bool {
	if e.StatusPending == "" || e.StatusVerified == "" || e.StatusExpired == "" || e.DelimiterForSliceJoinNSplit == "" {
		return false
	}
	if e.TTL == 0 || e.Length == 0 || e.Limit == 0 || e.LengthPasswordUserList == 0 || e.LengthPasswordOtpGenerate == 0 {
		return false
	}
	return true
}

// SMS SMS
type SMS struct {
	Purpose  string `json:"purpose"`
	Team     string `json:"team"`
	Source   string `json:"source"`
	UserID   string `json:"userID"`
	Password string `json:"password"`
	URL      string `json:"url"`
}

func (e SMS) validate() bool {
	if e.Purpose == "" || e.Team == "" || e.Source == "" || e.UserID == "" || e.Password == "" || e.URL == "" {
		return false
	}
	return true
}

// HTTP HTTP
type HTTP struct {
	InsecureSkipVerify    bool          `json:"insecureSkipVerify"`
	DialerTimeout         time.Duration `json:"dialerTimeout"`
	TLSHandshakeTimeout   time.Duration `json:"tlsHandshakeTimeout"`
	ResponseHeaderTimeout time.Duration `json:"responseHeaderTimeout"`
	ExpectContinueTimeout time.Duration `json:"expectContinueTimeout"`
}

func (e HTTP) validate() bool {
	if e.DialerTimeout == 0 || e.TLSHandshakeTimeout == 0 || e.ResponseHeaderTimeout == 0 || e.ExpectContinueTimeout == 0 {
		return false
	}
	return true
}

// AUC AUC
type AUC struct {
	ApplicationSource string        `json:"applicationSource"`
	IPAddress         string        `json:"ipAddress"`
	URL               string        `json:"url"`
	TTL               time.Duration `json:"ttl"`
}

func (e AUC) validate() bool {
	if e.ApplicationSource == "" || e.IPAddress == "" || e.URL == "" || e.TTL == 0 {
		return false
	}
	return true
}

// RSA RSA
type RSA struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	KeyLength  int    `json:"keyLength"`
	Algo       *jwt.SigningMethodRSA
}

// KeyFunc KeyFunc
func (r *RSA) KeyFunc(sitokengnedJWT *jwt.Token) (interface{}, error) {
	publicKey, _ := ioutil.ReadFile(r.PublicKey)
	//error already checked during config bootstrap
	key, _ := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	return key, nil
}

// HMAC HMAC
type HMAC struct {
	SigningKey string `json:"signingKey"`
	KeyLength  int    `json:"keyLength"`
	Algo       *jwt.SigningMethodHMAC
}

// KeyFunc KeyFunc
func (h *HMAC) KeyFunc(sitokengnedJWT *jwt.Token) (interface{}, error) {
	return []byte(h.SigningKey), nil
}

// JWT JWT
type JWT struct {
	TokenType   string        `json:"tokenType"`
	TTL         time.Duration `json:"ttl"`
	AllowedIDPs string        `json:"allowedIDPs"`
	AllowedAud  []string      `json:"allowedAud"`
	RSA         *RSA          `json:"rsa"`
	HMAC        *HMAC         `json:"hmac"`
}

func (c JWT) validate() bool {
	if c.TTL == 0 || c.AllowedIDPs == "" || len(c.AllowedAud) == 0 || c.TokenType == "" {
		log.Println("c.TTL == 0 || c.AllowedIDPs == '' || len(c.AllowedAud) == 0 || c.TokenType == ''")
		return false
	}
	if c.RSA == nil && c.HMAC == nil {
		log.Println("c.RSA == nil && c.HMAC == nil : NOT Allowed")
		return false
	}
	if c.RSA != nil && c.HMAC != nil {
		log.Println("c.RSA != nil && c.HMAC != nil : NOT Allowed")
		return false
	}
	if c.RSA != nil {
		if c.RSA.KeyLength == 0 || c.RSA.PrivateKey == "" || c.RSA.PublicKey == "" {
			log.Println("c.RSA.KeyLength == 0 || c.RSA.PrivateKey =='' || c.RSA.PublicKey == ''")
			return false
		}
		switch c.RSA.KeyLength {
		case 512:
			c.RSA.Algo = jwt.SigningMethodRS512
		case 256:
			c.RSA.Algo = jwt.SigningMethodRS256
		default:
			log.Println("c.RSA.KeyLength==512 || 256")
			return false
		}
		publicKey, err := ioutil.ReadFile(c.RSA.PublicKey)
		if err != nil {
			log.Println("c.RSA.PublicKey not found " + c.RSA.PublicKey)
			return false
		}
		_, err = jwt.ParseRSAPublicKeyFromPEM(publicKey)
		if err != nil {
			log.Println("INVALID RSA PUBLIC KEY " + c.RSA.PublicKey)
			return false
		}
	}
	if c.HMAC != nil {
		if c.HMAC.KeyLength == 0 || c.HMAC.SigningKey == "" {
			log.Println("c.HMAC.KeyLength == 0 || c.HMAC.SigningKey == ''")
			return false
		}
		switch c.HMAC.KeyLength {
		case 512:
			c.HMAC.Algo = jwt.SigningMethodHS512
		case 256:
			c.HMAC.Algo = jwt.SigningMethodHS256
		default:
			log.Println("c.HMAC.KeyLength==512 || 256")
			return false
		}
	}

	return true
}

// ParseConfigFromOSEnv ParseConfigFromOSEnv
func ParseConfigFromOSEnv(envVarName string) (*CloudAuthConfig, error) {
	cv := &CloudAuthConfig{}
	if os.Getenv(envVarName) == "" {
		msg := fmt.Sprintf("%s Environment variable not set", envVarName)
		log.Println(msg)
		sm := &SampleCloudAuthConfig{}
		jCOnf, _ := json.Marshal(sm)
		log.Println("JSON should look like", string(jCOnf))
		return nil, errors.New(msg)
	}
	configJSON := os.Getenv(envVarName)
	err := json.Unmarshal([]byte(configJSON), cv)
	if err != nil {
		msg := fmt.Sprintf("%s Environment variable is not a valid JSON", envVarName)
		log.Println(msg, err)
		return nil, errors.New(msg)
	}

	if reflect.DeepEqual(cv, &CloudAuthConfig{}) {
		msg := fmt.Sprintf("One or more keys are not set in config")
		log.Println(msg)
		return nil, errors.New(msg)
	}
	return cv, nil

}
