package auth

import (
	"amritsingh374.bitbucket.org/cloud/auth/pkg/config"
)

// ErrAuth Error format for Auth
// ErrAuth maps a string key to a list of values.
// The keys in a ErrAuth map
// are case-sensitive.
type ErrAuth map[string][]string

// Get gets the first value associated with the given key.
// If there are no values associated with the key, Get returns
// the empty string. To access multiple values, use the map
// directly.
func (v ErrAuth) Get(key string) string {
	if v == nil {
		return ""
	}
	vs := v[key]
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

// Set sets the key to value. It replaces any existing
// values.
func (v ErrAuth) Set(key, value string) {
	v[key] = []string{value}
}

// Add adds the value to key. It appends to any existing
// values associated with key.
func (v ErrAuth) Add(key, value string) {
	v[key] = append(v[key], value)
}

// Del deletes the values associated with key.
func (v ErrAuth) Del(key string) {
	delete(v, key)
}

func init() {
	fieldNamesOtpUser = metaDataFieldNamesOtpUser{
		AucCodes:              "aucCodes",
		ClientNames:           "clientNames",
		CreatedAt:             "createdAt",
		HashedOtp:             "hashedOtp",
		HashedPassword:        "hashedPassword",
		IsOtpVerified:         "isOtpVerified",
		MobileNumber:          "mobileNumber",
		OtpStatus:             "otpStatus",
		TimeStampsUnix:        "timeStampsUnix",
		TradingHashedOtp:      "tradingHashedOtp",
		TradingHashedPassword: "tradingHashedPassword",
		TradingIsOtpVerified:  "tradingIsOtpVerified",
		TradingOtpStatus:      "tradingOtpStatus",
		UpdatedAt:             "updatedAt",
		ValidUptoUnix:         "validUptoUnix",
	}
	fieldTypesOtpUser = metaDataFieldTypesOtpUser{
		AucCodes:              "text[]",
		ClientNames:           "text[]",
		CreatedAt:             "bigint",
		HashedOtp:             "text",
		HashedPassword:        "text",
		IsOtpVerified:         "bool",
		MobileNumber:          "bigint",
		OtpStatus:             "text",
		TimeStampsUnix:        "bigint[]",
		TradingHashedOtp:      "text",
		TradingHashedPassword: "text",
		TradingIsOtpVerified:  "bool",
		TradingOtpStatus:      "text",
		UpdatedAt:             "bigint",
		ValidUptoUnix:         "bigint",
	}
	fieldNamesAUCuser = aucUserFieldMap{
		JTIForAuthJWT:    "authjti",
		JTIForRefreshJWT: "refreshjti",
		MobileNumber:     "mobileNumber",
		ClientName:       "clientName",
		AUC:              "auc",
		HashedPassword:   "hashedPassword",
		ValidUptoUnix:    "validUptoUnix",
		CreatedAt:        "createdAt",
		UpdatedAt:        "updatedAt",
	}
	fieldTypesAUCUser = aucUserFieldTypeMap{
		JTIForAuthJWT:    "text[]",
		JTIForRefreshJWT: "text[]",
		MobileNumber:     "bigint",
		ClientName:       "text",
		AUC:              "text",
		HashedPassword:   "text",
		ValidUptoUnix:    "bigint",
		CreatedAt:        "bigint",
		UpdatedAt:        "bigint",
	}
}

var errorConfig *config.Error

// Bootstrap Bootstrap
func Bootstrap(otpCfg *config.Otp, aucCfg *config.AUC, authJWTCfg *config.JWT, refJWTCfg *config.JWT, ecfg *config.Error, amConfig *config.OTPMeta) {
	otpConfig = otpCfg
	aucConfig = aucCfg
	otpMetaConfig = amConfig

	authJWTConfig = authJWTCfg
	if authJWTCfg.RSA != nil {
		switch authJWTCfg.RSA.KeyLength {
		case 512:
		default:

		}
	}
	refreshJWTConfig = refJWTCfg

	errorConfig = ecfg
	return
}
