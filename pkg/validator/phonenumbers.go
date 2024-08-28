package validator

import (
	"regexp"
	"strconv"
)

const (
	// RegexValidMobileNumber the regex used to validate mobile number
	RegexValidMobileNumber = `^[6-9]\d{9}$`
	// ErrInvalidMobile Invalid Mobile number
	ErrInvalidMobile = "INVALID_MOBILE"
	// ErrInvalidPassword ErrInvalidPassword
	ErrInvalidPassword = "INVALID_PASSWORD"
	// ErrInvalidOtp ErrInvalidOtp
	ErrInvalidOtp = "INVALID_Otp"
	// ErrInvalidAUC ErrInvalidAUC
	ErrInvalidAUC = "INVALID_AUC"
	// ErrInvalidJWT ErrInvalidJWT
	ErrInvalidJWT = "INVALID_JWT"
	//ErrExpiredAUC ErrExpiredAUC
	ErrExpiredAUC = "AUC_SESSION_EXPIRED, start again from Generate Otp step"
	//ErrInvalidToken ...
	ErrInvalidToken = "INVALID_TOKEN"
)

var (
	regexMobile = regexp.MustCompile(RegexValidMobileNumber)
)

// IsValidMobileNumber ...
func IsValidMobileNumber(m int64) bool {

	return regexMobile.MatchString(strconv.FormatInt(m, 10))
}
