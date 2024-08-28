package config

import (
	"reflect"
	"strconv"
	"strings"
)

const (
	newOtp = iota + 1
	resendSameOtp
)

// OtpMetaOtp OtpMetaOtp
type otpMetaOtp struct {
	EncryptionKey string `json:"encryptionKey"`
}

// OTPMeta OTPMeta
type OTPMeta struct {
	Otp              *otpMetaOtp              `json:"otp"`
	BaseURL          string                   `json:"baseURL"`
	TransactionCodes *otpMetaTransactionCodes `json:"transactionCodes"`
	SourceID         *otpMetaSourceID         `json:"sourceTypes"`
	UserTypes        *otpMetaUserTypeID       `json:"userTypes"`
	Endpoints        *endpointsOtpMeta        `json:"endpoints"`
}

// GenerateEndpoints GenerateEndpoints
func (a *OTPMeta) GenerateEndpoints() {
	a.Endpoints = &endpointsOtpMeta{
		GenerateOtp: a.BaseURL + "/" + "CGI/Login",
	}
}
func (a *OTPMeta) validate() bool {
	if reflect.DeepEqual(a, OTPMeta{}) {
		return false
	}
	if a.BaseURL == "" || a.TransactionCodes == nil || a.SourceID == nil || a.UserTypes == nil || a.Otp == nil {
		return false
	}
	if a.TransactionCodes.RequestGenerateOtp == 0 || a.TransactionCodes.ResponseGenerateOtp == 0 || a.TransactionCodes.RequestVerifyOtp == 0 || a.TransactionCodes.ResponseVerifyOtp == 0 || a.SourceID.Mobile == 0 || a.SourceID.Desktop == 0 || a.SourceID.Web == 0 || a.UserTypes.Client == 0 || a.UserTypes.Dealer == 0 || a.Otp.EncryptionKey == "" {
		return false
	}
	return true
}

type otpMetaTransactionCodes struct {
	RequestGenerateOtp  uint64 `json:"generateOtpReq"`
	ResponseGenerateOtp uint64 `json:"generateOtpRes"`
	RequestVerifyOtp    uint64 `json:"verifyOtpReq"`
	ResponseVerifyOtp   uint64 `json:"verifyOtpRes"`
}

type otpMetaSourceID struct {
	Desktop uint64 `json:"desktop"` // 1
	Mobile  uint64 `json:"mobile"`  // 2
	Web     uint64 `json:"web"`     // 3
}
type otpMetaUserTypeID struct {
	Client uint64 `json:"client"` // 1
	Dealer uint64 `json:"dealer"` // 2
}
type endpointsOtpMeta struct {
	GenerateOtp string
}

// RequestBodyNewOtpGenerateMobile RequestBodyNewOtpGenerateMobile
func (a *OTPMeta) RequestBodyNewOtpGenerateMobile(mobileNumber uint64, clientLocalIP string, clientPublicIP string, mac string) string {
	return strings.Join([]string{
		strconv.FormatUint(a.TransactionCodes.RequestGenerateOtp, 10),
		strconv.FormatUint(mobileNumber, 10),
		"MOBILE",
		strconv.FormatUint(a.SourceID.Mobile, 10),
		strconv.FormatUint(a.UserTypes.Client, 10),
		clientLocalIP,
		clientPublicIP,
		mac,
		strings.Repeat("|", 3),
		strconv.FormatInt(newOtp, 10),
	}, "|")
}

// RequestBodyResendOldOtpMobile RequestBodyResendOldOtpMobile
func (a *OTPMeta) RequestBodyResendOldOtpMobile(mobileNumber uint64, clientLocalIP string, clientPublicIP string, mac string) string {
	return strings.Join([]string{
		strconv.FormatUint(a.TransactionCodes.RequestGenerateOtp, 10),
		strconv.FormatUint(mobileNumber, 10),
		"MOBILE",
		strconv.FormatUint(a.SourceID.Mobile, 10),
		strconv.FormatUint(a.UserTypes.Client, 10),
		clientLocalIP,
		clientPublicIP,
		mac,
		strings.Repeat("|", 3),
		strconv.FormatInt(resendSameOtp, 10),
	}, "|")
}

// RequestBodyVerifyOtpMobile RequestBodyVerifyOtpMobile
func (a *OTPMeta) RequestBodyVerifyOtpMobile(mobileNumber uint64, otp uint64) string {
	return strings.Join([]string{
		strconv.FormatUint(a.TransactionCodes.RequestVerifyOtp, 10),
		strconv.FormatUint(mobileNumber, 10),
		"MOBILE",
		strconv.FormatUint(otp, 10),
	}, "|")
}
