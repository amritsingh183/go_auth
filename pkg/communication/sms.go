package communication

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"encoding/json"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/config"
)

// requestSpecSMS requestSpecSMS
type requestSpecSMS struct {
	MobileNumber string `json:"mobileNo"`
	Content      string `json:"smsContent"`
	Purpose      string `json:"smsPuspose"`
	Source       string `json:"smsSource"`
	Team         string `json:"smsTeam"`
	UserID       string `json:"smsUserId"`
	Password     string `json:"smsPassword"`
}

// requestSpecOtpMetaSMS requestSpecOtpMetaSMS
type requestSpecOtpMetaSMS struct {
	MobileNumber string `json:"mobileNo"`
}

// ConfigSMS ConfigSMS
type ConfigSMS struct {
	Purpose                string
	Team                   string
	Source                 string
	UserID                 string
	Password               string
	URL                    string
	ErrDelimiter           string
	ErrInternalServerError string
}

// SMS SMS
type SMS struct {
	Content      string
	MobileNumber int64
}

// ResponseSMS ResponseSMS
// {"success":true,"message":"SENT","data":"2076007131303466000"}
type ResponseSMS struct {
	Success bool
	Message string
	Data    string
}

// SMSConfig SMSConfig
var smsConfig *config.SMS

var otpMetaConfig *config.OTPMeta

// Send Send SMS
func (s SMS) Send(ctx context.Context) (*ResponseSMS, error) {
	mobileNumber := strconv.FormatInt(s.MobileNumber, 10)
	newSMSRequest := &requestSpecSMS{
		MobileNumber: mobileNumber,
		Content:      s.Content,
		Purpose:      smsConfig.Purpose,
		Source:       smsConfig.Source,
		Team:         smsConfig.Team,
		UserID:       smsConfig.UserID,
		Password:     smsConfig.Password,
	}
	smsReqBody, err := json.Marshal(newSMSRequest)
	if err != nil {
		// Something wrong with our config or request validation
		return nil, fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, err.Error())
	}
	respCh := &HTTPResponse{
		Done: make(chan bool),
	}

	httpReq := &HTTP{
		Method:      HTTPMethodPOST,
		URL:         smsConfig.URL,
		Body:        smsReqBody,
		ContentType: HTTPContentTypeJSON,
	}
	go httpReq.Send(ctx, respCh)
	<-respCh.Done
	if respCh.Error != nil {
		return nil, respCh.Error
	}
	rspSMS := &ResponseSMS{}
	err = json.Unmarshal(respCh.Body, rspSMS)
	if err != nil {
		// Nothing wrong with user input
		// THE SMS server has not adhered to the predefined struct ResponseSMS
		return nil, fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, err.Error())
	}
	return rspSMS, nil
}

// OtpMetaSMS OtpMetaSMS
type OtpMetaSMS struct {
	MobileNumber uint64
}

// Send Send SMS via OTPMeta
func (amsm OtpMetaSMS) Send(ctx context.Context) (*ResponseSMS, error) {
	strBody := otpMetaConfig.RequestBodyNewOtpGenerateMobile(amsm.MobileNumber, "", "", "")
	respCh := &HTTPResponse{
		Done: make(chan bool),
	}
	httpReq := &HTTP{
		Method:      HTTPMethodPOST,
		URL:         otpMetaConfig.Endpoints.GenerateOtp,
		Body:        []byte(strBody),
		ContentType: HTTPContentTypeText,
	}
	go httpReq.Send(ctx, respCh)
	<-respCh.Done
	if respCh.Error != nil {
		return nil, respCh.Error
	}
	stringResBody := string(respCh.Body)
	responseData := strings.Split(stringResBody, "|")
	rspSMS := &ResponseSMS{}
	switch true {
	case len(responseData) == 4:
		// 2001|1|0000015|TECHNICAL_ERROR
		// 2001|1|0000016|INPUT IS INVALID
		rspSMS.Message = responseData[3]
		return rspSMS, nil
	case len(responseData) == 6:
		// 2064|0|0000119|8053283283|-1|Otp Generate Failed User is blocked
		rspSMS.Message = responseData[5]
		return rspSMS, nil
	case len(responseData) == 7:
		// 2064|0|0000046|8053283283|1|Otp Generated Successfully|188046
		rspSMS.Message = responseData[5]
		// the Otp from OTPMeta
		rspSMS.Data = responseData[6]
		switch responseData[4] {
		case "1":
			rspSMS.Success = true
			return rspSMS, nil
		case "-1":
			rspSMS.Success = false
			return rspSMS, nil
		default:
			return nil, fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, rspSMS.Message)
		}
	}
	return nil, fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, "Unexpected Response from OTPMeta. ResponseData: "+stringResBody)
}

// VerifyOtpMetaOtp VerifyOtpMetaOtp
func VerifyOtpMetaOtp(ctx context.Context, mobileNumber uint64, otp uint64) (*ResponseSMS, error) {

	strBody := otpMetaConfig.RequestBodyVerifyOtpMobile(mobileNumber, otp)
	httpReq := &HTTP{
		Method:      HTTPMethodPOST,
		URL:         otpMetaConfig.Endpoints.GenerateOtp,
		Body:        []byte(strBody),
		ContentType: HTTPContentTypeText,
	}
	rspCh := &HTTPResponse{
		Done: make(chan bool),
	}
	go httpReq.Send(ctx, rspCh)
	<-rspCh.Done
	if rspCh.Error != nil {
		return nil, rspCh.Error
	}
	stringResBody := string(rspCh.Body)
	responseData := strings.Split(stringResBody, "|")
	rspSMS := &ResponseSMS{}
	if len(responseData) < 4 {
		return nil, fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, "Unexpected Response from OTPMeta. ResponseData: "+stringResBody)
	}
	otpMetaReturnCode := responseData[1]
	switch otpMetaReturnCode {
	case "1":
		// 2001|1|0000015|TECHNICAL_ERROR
		// 2001|1|0000016|INPUT IS INVALID
		rspSMS.Message = responseData[3]
		return rspSMS, nil
	case "0":
		if len(responseData) == 4 {
			rspSMS.Message = "Success from OTPMeta otp verification"
			rspSMS.Success = true
			rspSMS.Data = responseData[3]
			return rspSMS, nil
		}
		if len(responseData) == 7 {
			// 2022|0|0000044|ADEALER~-1~AMRIT SINGH^A299861~1~AMRIT SINGH
			// 2022|0|0000044|A299861~1~AMRIT SINGH^ADEALER~-1~AMRIT SINGH
			// 2025|0|0000087|8053283283|-1|Entered Otp is incorrect or expired. Kindly regenerate Otp.|8053283283~0~
			otpGeneratedSucess := responseData[4]
			if otpGeneratedSucess == "1" {

			}
			rspSMS.Message = responseData[5]
			// the Otp from OTPMeta
			rspSMS.Data = responseData[6]
			switch responseData[4] {
			case "0":
				rspSMS.Success = true
				return rspSMS, nil
			case "1":
				rspSMS.Success = true
				return rspSMS, nil
			case "-1":
				rspSMS.Success = false
				return rspSMS, nil
			default:
				return nil, fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, rspSMS.Message)
			}
		}
	}

	return nil, fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, "Unexpected Response from OTPMeta. ResponseData: "+stringResBody)
}
