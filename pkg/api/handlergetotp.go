package api

import (
	"net/http"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/communication"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/auth"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/validator"
	"github.com/julienschmidt/httprouter"
)

// RequestSpecOtp RequestSpecOtp
type RequestSpecOtp struct {
	MobileNumber           int64 `json:"mobileNumber"`
	IsForTradingSession    bool  `json:"isForTradingSession"`
	IsForNonTradingSession bool  `json:"isForNonTradingSession"`
}

func (p *RequestSpecOtp) validate() *auth.ErrAuth {
	errs := &auth.ErrAuth{}
	isValid := validator.IsValidMobileNumber(p.MobileNumber)
	if !isValid {
		errs.Add("MobileNumber", validator.ErrInvalidMobile)
	}
	return errs
}

// ResponseSpecOtp ResponseSpecOtp
type ResponseSpecOtp struct {
	Password string `json:"password"`
}

func handlerGetOtp(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	requestID := r.Context().Value(communication.HttpHeaderRequestID).(string)
	reqBody := &RequestSpecOtp{}
	respnse := &Response{}
	rawReqBody, err := getJSONRequestBody(r, reqBody)
	if err != nil && len(*err) > 0 {
		respnse.Status = http.StatusBadRequest
		respnse.Error = *err
		SendJSONResponse(w, requestID, respnse)
		return
	}
	// no need to check for error, since we control everything upto this point
	reqBody, _ = rawReqBody.(*RequestSpecOtp)

	otpRequest := auth.ParamsOtp{
		MobileNumber:           reqBody.MobileNumber,
		IsForNonTradingSession: reqBody.IsForNonTradingSession,
		IsForTradingSession:    reqBody.IsForTradingSession,
	}
	password, errora := auth.GenerateOtp(r.Context(), otpRequest)
	if errora != nil && len(*errora) > 0 {
		respnse.Status = http.StatusBadRequest
		respnse.Error = *errora
		SendJSONResponse(w, requestID, respnse)
		return
	}
	respnse.Status = http.StatusOK
	respnse.Data = []interface{}{
		ResponseSpecOtp{
			Password: password,
		},
	}
	SendJSONResponse(w, requestID, respnse)
	return
}
