package api

import (
	"fmt"
	"net/http"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/auth"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/communication"
	"github.com/julienschmidt/httprouter"
)

// RequestSpecVerifyJWT RequestSpecVerifyJWT
type RequestSpecVerifyJWT struct {
	AUC string `json:"auc"`
}

func (pw *RequestSpecVerifyJWT) validate() *auth.ErrAuth {
	errs := &auth.ErrAuth{}
	if pw.AUC == "" {
		errs.Add("AUC", "AUC can not be empty")
	}
	return errs
}

// ResponseSpecVerifyJWT ResponseSpecVerifyJWT
type ResponseSpecVerifyJWT struct {
	IsValid bool `json:"isValid"`
}

func handlerVerifyJWT(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	requestID := r.Context().Value(communication.HttpHeaderRequestID).(string)
	reqBody := &RequestSpecVerifyJWT{}
	respnse := &Response{}
	rawReqBody, err := getJSONRequestBody(r, reqBody)
	if err != nil && len(*err) > 0 {
		respnse.Status = http.StatusBadRequest
		respnse.Error = *err
		SendJSONResponse(w, requestID, respnse)
		return
	}
	var jwtToken string
	authToken := r.Header.Get(authjwtheader)
	refreshToken := r.Header.Get(refreshjwtheader)
	tokenType := 0
	if authToken == "" && refreshToken == "" {
		respnse.Status = http.StatusBadRequest
		respnse.Error = auth.ErrAuth{
			"Headers": []string{
				fmt.Sprintf("Header can not be empty"),
			},
		}
		SendJSONResponse(w, requestID, respnse)
		return
	}
	if authToken != "" {
		jwtToken = authToken
		tokenType = auth.TypeAuthToken
	} else if refreshToken != "" {
		jwtToken = refreshToken
		tokenType = auth.TypeRefreshToken
	} else {
		respnse.Status = http.StatusOK
		respnse.Data = []interface{}{
			ResponseSpecVerifyJWT{
				IsValid: false,
			},
		}
		SendJSONResponse(w, requestID, respnse)
		return
	}

	// no need to check for error, since we control everything upto this point
	reqBody, _ = rawReqBody.(*RequestSpecVerifyJWT)
	tokenRequest := auth.ParamsVerifyJWT{
		AUC:  reqBody.AUC,
		JWT:  jwtToken,
		Type: tokenType,
		Host: r.Host,
	}
	rsp, errora := auth.ValidateJWT(r.Context(), tokenRequest)
	if errora != nil && len(*errora) > 0 {
		respnse.Status = http.StatusBadRequest
		respnse.Error = *errora
		SendJSONResponse(w, requestID, respnse)
		return
	}
	respnse.Status = http.StatusOK
	respnse.Data = []interface{}{
		ResponseSpecVerifyJWT{
			IsValid: rsp.IsValid,
		},
	}
	SendJSONResponse(w, requestID, respnse)
	return
}
