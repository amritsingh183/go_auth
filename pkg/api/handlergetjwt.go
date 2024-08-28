package api

import (
	"fmt"
	"net/http"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/auth"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/communication"
	"github.com/julienschmidt/httprouter"
)

// RequestSpecGetJWT RequestSpecGetJWT
type RequestSpecGetJWT struct {
	AUC      string `json:"auc"`
	Password string `json:"password"`
}

// RequestSpecGetJWTUsingRefreshToken RequestSpecGetJWTUsingRefreshToken
type RequestSpecGetJWTUsingRefreshToken struct {
	AUC string `json:"auc"`
}

func (pw *RequestSpecGetJWTUsingRefreshToken) validate() *auth.ErrAuth {
	errs := &auth.ErrAuth{}
	if pw.AUC == "" {
		errs.Add("AUC", "AUC can not be empty")
	}
	return errs
}
func (pw *RequestSpecGetJWT) validate() *auth.ErrAuth {
	errs := &auth.ErrAuth{}
	if pw.Password == "" {
		errs.Add("Password", "Password can not be empty")
	}
	if pw.AUC == "" {
		errs.Add("AUC", "AUC can not be empty")
	}
	return errs
}

func handlerGetJWT(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	requestID := r.Context().Value(communication.HttpHeaderRequestID).(string)
	reqBody := &RequestSpecGetJWT{}
	respnse := &Response{}
	rawReqBody, err := getJSONRequestBody(r, reqBody)
	if err != nil && len(*err) > 0 {
		respnse.Status = http.StatusBadRequest
		respnse.Error = *err
		SendJSONResponse(w, requestID, respnse)
		return
	}
	// no need to check for error, since we control everything upto this point
	reqBody, _ = rawReqBody.(*RequestSpecGetJWT)
	tokenRequest := auth.ParamsJWT{
		AUC:      reqBody.AUC,
		Password: reqBody.Password,
	}
	jwtResp, errora := auth.GetJWT(r.Context(), tokenRequest)
	if errora != nil && len(*errora) > 0 {
		respnse.Status = http.StatusBadRequest
		respnse.Error = *errora
		SendJSONResponse(w, requestID, respnse)
		return
	}
	respnse.Status = http.StatusOK
	respnse.Message = "JWT has been sent in response headers"
	w.Header().Set(authjwtheader, jwtResp.JWTForAuth)
	w.Header().Set(refreshjwtheader, jwtResp.JWTForRefresh)
	SendJSONResponse(w, requestID, respnse)
	return
}

func handlerGetJWTusingRefreshToken(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	requestID := r.Context().Value(communication.HttpHeaderRequestID).(string)
	reqBody := &RequestSpecGetJWTUsingRefreshToken{}
	respnse := &Response{}
	rawReqBody, err := getJSONRequestBody(r, reqBody)
	if err != nil && len(*err) > 0 {
		respnse.Status = http.StatusBadRequest
		respnse.Error = *err
		SendJSONResponse(w, requestID, respnse)
		return
	}
	reqBody, _ = rawReqBody.(*RequestSpecGetJWTUsingRefreshToken)
	refreshToken := r.Header.Get(refreshjwtheader)
	if refreshToken == "" {
		respnse.Status = http.StatusBadRequest
		respnse.Error = auth.ErrAuth{
			"Headers": []string{
				fmt.Sprintf("%s Header can not be empty", refreshjwtheader),
			},
		}
		SendJSONResponse(w, requestID, respnse)
		return
	}
	tokenRequest := auth.ParamsRefreshJWT{
		AUC:  reqBody.AUC,
		JWT:  refreshToken,
		Host: r.Host,
	}
	jwtResp, errora := auth.RegenerateJWTUsingRefreshToken(r.Context(), tokenRequest)
	if errora != nil && len(*errora) > 0 {
		respnse.Status = http.StatusBadRequest
		respnse.Error = *errora
		SendJSONResponse(w, requestID, respnse)
		return
	}
	respnse.Status = http.StatusOK
	respnse.Message = "JWT has been sent in response headers"
	w.Header().Set(authjwtheader, jwtResp.JWTForAuth)
	w.Header().Set(refreshjwtheader, jwtResp.JWTForRefresh)
	SendJSONResponse(w, requestID, respnse)
	return
}
