package api

import (
	"net/http"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/auth"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/communication"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/validator"
	"github.com/julienschmidt/httprouter"
)

// RequestSpecUserList RequestSpecUserList
type RequestSpecUserList struct {
	IsForTradingSession    bool   `json:"isForTradingSession"`
	IsForNonTradingSession bool   `json:"isForNonTradingSession"`
	MobileNumber           int64  `json:"mobileNumber"`
	Password               string `json:"password"`
	Otp                    int64  `json:"otp"`
}

func (p *RequestSpecUserList) validate() *auth.ErrAuth {
	errs := &auth.ErrAuth{}
	if isValid := validator.IsValidMobileNumber(p.MobileNumber); !isValid {
		errs.Add("MobileNumber", validator.ErrInvalidMobile)
	}
	if p.Password == "" {
		errs.Add("Password", "Password can not be empty")
	}
	if !p.IsForNonTradingSession && !p.IsForTradingSession {
		errs.Add("InvalidRequest", "Please set IsForNonTradingSession=true or IsForTradingSession=true, both can not be false")
	}
	if p.Otp == 0 {
		errs.Add("Otp", "Otp can not be empty")
	}
	return errs
}

// User User
type User struct {
	AUC        string `json:"auc"`
	ClientName string `json:"clientName"`
}

// ResponseSpecUserList ResponseSpecUserList
type ResponseSpecUserList struct {
	Password string `json:"password"`
	UserList []User `json:"userList"`
}

func handlerGetUserList(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	requestID := r.Context().Value(communication.HttpHeaderRequestID).(string)
	reqBody := &RequestSpecUserList{}
	respnse := &Response{}
	rawReqBody, err := getJSONRequestBody(r, reqBody)
	if err != nil && len(*err) > 0 {
		respnse.Status = http.StatusBadRequest
		respnse.Error = *err
		SendJSONResponse(w, requestID, respnse)
		return
	}
	// no need to check for error, since we control everything upto this point
	reqBody, _ = rawReqBody.(*RequestSpecUserList)
	tokenRequest := auth.ParamsUsers{
		IsForNonTradingSession: reqBody.IsForNonTradingSession,
		IsForTradingSession:    reqBody.IsForTradingSession,
		MobileNumber:           reqBody.MobileNumber,
		Password:               reqBody.Password,
		Otp:                    reqBody.Otp,
	}
	userList, errora := auth.GetUserList(r.Context(), tokenRequest)
	if errora != nil && len(*errora) > 0 {
		respnse.Status = http.StatusBadRequest
		respnse.Error = *errora
		SendJSONResponse(w, requestID, respnse)
		return
	}
	respnse.Status = http.StatusOK
	users := []User{}
	var user User
	for _, v := range userList.Users {
		user.AUC = v.AUC
		user.ClientName = v.ClientName
		users = append(users, user)
	}
	respnse.Data = []interface{}{
		ResponseSpecUserList{
			Password: userList.Password,
			UserList: users,
		},
	}
	SendJSONResponse(w, requestID, respnse)
	return
}
