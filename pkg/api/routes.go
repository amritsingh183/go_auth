package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/auth"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/communication"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/logger"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/util"
	"github.com/julienschmidt/httprouter"
)

const (
	authjwtheader     = "X-Authorization-Token"
	refreshjwtheader  = "X-Refresh-Token"
	contentTypeHeader = "Content-Type"
)

// Response Response
type Response struct {
	RequestID string        `json:"requestID"`
	Status    uint16        `json:"status"`
	Message   string        `json:"message"`
	Error     auth.ErrAuth  `json:"error"`
	Data      []interface{} `json:"data"`
}

// SendJSONResponse SendJSONResponse
func SendJSONResponse(w http.ResponseWriter, requestID string, r *Response) {
	if r.Status != http.StatusOK && r.Error == nil {
		// we panic to make sure that code is tested and this situation never comes up
		panic("r.Status != http.StatusOK && r.Error == nil")
	}
	r.RequestID = requestID
	if r.Data == nil {
		r.Data = []interface{}{}
	}
	w.Header().Set(contentTypeHeader, communication.HTTPContentTypeJSON)
	json.NewEncoder(w).Encode(r)
	return
}

type vInterface interface {
	validate() *auth.ErrAuth
}

func getJSONRequestBody(r *http.Request, rb vInterface) (interface{}, *auth.ErrAuth) {
	validationErrors := &auth.ErrAuth{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(rb)
	if err != nil {
		validationErrors.Add(http.StatusText(http.StatusBadRequest), "Invalid request body")
		return nil, validationErrors
	}
	errora := rb.validate()
	if errora != nil && len(*errora) > 0 {
		return nil, errora
	}
	return rb, nil
}

func heartBeat(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
	writer.Write([]byte("pong"))
	return
}
func addRequestID(handler httprouter.Handle) httprouter.Handle {
	return func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		request = request.Clone(context.WithValue(request.Context(), communication.HttpHeaderRequestID, util.GenerateUUID()))
		handler(writer, request, params)
	}
}

// RestAPIStartServer RestAPIStartServer
func RestAPIStartServer(port string, host string) {
	router := httprouter.New()
	allPOSTRoutes := map[string]httprouter.Handle{
		"/ping":                   heartBeat,
		"/api/v1/user/otp":        handlerGetOtp,
		"/api/v1/user/verifyotp":  handlerGetUserList,
		"/api/v1/user/getjwt":     handlerGetJWT,
		"/api/v1/user/verfifyjwt": handlerVerifyJWT,
		"/api/v1/user/refreshjwt": handlerGetJWTusingRefreshToken,
	}
	allGETRoutes := map[string]httprouter.Handle{
		"/ping": heartBeat,
	}
	for endPoint, handler := range allPOSTRoutes {
		router.POST(endPoint, addRequestID(handler))
	}
	for endPoint, handler := range allGETRoutes {
		router.GET(endPoint, addRequestID(handler))
	}

	socket := fmt.Sprintf("%s:%s", host, port)
	logger.Log("Application running on ", socket)
	log.Fatal(http.ListenAndServe(socket, router))
	return
}
