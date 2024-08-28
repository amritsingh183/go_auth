package communication

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/config"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/logger"
)

var (
	httpConfig *config.HTTP
)

const (
	HttpHeaderRequestID   = "x-req-id"
	ErrInvalidContentType = "INVALID_CONTENT_TYPE"
	ErrHTTPMethod         = "INVALID_HTTP_METHOD"
	HTTPMethodPOST        = "POST"
	HTTPMethodGET         = "GET"
	HTTPContentTypeJSON   = "application/json;charset=UTF-8"
	HTTPContentTypeText   = "text/plain;charset=UTF-8"
	HTTPContentTypeHTML   = "text/html;charset=UTF-8"
)

// HTTPResponse ...
type HTTPResponse struct {
	Body  []byte
	Error error
	Done  chan bool
}

// HTTP HTTP
type HTTP struct {
	Method      string
	URL         string
	Body        []byte
	ContentType string
}

// Send ...
func (h *HTTP) Send(ctx context.Context, response *HTTPResponse) {
	requestID := ctx.Value(HttpHeaderRequestID).(string)
	var (
		req *http.Request
		err error
	)
	// Create new request with given Method
	switch h.Method {
	case HTTPMethodPOST:
		req, err = http.NewRequestWithContext(ctx, HTTPMethodPOST, h.URL, bytes.NewBuffer(h.Body))
	case HTTPMethodGET:
		req, err = http.NewRequestWithContext(ctx, HTTPMethodGET, h.URL, nil)
	default:
		err = errors.New(ErrHTTPMethod)
	}
	if err != nil {
		logger.Log(requestID, " ::: ", "The code needs improvement,  nothing wrong with user input")
		// Since this function is used only internally
		// If we enter this block, then it is our code that needs improvement
		// There is nothing wrong with user input
		response.Body = nil
		response.Error = fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, err.Error())
		response.Done <- true
		return
	}

	// Set vallid Content type
	switch h.ContentType {
	case HTTPContentTypeJSON:
		req.Header.Add("Content-Type", HTTPContentTypeJSON)
	case HTTPContentTypeText:
		req.Header.Add("Content-Type", HTTPContentTypeText)
	case HTTPContentTypeHTML:
		req.Header.Add("Content-Type", HTTPContentTypeHTML)
	default:
		err = errors.New(ErrInvalidContentType)
	}
	if err != nil {
		logger.Log(requestID, " ::: ", "The code needs improvement,  nothing wrong with user input")
		// Since this function is used only internally
		// If we enter this block, then it is our code that needs improvement
		// There is nothing wrong with user input
		response.Body = nil
		response.Error = fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, err.Error())
		response.Done <- true
		return
	}

	resp, err := hclient.Do(req)
	if err != nil {
		response.Body = nil
		response.Error = err
		response.Done <- true
		return
	}
	logger.Log(requestID, " ::: ", h.Method, ":", h.URL, ":", h.ContentType, ":", resp.Status, ":", resp.StatusCode)
	defer resp.Body.Close()
	// We know that our response is going to be small
	// therefore we read all of it
	// otherwise
	// we would need to buffer it
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		response.Body = nil
		response.Error = err
		response.Done <- true
		return
	}
	response.Body = body
	response.Error = nil
	response.Done <- true
	return
}
