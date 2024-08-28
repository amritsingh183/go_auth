package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/config"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/communication"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/logger"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/persistence"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/util"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/validator"
)

var (
	aucConfig         *config.AUC
	authJWTConfig     *config.JWT
	refreshJWTConfig  *config.JWT
	fieldNamesAUCuser aucUserFieldMap
	fieldTypesAUCUser aucUserFieldTypeMap
)

// ParamsAUC Params for AUC Request
type ParamsAUC struct {
	MobileNumber int64
}

// Validate ...
//
// Validate the data required for GenerateOtp
func (p ParamsAUC) Validate() *ErrAuth {
	errs := &ErrAuth{}
	isValid := validator.IsValidMobileNumber(p.MobileNumber)
	if !isValid {
		errs.Add("MobileNumber", validator.ErrInvalidMobile)
	}
	return errs
}

// aucUser aucUser
type aucUser struct {
	JTIForAuthJWT    []string
	JTIForRefreshJWT []string
	MobileNumber     int64
	ClientName       string
	HashedPassword   []byte
	// After getting the list of users from GetUserList
	// How long can the user wait to make his first
	// JWT request
	ValidUptoUnix int64
	// DB
	AUC       string
	CreatedAt int64
	UpdatedAt int64
}

// otpFieldMap otpFieldMap Map
type aucUserFieldMap struct {
	JTIForAuthJWT    string
	JTIForRefreshJWT string
	MobileNumber     string
	ClientName       string
	HashedPassword   string
	ValidUptoUnix    string
	// DB
	AUC       string
	CreatedAt string
	UpdatedAt string
}

// aucUserFieldTypeMap aucUserFieldTypeMap Map
type aucUserFieldTypeMap struct {
	JTIForAuthJWT    string
	JTIForRefreshJWT string
	MobileNumber     string
	ClientName       string
	HashedPassword   string
	ValidUptoUnix    string
	// DB fields
	AUC       string
	CreatedAt string
	UpdatedAt string
}

func (au *aucUser) createRedisMap() *map[string]interface{} {
	redisMap := make(map[string]interface{})
	if au.HashedPassword != nil {
		if len(au.HashedPassword) > 0 {
			redisMap[fieldNamesAUCuser.HashedPassword] = util.Base64URLEncode(au.HashedPassword)
		}
	}
	if au.ValidUptoUnix != 0 {
		strUnix := strconv.FormatInt(au.ValidUptoUnix, 10)
		redisMap[fieldNamesAUCuser.ValidUptoUnix] = strUnix
	}
	if au.JTIForAuthJWT != nil {
		if len(au.JTIForAuthJWT) > 0 {
			redisMap[fieldNamesAUCuser.JTIForAuthJWT] = strings.Join(au.JTIForAuthJWT, otpConfig.DelimiterForSliceJoinNSplit)
		}
	}
	if au.JTIForRefreshJWT != nil {
		if len(au.JTIForRefreshJWT) > 0 {
			redisMap[fieldNamesAUCuser.JTIForRefreshJWT] = strings.Join(au.JTIForRefreshJWT, otpConfig.DelimiterForSliceJoinNSplit)
		}
	}
	redisMap[fieldNamesAUCuser.MobileNumber] = au.MobileNumber
	redisMap[fieldNamesAUCuser.ClientName] = au.ClientName
	return &redisMap
}

// Update Update aucUser in cache
func (au *aucUser) updateCache(ctx context.Context, auc string) error {
	// Make sure the hash exists in redis before calling this function
	// Could have written one extra redis call to check if hash exists or
	// not, but chosen to call this function only in relevant scenario
	redisMap := au.createRedisMap()
	rc := &persistence.ChannelRedis{
		Done: make(chan bool),
	}
	go persistence.DB.HSetFields(ctx, rc, auc, *redisMap)
	<-rc.Done
	if rc.Err != nil {
		return rc.Err
	}
	return nil
}

// getAUCUserFromCache getAUCUserFromCache
func getAUCUserFromCache(ctx context.Context, auc string) (*aucUser, error) {
	requestID := ctx.Value(communication.HttpHeaderRequestID).(string)
	dataFromCache := &aucUser{}
	rc := &persistence.ChannelRedisMap{
		Done: make(chan bool),
	}
	go persistence.DB.HashGetAll(ctx, auc, rc)
	<-rc.Done
	switch true {
	case rc.Err != nil:
		//If we are here, there is some problem with redis server or redis connection
		logger.Log(requestID, " ::: ", "Failed to get data from cache: ", rc.Err.Error())
		return nil, errors.New(errorConfig.RedisError)
	case rc.Value == nil:
		logger.Log(requestID, " ::: ", "User does not exist in cache: ")
		return nil, errors.New(errorConfig.UserNotFound)
	case len(rc.Value) == 0:
		logger.Log(requestID, " ::: ", "User does not exist in cache: ")
		return nil, errors.New(errorConfig.UserNotFound)
	}
	redisMap := rc.Value
	if v, ok := redisMap[fieldNamesAUCuser.HashedPassword]; ok {
		if len(v) > 0 {
			pass, err := util.Base64URLDecode(v)
			if err != nil {
				return nil, err
			}
			dataFromCache.HashedPassword = pass
		}
	}
	if v, ok := redisMap[fieldNamesAUCuser.ValidUptoUnix]; ok {
		if len(v) > 0 {
			// Truncating the type int64 value to type int32 is an example of the Year 2038 problem
			intTimeStamp, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return nil, err
			}
			dataFromCache.ValidUptoUnix = intTimeStamp
		}
	}
	if v, ok := redisMap[fieldNamesAUCuser.ClientName]; ok {
		dataFromCache.ClientName = v
	}
	if v, ok := redisMap[fieldNamesAUCuser.JTIForAuthJWT]; ok {
		if len(v) > 0 {
			dataFromCache.JTIForAuthJWT = strings.Split(v, otpConfig.DelimiterForSliceJoinNSplit)
		}
	}
	if v, ok := redisMap[fieldNamesAUCuser.JTIForRefreshJWT]; ok {
		if len(v) > 0 {
			dataFromCache.JTIForRefreshJWT = strings.Split(v, otpConfig.DelimiterForSliceJoinNSplit)
		}
	}
	if v, ok := redisMap[fieldNamesAUCuser.MobileNumber]; ok {
		mobileNum, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, err
		}
		dataFromCache.MobileNumber = mobileNum
	}
	return dataFromCache, nil
}

type requestSpecAUC struct {
	Value             string `json:"Value"`
	Type              string `json:"Type"`
	ApplicationSource string `json:"ApplicationSource"`
	IPAddress         string `json:"IpAddress"`
	UserID            string `json:"UserId"`
}

// AUC AUC
type auc struct {
	Code         string `json:"AUC"`
	MobileNumber string `json:"Mobile"`
	PartyCode    string `json:"PartyCode"`
	ErrorMessage string `json:"ErrorMessage"`
	ClientName   string `json:"ClientName"`
}
type apiResponseAUCServer struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
	Data    []auc  `json:"data"`
}

// trigerAUCAPI ...
// Trigger an AUC request
func trigerAUCAPI(ctx context.Context, params ParamsOtp, timestamps []int64) (string, error) {
	requestID := ctx.Value(communication.HttpHeaderRequestID).(string)
	mobileNumber := strconv.FormatInt(params.MobileNumber, 10)
	aucRequest := &requestSpecAUC{
		Value:             mobileNumber,
		ApplicationSource: aucConfig.ApplicationSource,
		IPAddress:         aucConfig.IPAddress,
		Type:              "M",
		UserID:            "",
	}
	jsonBytes, err := json.Marshal(aucRequest)
	if err != nil {
		// Something wrong with our config
		return "", fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, err.Error())
	}
	httpReq := &communication.HTTP{
		Method:      communication.HTTPMethodPOST,
		URL:         aucConfig.URL,
		Body:        jsonBytes,
		ContentType: communication.HTTPContentTypeJSON,
	}
	rspCh := &communication.HTTPResponse{
		Done: make(chan bool),
	}
	go httpReq.Send(ctx, rspCh)
	<-rspCh.Done
	if rspCh.Error != nil {
		return "", rspCh.Error
	}

	aucResp := &apiResponseAUCServer{}
	err = json.Unmarshal(rspCh.Body, aucResp)
	if err != nil {
		// Nothing wrong with user input
		// THE AUC server has not adhered to the predefined struct apiResponseAUCServer
		logger.Log(requestID, " ::: ", string(rspCh.Body))
		return "", fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, err.Error())
	}
	if aucResp.Status == false {
		// aucResp looks like
		// &{false No record found! []}
		// &{true Fetched successfully! [{ACK002233-0000 1234567899 ALLD  John Doe}]}
		if aucResp.Message != "" {
			// return the error message sent by AUC API
			return "", errors.New(aucResp.Message)
		}
		message := "AUC API call failed with status=false, but no message was provided by them"
		return "", fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, message)
	}
	if aucResp.Data == nil || len(aucResp.Data) == 0 {
		return "", errors.New(errorConfig.UserNotFound)
	}
	password, err := sendOtp(ctx, aucResp.Data, timestamps)
	if err != nil {
		return "", err
	}
	return password, nil
}
