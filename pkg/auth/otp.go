package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/config"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/communication"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/logger"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/persistence"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/util"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/validator"
)

// otpConfig otpConfig
var (
	otpConfig     *config.Otp
	otpMetaConfig *config.OTPMeta

	fieldNamesOtpUser metaDataFieldNamesOtpUser
	fieldTypesOtpUser metaDataFieldTypesOtpUser
)

const otpUserTableName = "otp_user"

type metaDataFieldNamesOtpUser struct {
	AucCodes              string
	ClientNames           string
	CreatedAt             string
	HashedOtp             string
	HashedPassword        string
	IsOtpVerified         string
	MobileNumber          string
	OtpStatus             string
	TimeStampsUnix        string
	TradingHashedOtp      string
	TradingHashedPassword string
	TradingIsOtpVerified  string
	TradingOtpStatus      string
	UpdatedAt             string
	ValidUptoUnix         string
}

type metaDataFieldTypesOtpUser struct {
	AucCodes              string
	ClientNames           string
	CreatedAt             string
	HashedOtp             string
	HashedPassword        string
	IsOtpVerified         string
	MobileNumber          string
	OtpStatus             string
	TimeStampsUnix        string
	TradingHashedOtp      string
	TradingHashedPassword string
	TradingIsOtpVerified  string
	TradingOtpStatus      string
	UpdatedAt             string
	ValidUptoUnix         string
}

type OtpUser struct {
	AucCodes              []string `json:"aucCodes"`
	ClientNames           []string `json:"clientNames"`
	CreatedAt             int64    `json:"createdAt"`
	HashedOtp             []byte   `json:"hashedOtp"`
	HashedPassword        []byte   `json:"hashedPassword"`
	IsOtpVerified         bool     `json:"isOtpVerified"`
	MobileNumber          int64    `json:"mobileNumber"`
	OtpStatus             string   `json:"otpStatus"`
	TimeStampsUnix        []int64  `json:"timeStampsUnix"`
	TradingHashedOtp      []byte   `json:"tradingHashedOtp"`
	TradingHashedPassword []byte   `json:"tradingHashedPassword"`
	TradingIsOtpVerified  bool     `json:"tradingIsOtpVerified"`
	TradingOtpStatus      string   `json:"tradingOtpStatus"`
	UpdatedAt             int64    `json:"updatedAt"`
	ValidUptoUnix         int64    `json:"validUptoUnix"`
}

type FieldSelectOtpUser struct {
	AucCodes              bool
	ClientNames           bool
	CreatedAt             bool
	HashedOtp             bool
	HashedPassword        bool
	IsOtpVerified         bool
	MobileNumber          bool
	OtpStatus             bool
	TimeStampsUnix        bool
	TradingHashedOtp      bool
	TradingHashedPassword bool
	TradingIsOtpVerified  bool
	TradingOtpStatus      bool
	UpdatedAt             bool
	ValidUptoUnix         bool
}

// ParamsOtp ...
type ParamsOtp struct {
	MobileNumber           int64
	IsForTradingSession    bool
	IsForNonTradingSession bool
}

// Validate ...
//
// Validate the data required for GenerateOtp
func (p ParamsOtp) validate() *ErrAuth {
	errs := &ErrAuth{}
	isValid := validator.IsValidMobileNumber(p.MobileNumber)
	if !isValid {
		errs.Add("MobileNumber", validator.ErrInvalidMobile)
	}
	return errs
}

// Update Update user in cache
func (o *OtpUser) updateCache(ctx context.Context) error {
	mobileNumber := strconv.FormatInt(o.MobileNumber, 10)
	// Make sure the hash exists in redis before calling this function
	// Could have written one extra redis call to check if hash exists or
	// not, but chosen to call this function only in relevant scenario
	redisMap := o.createRedisMap()
	rc := &persistence.ChannelRedis{
		Done: make(chan bool),
	}
	go persistence.DB.HSetFields(ctx, rc, mobileNumber, *redisMap)
	<-rc.Done
	if rc.Err != nil {
		return rc.Err
	}
	return nil
}

func (o *OtpUser) createRedisMap() *map[string]interface{} {
	redisMap := make(map[string]interface{})
	redisMap[fieldNamesOtpUser.IsOtpVerified] = o.IsOtpVerified

	if o.TradingHashedPassword != nil {
		if len(o.TradingHashedPassword) > 0 {
			redisMap[fieldNamesOtpUser.TradingHashedPassword] = util.Base64URLEncode(o.TradingHashedPassword)
		}
	}
	if o.TradingOtpStatus != "" {
		redisMap[fieldNamesOtpUser.TradingOtpStatus] = o.TradingOtpStatus
	}

	if o.TradingIsOtpVerified {
		redisMap[fieldNamesOtpUser.TradingIsOtpVerified] = "1"
	} else {
		redisMap[fieldNamesOtpUser.TradingIsOtpVerified] = "0"
	}
	if o.TradingHashedOtp != nil {
		if len(o.TradingHashedOtp) > 0 {
			redisMap[fieldNamesOtpUser.TradingHashedOtp] = util.Base64URLEncode(o.TradingHashedOtp)
		}
	}

	// we can pass an empty string "", to empty to hashedOtp
	// hence don't check len(o.HashedOtp) > 0
	if o.HashedOtp != nil {
		if len(o.HashedOtp) > 0 {
			redisMap[fieldNamesOtpUser.HashedOtp] = util.Base64URLEncode(o.HashedOtp)
		}
	}
	// we can pass an empty string "", to empty to Password
	// hence don't check len(o.HashedPassword) > 0
	if o.HashedPassword != nil {
		if len(o.HashedPassword) > 0 {
			redisMap[fieldNamesOtpUser.HashedPassword] = util.Base64URLEncode(o.HashedPassword)
		}
	}

	if o.AucCodes != nil {
		if len(o.AucCodes) > 0 {
			redisMap[fieldNamesOtpUser.AucCodes] = strings.Join(o.AucCodes, otpConfig.DelimiterForSliceJoinNSplit)
		}
	}
	if o.ClientNames != nil {
		if len(o.ClientNames) > 0 {
			redisMap[fieldNamesOtpUser.ClientNames] = strings.Join(o.ClientNames, otpConfig.DelimiterForSliceJoinNSplit)
		}
	}
	if o.TimeStampsUnix != nil {
		if len(o.TimeStampsUnix) > 0 {
			stringTimestamps := make([]string, len(o.TimeStampsUnix))
			for i, v := range o.TimeStampsUnix {
				stringTimestamps[i] = strconv.FormatInt(v, 10)
			}
			redisMap[fieldNamesOtpUser.TimeStampsUnix] = strings.Join(stringTimestamps, otpConfig.DelimiterForSliceJoinNSplit)
		}

	}
	if o.ValidUptoUnix != 0 {
		strUnix := strconv.FormatInt(o.ValidUptoUnix, 10)
		redisMap[fieldNamesOtpUser.ValidUptoUnix] = strUnix
	}
	if o.OtpStatus != "" {
		redisMap[fieldNamesOtpUser.OtpStatus] = o.OtpStatus
	}

	if o.IsOtpVerified {
		redisMap[fieldNamesOtpUser.IsOtpVerified] = "1"
	} else {
		redisMap[fieldNamesOtpUser.IsOtpVerified] = "0"
	}

	return &redisMap
}

// GetOtpUserFromCache GetOtpUserFromCache
func GetOtpUserFromCache(ctx context.Context, m int64) (*OtpUser, error) {
	requestID := ctx.Value(communication.HttpHeaderRequestID).(string)
	mobileNumber := strconv.FormatInt(m, 10)
	dataFromCache := &OtpUser{}
	rc := &persistence.ChannelRedisMap{
		Done: make(chan bool),
	}
	go persistence.DB.HashGetAll(ctx, mobileNumber, rc)
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
	if otpFromRedis, ok := redisMap[fieldNamesOtpUser.TradingHashedOtp]; ok {
		if len(otpFromRedis) > 0 {
			hashedOtp, err := util.Base64URLDecode(otpFromRedis)
			if err != nil {
				logger.Log(requestID, " ::: ", "TradingHashedOtp from redis is not a valid Base64URLEncoded data")
				return nil, err
			}
			dataFromCache.TradingHashedOtp = hashedOtp
		}
	}
	if v, ok := redisMap[fieldNamesOtpUser.TradingHashedPassword]; ok {
		if len(v) > 0 {
			pass, err := util.Base64URLDecode(v)
			if err != nil {
				logger.Log(requestID, " ::: ", "TradingHashedPassword from redis is not a valid Base64URLEncoded data")
				return nil, err
			}
			dataFromCache.TradingHashedPassword = pass
		}
	}
	if v, ok := redisMap[fieldNamesOtpUser.TradingIsOtpVerified]; ok {
		dataFromCache.TradingIsOtpVerified = v == "1"
	}
	if v, ok := redisMap[fieldNamesOtpUser.TradingOtpStatus]; ok {
		dataFromCache.TradingOtpStatus = v
	}

	if otpFromRedis, ok := redisMap[fieldNamesOtpUser.HashedOtp]; ok {
		if len(otpFromRedis) > 0 {
			hashedOtp, err := util.Base64URLDecode(otpFromRedis)
			if err != nil {
				logger.Log(requestID, " ::: ", "HashedOtp from redis is not a valid Base64URLEncoded data")
				return nil, err
			}
			dataFromCache.HashedOtp = hashedOtp
		}
	}
	if v, ok := redisMap[fieldNamesOtpUser.HashedPassword]; ok {
		if len(v) > 0 {
			pass, err := util.Base64URLDecode(v)
			if err != nil {
				logger.Log(requestID, " ::: ", "HashedPassword from redis is not a valid Base64URLEncoded data")
				return nil, err
			}
			dataFromCache.HashedPassword = pass
		}
	}

	if v, ok := redisMap[fieldNamesOtpUser.IsOtpVerified]; ok {
		dataFromCache.IsOtpVerified = v == "1"
	}
	if v, ok := redisMap[fieldNamesOtpUser.AucCodes]; ok {
		if len(v) > 0 {
			dataFromCache.AucCodes = strings.Split(v, otpConfig.DelimiterForSliceJoinNSplit)
		}
	}
	if v, ok := redisMap[fieldNamesOtpUser.ClientNames]; ok {
		if len(v) > 0 {
			dataFromCache.ClientNames = strings.Split(v, otpConfig.DelimiterForSliceJoinNSplit)
		}
	}

	if v, ok := redisMap[fieldNamesOtpUser.OtpStatus]; ok {
		dataFromCache.OtpStatus = v
	}
	if v, ok := redisMap[fieldNamesOtpUser.ValidUptoUnix]; ok {
		if len(v) > 0 {
			// Truncating the type int64 value to type int32 is an example of the Year 2038 problem
			intTimeStamp, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				logger.Log(requestID, " ::: ", "ValidUptoUnix from redis is not a valid intTimeStamp")
				return nil, err
			}
			dataFromCache.ValidUptoUnix = intTimeStamp
		}

	}
	if v, ok := redisMap[fieldNamesOtpUser.TimeStampsUnix]; ok {
		if len(v) > 0 {
			stamps := strings.Split(v, otpConfig.DelimiterForSliceJoinNSplit)
			if len(stamps) > 0 {
				intStamps := make([]int64, len(stamps))
				for idx, stamp := range stamps {
					// Truncating the type int64 value to type int32 is an example of the Year 2038 problem
					intTimeStamp, err := strconv.ParseInt(stamp, 10, 64)
					if err != nil {
						logger.Log(requestID, " ::: ", "the ", otpConfig.DelimiterForSliceJoinNSplit, "separated TimeStampsUnix from redis is not a valid intTimeStamp")
						return nil, err
					}
					intStamps[idx] = intTimeStamp
				}
				dataFromCache.TimeStampsUnix = intStamps
			}
		}

	}
	return dataFromCache, nil
}

// GenerateOtp returns otp, errors
//
// # For successful generation of Otp, a valid token is a must
//
// otp: is a string,
// errors: is ErrAuth
//
// errors looks like so:
// {"RedisError":["m1","m2",..],"MobileNumber":["ErrorMessage1","ErrorMessage2",..]}
func GenerateOtp(ctx context.Context, params ParamsOtp) (string, *ErrAuth) {
	requestID := ctx.Value(communication.HttpHeaderRequestID).(string)
	var (
		password        string
		err             error
		validTimeStamps = []int64{}
		unixNow         = time.Now().Unix()
	)
	validationErrs := params.validate()
	if validationErrs != nil && len(*validationErrs) > 0 {
		return "", validationErrs
	}
	if params.IsForTradingSession {
		password, err = handleTradingSessionOtp(ctx, params)
		if err != nil {
			if password == "0" {
				validationErrs.Add("MobileNumber", err.Error())
				return "", validationErrs
			}
			logger.Log(requestID, " ::: ", "Error in handleTradingSessionOtp: ", err.Error())
			validationErrs.Add(errorConfig.InternalServerError, errorConfig.InternalServerError)
			return "", validationErrs
		}
		return password, nil
	}

	user, err := GetOtpUserFromCache(ctx, params.MobileNumber)
	if err != nil {
		switch err.Error() {
		case errorConfig.UserNotFound:
			user = &OtpUser{}
		default:
			logger.Log(requestID, " ::: ", "Error in GetOtpUserFromCache: ", err.Error())
			validationErrs.Add(errorConfig.InternalServerError, errorConfig.InternalServerError)
			return "", validationErrs
		}
	}
	// if Delimiter is "," then "t1,t2,t3" => []slice{"t1","t2","t3"}
	otpTimestamps := user.TimeStampsUnix
	// Remove invalid Otps from redis
	for _, existingTimeStamp := range otpTimestamps {
		// A user should not be able to generate for than otpConfig.MaxOtpCount
		// in otpConfig.TTLForOtp duration of time
		if existingTimeStamp > unixNow {
			// Otp has not expired yet
			// we keep a list of valid Otps
			validTimeStamps = append(validTimeStamps, existingTimeStamp)
		}
	}
	if len(validTimeStamps) < int(otpConfig.Limit) {
		password, err = trigerAUCAPI(ctx, params, validTimeStamps)
		if err != nil {
			switch err.Error() {
			case errorConfig.UserNotFound, "No record found!":
				password = util.Base64URLEncode(*util.GenerateRandomBytes(otpConfig.LengthPasswordOtpGenerate))
				// to make sure that an attacker does not get to know
				// if a mobile number has an trading account or not
				// we send normal response
			default:
				logger.Log(requestID, " ::: ", "Failed to send AUC", err.Error())
				validationErrs.Add(errorConfig.InternalServerError, errorConfig.InternalServerError)
				return "", validationErrs
			}
		}
		return password, nil
	}
	validationErrs.Add("MobileNumber", errorConfig.OtpQuotaExhausted)
	return "", validationErrs
}
func handleTradingSessionOtp(ctx context.Context, params ParamsOtp) (string, error) {
	user, err := GetOtpUserFromCache(ctx, params.MobileNumber)
	if err != nil {
		switch err.Error() {
		case errorConfig.UserNotFound:
			user = &OtpUser{}
		default:
			return "", err
		}
	}
	otpMetaSMSReq := communication.OtpMetaSMS{
		MobileNumber: uint64(params.MobileNumber),
	}
	otpMetaSMSResponse, err := otpMetaSMSReq.Send(ctx)
	if err != nil {
		return "", err
	}
	password := util.GenerateRandomBytes(otpConfig.LengthPasswordOtpGenerate)
	switch {
	case (otpMetaSMSResponse.Success == false) && otpMetaSMSResponse.Message != "":
		return "0", errors.New(otpMetaSMSResponse.Message)
	case otpMetaSMSResponse.Success == true:
		encKey := []byte(otpMetaConfig.Otp.EncryptionKey)
		encryptedOtpBytes, err := util.Base64STDDecodeString(otpMetaSMSResponse.Data)
		if err != nil {
			logger.Log("failed to base64decode encryptedOtpBytes")
			return "", fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, err.Error())
		}
		b, err := util.AES256GCMDecrypt(&encryptedOtpBytes, &encKey)
		if err != nil {
			logger.Log("failed to AES256GCMDecrypt encryptedOtpBytes")
			return "", fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, err.Error())
		}
		otp := *b
		logger.Log(string(otp))
		hashedOtp, err := util.FastYetSecureHash(otp)
		if err != nil {
			return "", fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, err.Error())
		}
		hashedPassword, err := util.FastYetSecureHash(*password)
		if err != nil {
			return "", fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, err.Error())
		}
		user.MobileNumber = params.MobileNumber
		user.TradingHashedPassword = hashedPassword
		user.TradingHashedOtp = hashedOtp
		user.TradingIsOtpVerified = false
		user.TradingOtpStatus = otpConfig.StatusPending
		// user.HashedOtp = []byte{}
		// user.HashedPassword = []byte{}
		// user.TimeStampsUnix = []int64{}
		// user.AucCodes = []string{}
		// user.ClientNames = []string{}

		err = user.updateCache(ctx)
		if err != nil {
			return "", err
		}
	}
	return util.Base64URLEncode(*password), nil
}

func sendOtp(ctx context.Context, aucData []auc, timestamps []int64) (string, error) {
	requestID := ctx.Value(communication.HttpHeaderRequestID).(string)
	numAuc := len(aucData)
	if aucData == nil || numAuc == 0 {
		return "", errors.New(errorConfig.UserNotFound)
	}
	mobileNumber, err := strconv.ParseInt(aucData[0].MobileNumber, 10, 64) // mobile number will be same at all indexes
	if err != nil {
		logger.Log(requestID, " ::: ", "Invalid mobileNumber sent by SMS gateway in response", aucData)
		return "", fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, err.Error())
	}
	otp := util.GenerateRandomInteger(otpConfig.Length)
	hashedOtp, err := util.FastYetSecureHash(otp)
	if err != nil {
		return "", fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, err.Error())
	}
	var (
		aucCodes    []string
		clientNames []string
	)
	if numAuc > 1 {
		clientNames = make([]string, numAuc)
		aucCodes = make([]string, numAuc)
		for i, auc := range aucData {
			aucCodes[i] = auc.Code
			clientNames[i] = auc.ClientName
		}
	} else {
		aucCodes = []string{aucData[0].Code}
		clientNames = []string{aucData[0].ClientName}
	}

	validUpto := time.Now().Add(otpConfig.TTL).Unix()
	stringOtp := string(otp)
	message := fmt.Sprintf("Dear Client, your Otp is %s will be valid for the day.", stringOtp)
	sms := &communication.SMS{
		MobileNumber: mobileNumber,
		Content:      message,
	}
	smsResponse, err := sms.Send(ctx)
	if err != nil {
		// Maybe the HTTP request failed (timedout etc...)
		// Maybe the sms gateway misbehaved and sent invalid or an unknown response structure
		return "", err
	}
	password := util.GenerateRandomBytes(otpConfig.LengthPasswordOtpGenerate)
	hashedPassword, err := util.FastYetSecureHash(*password)
	if err != nil {
		return "", fmt.Errorf("%s%s%s", errorConfig.InternalServerError, errorConfig.Delimiter, err.Error())
	}
	switch smsResponse.Success {
	case true:
		timestamps = append(timestamps, validUpto)
		otpUser := &OtpUser{
			MobileNumber:   mobileNumber,
			HashedPassword: hashedPassword,
			HashedOtp:      hashedOtp,
			AucCodes:       aucCodes,
			ClientNames:    clientNames,
			IsOtpVerified:  false,
			ValidUptoUnix:  validUpto,
			TimeStampsUnix: timestamps,
			OtpStatus:      otpConfig.StatusPending,
			// TradingHashedPassword: []byte{},
			// TradingHashedOtp:      []byte{},
		}
		err = otpUser.updateCache(ctx)
		if err != nil {
			return "", err
		}
		return util.Base64URLEncode(*password), nil
	case false:
		logger.Log(requestID, " ::: ", "Failed to send SMS. Error message from gateway: ", smsResponse.Message)
		return "", errors.New(errorConfig.SmsGatewayError + " " + smsResponse.Message)
	}
	return "", nil
}
