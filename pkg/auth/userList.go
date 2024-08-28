package auth

import (
	"context"
	"strconv"
	"strings"
	"time"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/communication"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/logger"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/util"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/validator"
)

// ParamsUsers params for getting all users associated with a mobilenumber
type ParamsUsers struct {
	IsForNonTradingSession bool
	IsForTradingSession    bool
	MobileNumber           int64
	Password               string
	Otp                    int64
}

// Validate ...
// Validate the data required for GetUserList
func (p ParamsUsers) validate() *ErrAuth {
	errs := &ErrAuth{}
	if isValid := validator.IsValidMobileNumber(p.MobileNumber); !isValid {
		errs.Add("MobileNumber", validator.ErrInvalidMobile)
	}
	if p.Password == "" {
		errs.Add("MobileNumber", validator.ErrInvalidMobile)
	}
	if !p.IsForNonTradingSession && !p.IsForTradingSession {
		errs.Add("InvalidRequest", "Both IsForNonTradingSession and IsForTradingSession can not be false")
	}
	if p.Otp == 0 {
		errs.Add("Otp", validator.ErrInvalidMobile)
	}
	return errs
}

// ResponseUserList ResponseUserList
type ResponseUserList struct {
	Users    []AUCDetails
	Password string
}

// AUCDetails AUCDetails
type AUCDetails struct {
	AUC        string
	ClientName string
}

// GetUserList GetUserList
func GetUserList(ctx context.Context, params ParamsUsers) (*ResponseUserList, *ErrAuth) {
	requestID := ctx.Value(communication.HttpHeaderRequestID).(string)
	validationErrs := params.validate()
	if validationErrs != nil && len(*validationErrs) > 0 {
		return nil, validationErrs
	}
	cachedUser, err := GetOtpUserFromCache(ctx, params.MobileNumber)
	if err != nil {
		logger.Log(requestID, " ::: ", "Error in GetOtpUserFromCache: ", err.Error())
		switch err.Error() {
		case errorConfig.UserNotFound:
			validationErrs.Add("Mobile", validator.ErrInvalidMobile)
			return nil, validationErrs
		default:
			validationErrs.Add(errorConfig.InternalServerError, errorConfig.InternalServerError)
			return nil, validationErrs
		}
	}
	decodedPassword, err := util.Base64URLDecode(params.Password)
	if err != nil {
		logger.Log(requestID, " ::: ", "decodedPassword util.Base64URLDecode ", err.Error())
		validationErrs.Add("Password", validator.ErrInvalidPassword)
		return nil, validationErrs
	}
	isValidOtp := false
	if params.IsForTradingSession {
		// check if any Otp is pending verification
		if cachedUser.TradingOtpStatus != otpConfig.StatusPending {
			validationErrs.Add("Otp", validator.ErrInvalidOtp)
			return nil, validationErrs
		}
		if cachedUser.TradingHashedOtp == nil {
			validationErrs.Add("Otp", validator.ErrInvalidOtp)
			return nil, validationErrs
		}

		isValidPassword, err := util.ValidateHash(cachedUser.TradingHashedPassword, decodedPassword)
		if err != nil {
			logger.Log(requestID, " ::: ", "isValidPassword util.ValidateHash", err.Error())
			validationErrs.Add(errorConfig.InternalServerError, errorConfig.InternalServerError)
			return nil, validationErrs
		}
		if !isValidPassword {
			validationErrs.Add("Password", validator.ErrInvalidPassword)
			return nil, validationErrs
		}
		isValidOtp, err = util.ValidateHash(cachedUser.TradingHashedOtp, []byte(strconv.FormatInt(params.Otp, 10)))
		if !isValidOtp {
			validationErrs.Add("Otp", validator.ErrInvalidOtp)
			return nil, validationErrs
		}
		if err != nil {
			logger.Log(requestID, " ::: ", "isValidOtp util.ValidateHash", err.Error())
			validationErrs.Add(errorConfig.InternalServerError, errorConfig.InternalServerError)
			return nil, validationErrs
		}
		lrp, err := communication.VerifyOtpMetaOtp(ctx, uint64(params.MobileNumber), uint64(params.Otp))
		if err != nil {
			validationErrs.Add(errorConfig.InternalServerError, errorConfig.InternalServerError)
		}
		if !lrp.Success {
			validationErrs.Add("Otp", lrp.Message)
			return nil, validationErrs
		}
		var userList []AUCDetails
		userData := strings.Split(lrp.Data, "^")
		for _, usl := range userData {
			userLst := strings.Split(usl, "~")
			userAuc := userLst[0]
			userName := userLst[2]
			if userLst[1] == "1" {
				userList = append(userList, AUCDetails{
					AUC:        userAuc,
					ClientName: userName,
				})
			}

		}
		return &ResponseUserList{
			Users: userList,
		}, nil

	}
	// check if any Otp is pending verification
	if cachedUser.OtpStatus != otpConfig.StatusPending {
		validationErrs.Add("Otp", validator.ErrInvalidOtp)
		return nil, validationErrs
	}
	currentUnix := time.Now().Unix()
	// Check expiry
	if cachedUser.ValidUptoUnix < currentUnix {
		validationErrs.Add("Otp", validator.ErrInvalidOtp)
		return nil, validationErrs
	}
	if cachedUser.HashedOtp == nil {
		validationErrs.Add("Otp", validator.ErrInvalidOtp)
		return nil, validationErrs
	}

	isValidPassword, err := util.ValidateHash(cachedUser.HashedPassword, decodedPassword)
	if err != nil {
		logger.Log(requestID, " ::: ", "isValidPassword util.ValidateHash", err.Error())
		validationErrs.Add(errorConfig.InternalServerError, errorConfig.InternalServerError)
		return nil, validationErrs
	}
	if !isValidPassword {
		validationErrs.Add("Password", validator.ErrInvalidPassword)
		return nil, validationErrs
	}
	isValidOtp, err = util.ValidateHash(cachedUser.HashedOtp, []byte(strconv.FormatInt(params.Otp, 10)))
	if !isValidOtp {
		validationErrs.Add("Otp", validator.ErrInvalidOtp)
		return nil, validationErrs
	}
	if err != nil {
		logger.Log(requestID, " ::: ", "isValidOtp util.ValidateHash", err.Error())
		validationErrs.Add(errorConfig.InternalServerError, errorConfig.InternalServerError)
		return nil, validationErrs
	}
	newPassword := util.GenerateRandomBytes(otpConfig.LengthPasswordUserList)
	hashedPassword, err := util.FastYetSecureHash(*newPassword)
	if err != nil {
		logger.Log(requestID, " ::: ", "hashedPassword util.FastYetSecureHash", err.Error())
		validationErrs.Add(errorConfig.InternalServerError, errorConfig.InternalServerError)
		return nil, validationErrs
	}
	/*
		Suppose, first for 2 minutes the user trigerred 3 Otp requests (maybe SMS delivery is running late from SMS gateway)
		Now user triggers 4th request in desperation but otp number:
						1,2 or 3 arrives
							or
						all of them arrive

		we don't have all previous valid otp hasehs in redis!!!


		@toDo thinkover this, and allow user to enter any valid Otp
	*/

	cachedUser.IsOtpVerified = true
	cachedUser.HashedPassword = []byte("")
	cachedUser.HashedOtp = []byte("")
	cachedUser.ValidUptoUnix = 0
	cachedUser.TimeStampsUnix = []int64{}
	cachedUser.OtpStatus = otpConfig.StatusVerified

	cachedUser.MobileNumber = params.MobileNumber

	users := make([]AUCDetails, len(cachedUser.AucCodes))
	for i, v := range cachedUser.AucCodes {
		users[i].AUC = v
		users[i].ClientName = cachedUser.ClientNames[i]
	}
	rsp := &ResponseUserList{
		Users:    users,
		Password: util.Base64URLEncode(*newPassword),
	}
	validUpto := time.Now().Add(aucConfig.TTL).Unix()
	if len(users) > 0 {
		for _, userFromResponse := range users {
			aucUser := &aucUser{
				MobileNumber:   params.MobileNumber,
				ClientName:     userFromResponse.ClientName,
				HashedPassword: hashedPassword,
				ValidUptoUnix:  validUpto,
				AUC:            userFromResponse.AUC,
			}
			err := aucUser.updateCache(ctx, userFromResponse.AUC)
			if err != nil {
				logger.Log(requestID, " ::: ", "error in aucUser.updateCache", validationErrs)
				validationErrs.Add(errorConfig.InternalServerError, errorConfig.InternalServerError)
			}
		}
	}
	if validationErrs != nil && len(*validationErrs) > 0 {
		logger.Log(requestID, " ::: ", "error in aucUser.updateCache", validationErrs)
		validationErrs.Add(errorConfig.InternalServerError, errorConfig.InternalServerError)
		return nil, validationErrs
	}
	err = cachedUser.updateCache(ctx)
	if err != nil {
		logger.Log(requestID, " ::: ", "error in cachedUser.updateCache ", err.Error())
		validationErrs.Add(errorConfig.InternalServerError, errorConfig.InternalServerError)
		return nil, validationErrs
	}
	if validationErrs != nil && len(*validationErrs) > 0 {
		return nil, validationErrs
	}

	return rsp, nil
}
