package auth

import (
	"context"
	"fmt"
	"io/ioutil"
	"time"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/communication"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/config"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/logger"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/util"
	"amritsingh374.bitbucket.org/cloud/auth/pkg/validator"
	"github.com/dgrijalva/jwt-go"
)

const (
	TypeAuthToken = iota + 999
	TypeRefreshToken
)

// ABLClaim ABLClaim
type ABLClaim struct {
	Aud     []string `json:"aud"`
	Purpose int      `json:"purpose"`
	AUC     string   `json:"auc"`
	jwt.StandardClaims
}

func (claims *ABLClaim) createSignedToken(jwtConfig *config.JWT) (string, error) {
	var (
		jwtTokenSigned string
	)
	switch true {
	case jwtConfig.HMAC != nil:
		unSignedAccessToken := jwt.NewWithClaims(jwtConfig.HMAC.Algo, claims)
		signedTokenString, err := unSignedAccessToken.SignedString([]byte(jwtConfig.HMAC.SigningKey))
		if err != nil {
			return "", fmt.Errorf("INVALID SIGNING KEY: %v", err)
		}
		return signedTokenString, nil

	case jwtConfig.RSA != nil:
		privateKey, err := ioutil.ReadFile(jwtConfig.RSA.PrivateKey)
		if err != nil {
			return "", fmt.Errorf("error reading private key file: %v", err)
		}
		key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
		if err != nil {
			return "", fmt.Errorf("error parsing RSA private key: %v", err)
		}
		jwtUnsigned := jwt.NewWithClaims(jwtConfig.RSA.Algo, claims)
		jwtTokenSigned, err = jwtUnsigned.SignedString(key)
		if err != nil {
			return "", fmt.Errorf("error signing jwt: %v", err)
		}
	}
	return jwtTokenSigned, nil
}

// ParamsVerifyJWT ParamsVerifyJWT
type ParamsVerifyJWT struct {
	JWT  string
	Type int
	AUC  string
	Host string
}

// ResponseJWTVerification ResponseJWTVerification
type ResponseJWTVerification struct {
	IsValid bool
}

// Validate ...
// Validate the data required for ValidateJWT
func (pw ParamsVerifyJWT) validate() *ErrAuth {
	errs := &ErrAuth{}
	if pw.JWT == "" {
		errs.Add("JWT", validator.ErrInvalidJWT)
	}
	if pw.AUC == "" {
		errs.Add("AUC", validator.ErrInvalidJWT)
	}
	if pw.Host == "" {
		errs.Add("Host", validator.ErrInvalidJWT)
	}
	if pw.Type == 0 {
		errs.Add("Type", validator.ErrInvalidJWT)
	}
	return errs
}

// RSACredJWT RSACredJWT
type RSACredJWT struct {
	Algo       *jwt.SigningMethodRSA
	PrivateKey string
	PublicKey  string
}

// HMACCredJWT HMACCredJWT
type HMACCredJWT struct {
	Algo       *jwt.SigningMethodHMAC
	SigningKey string
}

// ParamsJWT ParamsJWT
type ParamsJWT struct {
	AUC      string
	Password string
}

// ResponseJWT ResponseJWT
type ResponseJWT struct {
	JWTForAuth    string
	JWTForRefresh string
}

// Validate ...
// Validate the data required for GetJWT
func (pw ParamsJWT) validate() *ErrAuth {
	errs := &ErrAuth{}
	if pw.Password == "" {
		errs.Add("Password", validator.ErrInvalidMobile)
	}
	if pw.AUC == "" {
		errs.Add("AUC", validator.ErrInvalidMobile)
	}
	return errs
}
func getUnixTimeAfternDays(ndays uint, hr, min, sec int) int64 {
	loc, _ := time.LoadLocation("Asia/Kolkata")
	y, m, d := time.Now().In(loc).AddDate(0, 0, int(ndays)).Date()
	return time.Date(y, m, d, hr, min, sec, 0, loc).Unix()
}

// GetJWT GetJWT
func GetJWT(ctx context.Context, params ParamsJWT) (*ResponseJWT, *ErrAuth) {
	requestID := ctx.Value(communication.HttpHeaderRequestID).(string)
	validationErrs := params.validate()
	if validationErrs != nil && len(*validationErrs) > 0 {
		return nil, validationErrs
	}
	cachedAUCUser, err := getAUCUserFromCache(ctx, params.AUC)
	if err != nil {
		switch err.Error() {
		case errorConfig.UserNotFound:
			validationErrs.Add("AUC", validator.ErrInvalidAUC)
			return nil, validationErrs
		default:
			validationErrs.Add(errorConfig.InternalServerError, err.Error())
			return nil, validationErrs
		}
	}
	if cachedAUCUser.ValidUptoUnix < time.Now().Unix() {
		validationErrs.Add("AUC", validator.ErrExpiredAUC)
		return nil, validationErrs
	}
	if cachedAUCUser.HashedPassword == nil {
		validationErrs.Add("AUC", validator.ErrInvalidAUC)
		return nil, validationErrs
	}
	decodedPassword, err := util.Base64URLDecode(params.Password)
	if err != nil {
		logger.Log(requestID, " ::: ", err.Error())
		validationErrs.Add("AUC", validator.ErrInvalidAUC)
		return nil, validationErrs
	}
	isValidPassword, err := util.ValidateHash(cachedAUCUser.HashedPassword, decodedPassword)
	if err != nil {
		logger.Log(requestID, " ::: ", err.Error())
		validationErrs.Add(errorConfig.InternalServerError, err.Error())
		return nil, validationErrs
	}
	if !isValidPassword {
		validationErrs.Add("Password", validator.ErrInvalidPassword)
		return nil, validationErrs
	}
	return composeJWT(ctx, params.AUC, cachedAUCUser)

}
func composeJWT(ctx context.Context, auc string, cachedAUCUser *aucUser) (*ResponseJWT, *ErrAuth) {
	validationErrs := &ErrAuth{}
	authJWT, jtix, err := makeAuthJWT(auc)
	if err != nil {
		validationErrs.Add("SIGN", err.Error())
		return nil, validationErrs
	}
	refreshToken, jtiy, err := makeRefreshJWT(auc)
	if err != nil {
		validationErrs.Add("SIGN", err.Error())
		return nil, validationErrs
	}
	cachedAUCUser.JTIForAuthJWT = append(cachedAUCUser.JTIForAuthJWT, jtix)
	cachedAUCUser.JTIForRefreshJWT = append(cachedAUCUser.JTIForRefreshJWT, jtiy)

	cachedAUCUser.AUC = auc

	err = cachedAUCUser.updateCache(ctx, auc)
	if err != nil {
		validationErrs.Add("AUC", err.Error())
		return nil, validationErrs
	}
	return &ResponseJWT{
		JWTForAuth:    authJWT,
		JWTForRefresh: refreshToken,
	}, validationErrs
}
func makeAuthJWT(subject string) (string, string, error) {
	jti := util.GenerateUUID()
	claims := &ABLClaim{}
	claims.Purpose = TypeAuthToken
	claims.Id = jti
	claims.Aud = authJWTConfig.AllowedAud
	claims.ExpiresAt = getUnixTimeAfternDays(1, 15, 59, 59)
	claims.IssuedAt = time.Now().Unix()
	claims.Issuer = authJWTConfig.AllowedIDPs
	claims.AUC = subject
	claims.Subject = subject
	signedTokenString, err := claims.createSignedToken(authJWTConfig)
	if err != nil {
		return "", "", err
	}
	return signedTokenString, jti, nil
}
func makeRefreshJWT(subject string) (string, string, error) {
	jti := util.GenerateUUID()
	claims := &ABLClaim{}
	claims.Id = jti
	claims.Purpose = TypeRefreshToken
	claims.Aud = refreshJWTConfig.AllowedAud
	claims.ExpiresAt = getUnixTimeAfternDays(30, 15, 59, 59)
	claims.IssuedAt = time.Now().Unix()
	claims.Issuer = refreshJWTConfig.AllowedIDPs
	claims.AUC = subject
	claims.Subject = subject
	signedTokenString, err := claims.createSignedToken(refreshJWTConfig)
	if err != nil {
		return "", "", err
	}
	return signedTokenString, jti, nil
}

// ValidateJWT ValidateJWT
func ValidateJWT(ctx context.Context, params ParamsVerifyJWT) (*ResponseJWTVerification, *ErrAuth) {
	requestID := ctx.Value(communication.HttpHeaderRequestID).(string)
	rsp := &ResponseJWTVerification{}
	validationErrs := params.validate()
	if validationErrs != nil && len(*validationErrs) > 0 {
		validationErrs.Add("JWT", validator.ErrInvalidJWT)
		return rsp, validationErrs
	}
	myClaims := validateToken(ctx, params)
	if myClaims == nil {
		validationErrs.Add("JWT", validator.ErrInvalidJWT)
		return rsp, validationErrs
	}
	if myClaims.AUC != params.AUC {
		validationErrs.Add("JWT", validator.ErrInvalidJWT)
		return rsp, validationErrs
	}
	//
	cachedAUCUser, err := getAUCUserFromCache(ctx, myClaims.AUC)
	if err != nil {
		switch err.Error() {
		case errorConfig.UserNotFound:
			validationErrs.Add("JWT", validator.ErrInvalidJWT)
			return rsp, validationErrs
		default:
			logger.Log(requestID, " ::: ", "cachedAUCUser getAUCUserFromCache", err.Error())
			validationErrs.Add(errorConfig.InternalServerError, errorConfig.InternalServerError)
			return rsp, validationErrs
		}
	}
	// since params.Type is controlled by user and he can also see myClaims.Purpose in token
	// this check is just for novice attackers
	// otherwise
	// This check does not provide any security
	// anyone in possession of token can get thru this check
	if myClaims.Purpose != params.Type {
		validationErrs.Add("JWT", validator.ErrInvalidJWT)
		return rsp, validationErrs

	}
	switch params.Type {
	case TypeAuthToken:
		if cachedAUCUser.JTIForAuthJWT == nil { // may be JTI was deemed invalid by admin!
			validationErrs.Add("JWT", validator.ErrInvalidJWT)
			return rsp, validationErrs
		}
		if !util.SliceContainsString(cachedAUCUser.JTIForAuthJWT, myClaims.Id) {
			validationErrs.Add("JWT", validator.ErrInvalidJWT)
			return rsp, validationErrs
		}
	case TypeRefreshToken:
		if cachedAUCUser.JTIForRefreshJWT == nil { // may be JTI was deemed invalid by admin!
			validationErrs.Add("JWT", validator.ErrInvalidJWT)
			return rsp, validationErrs
		}
		if !util.SliceContainsString(cachedAUCUser.JTIForRefreshJWT, myClaims.Id) {
			validationErrs.Add("JWT", validator.ErrInvalidJWT)
			return rsp, validationErrs
		}
	}
	rsp.IsValid = true
	return rsp, validationErrs

}
func validateToken(ctx context.Context, params ParamsVerifyJWT) *ABLClaim {
	requestID := ctx.Value(communication.HttpHeaderRequestID).(string)
	/*
		Errors are caught:
		if token is expired
		if signature is invalid (example: if somebody changes algo name in header )

		err != nil || !token.Valid is enough
		but for security we do additional checks
	*/
	var jwtConfig *config.JWT
	var (
		token *jwt.Token
		err   error
	)
	if params.Type == TypeAuthToken {
		jwtConfig = authJWTConfig
	} else if params.Type == TypeRefreshToken {
		jwtConfig = refreshJWTConfig
	} else {
		return nil
	}
	switch true {
	case jwtConfig.RSA != nil:
		token, err = jwt.ParseWithClaims(params.JWT, &ABLClaim{}, jwtConfig.RSA.KeyFunc)
		if err != nil {
			return nil
		}
		if token.Header["alg"] != jwtConfig.RSA.Algo.Name {
			return nil
		}
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil
		}
	case jwtConfig.HMAC != nil:
		token, err = jwt.ParseWithClaims(params.JWT, &ABLClaim{}, jwtConfig.HMAC.KeyFunc)
		if err != nil {
			return nil
		}
		if token.Header["alg"] != jwtConfig.HMAC.Algo.Name {
			return nil
		}
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil
		}
	}
	if !token.Valid || (token.Header["typ"] != jwtConfig.TokenType) {
		return nil
	}
	myCLaims, ok := token.Claims.(*ABLClaim)
	if !ok || !token.Valid {
		return nil
	}
	isValidHost := false
	for _, h := range jwtConfig.AllowedAud {
		if h == params.Host {
			isValidHost = true
			break
		}
	}
	if !isValidHost {
		logger.Log(requestID, " ::: ", "Invalid host", params.Host)
		return nil
	}
	if myCLaims.Id == "" {
		logger.Log(requestID, " ::: ", "Invalid JTI")
		return nil
	}
	if myCLaims.Issuer != jwtConfig.AllowedIDPs {
		logger.Log(requestID, " ::: ", "Invalid ISS", myCLaims.Issuer)
		return nil
	}
	return myCLaims
}

// ParamsRefreshJWT ParamsRefreshJWT
type ParamsRefreshJWT struct {
	JWT  string
	AUC  string
	Host string
}

// Validate Validates
func (p ParamsRefreshJWT) validate() *ErrAuth {
	errs := &ErrAuth{}
	if p.AUC == "" {
		errs.Add("AUC", validator.ErrInvalidAUC)
	}
	if p.JWT == "" {
		errs.Add("JWT", validator.ErrInvalidJWT)
	}
	return errs
}

// RegenerateJWTUsingRefreshToken RegenerateJWTUsingRefreshToken
func RegenerateJWTUsingRefreshToken(ctx context.Context, params ParamsRefreshJWT) (*ResponseJWT, *ErrAuth) {
	requestID := ctx.Value(communication.HttpHeaderRequestID).(string)
	rsp := &ResponseJWT{}
	validationErrs := params.validate()
	if validationErrs != nil && len(*validationErrs) > 0 {
		return rsp, validationErrs
	}
	verificationRequest := ParamsVerifyJWT{
		AUC:  params.AUC,
		JWT:  params.JWT,
		Type: TypeRefreshToken,
		Host: params.Host,
	}
	verificationREsponse, verr := ValidateJWT(ctx, verificationRequest)
	if verr != nil && len(*verr) > 0 {
		return rsp, verr
	}
	if !verificationREsponse.IsValid {
		validationErrs.Add("JWT", validator.ErrInvalidJWT)
		return rsp, validationErrs
	}
	cachedAUCUser, err := getAUCUserFromCache(ctx, params.AUC)
	if err != nil {
		logger.Log(requestID, " ::: ", "Error in cachedAUCUser getAUCUserFromCache: ", err.Error())
		switch err.Error() {
		case errorConfig.UserNotFound:
			validationErrs.Add("JWT", validator.ErrInvalidJWT)
			return rsp, validationErrs
		default:
			validationErrs.Add(errorConfig.InternalServerError, errorConfig.InternalServerError)
			return rsp, validationErrs
		}
	}
	return composeJWT(ctx, params.AUC, cachedAUCUser)
}
