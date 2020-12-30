package jwtwrapper

import (
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/leyle/fabric-user-manager/model"
	"github.com/leyle/go-api-starter/couchdb"
	"github.com/leyle/go-api-starter/util"
	"time"
)

// based on gin framework

const (
	ctxClaimKey = "claimkey"
)

var (
	ErrWrongPasswd        = errors.New("wrong passwd")
	ErrNoTokenInHeaders   = errors.New("no token in headers")
	ErrInvalidToken       = errors.New("invalid token value")
	ErrContextNoClaim     = errors.New("get user's claim from request context failed")
	ErrUserNoPermission   = errors.New("current user doesn't have permission")
	ErrUserIdExist        = errors.New("username/enrollId has already exists")
	ErrUserIsInvalid      = errors.New("user is invalid")
	ErrNoWalletCredential = errors.New("user doesn't register/enroll ca")
)

// login
// input values are username and password
// return value is jwtwrapper token response
func JWTLogin(ctx *model.JWTContext, username, passwd string) *model.JWTResponse {
	var err error
	resp := model.InitJWTResponse()
	/*
		err := ctx.Ds(model.DBNameUserAccount).SetDBName(ctx.C.Request.Context(), model.DBNameUserAccount)
		if err != nil {
			ctx.Logger().Error().Err(err).Msg("JWTLogin, set db name failed")
			resp.Err = err
			return resp
		}
	*/

	// query by username and passwd
	// username is db's id
	var user *model.UserAccount
	_, err = ctx.Ds(model.DBNameUserAccount).GetById(ctx.C.Request.Context(), username, &user)
	if err == couchdb.NoIdData {
		ctx.Logger().Warn().Str("username", username).Msg("JWTLogin, no data refer to username")
		resp.Err = err
		return resp
	}
	if err != nil {
		resp.Err = err
		return resp
	}

	// check if password is ok
	if !user.IsPasswdEqual(passwd) {
		// if password is wrong
		ctx.Logger().Warn().Str("username", username).Msg("JWTLogin, wrong password")
		resp.Err = ErrWrongPasswd
		return resp
	}

	// check if user status is ok
	if !user.Valid {
		ctx.Logger().Warn().Str("username", username).Msg("JWTLogin failed, user is invalid")
		resp.Err = ErrUserIsInvalid
		return resp
	}

	// password is right, generate jwtwrapper token
	token, err := createJWTToken(ctx, user)
	if err != nil {
		resp.Err = err
		return resp
	}

	resp.Token = token
	resp.UserAccount = user
	return resp
}

// register
// input values are username and password
// return value is result flag
func JWTRegister(ctx *model.JWTContext, username, passwd string, role model.UserRole) *model.JWTResponse {
	resp := model.InitJWTResponse()
	claim := GetCurUser(ctx.C)
	if claim == nil {
		resp.Err = ErrContextNoClaim
		ctx.Logger().Error().Err(ErrContextNoClaim).Msg("get user from request context failed")
		return resp
	}

	// check if user role is admin
	if claim.Role != model.UserRoleAdmin {
		resp.Err = ErrUserNoPermission
		ctx.Logger().Error().Err(ErrUserNoPermission).Str("role", claim.Role.String()).Msg("current user is not admin")
		return resp
	}

	// check if username is already exist
	var dbUser model.UserAccount
	_, err := ctx.Ds(model.DBNameUserAccount).GetById(ctx.C.Request.Context(), username, &dbUser)
	if err == couchdb.NoIdData {
		// ok, create it
		resp = registerUser(ctx, username, passwd, role)
		if resp.Err != nil {
			ctx.Logger().Error().Err(resp.Err).Str("username", username).Msg("register user failed")
			return resp
		}
		// create account success, return immediately
		return resp
	}

	// other error
	if err != nil {
		ctx.Logger().Error().Err(err).Str("username", username).Msg("get username from db failed")
		resp.Err = err
		return resp
	}

	// if user has exist
	if dbUser.Id != "" {
		resp.Err = ErrUserIdExist
		ctx.Logger().Error().Err(ErrUserIdExist).Str("username", username).Msg("create user failed, username has exists")
		return resp
	}

	return resp
}

func createJWTToken(ctx *model.JWTContext, user *model.UserAccount) (string, error) {
	expireTime := time.Now().Add(time.Duration(ctx.Opt.JWTOpt.ExpireHours) * time.Hour)
	claim := &model.JWTClaim{
		UserId:   user.Id,
		UserName: user.Username,
		Role:     user.Role,
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  util.CurUnixTime(),
			ExpiresAt: expireTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	tokenStr, err := token.SignedString(ctx.Opt.JWTOpt.Secret)
	if err != nil {
		ctx.Logger().Error().Err(err).Msg("create jwtwrapper token failed")
		return "", err
	}

	return tokenStr, nil
}

func ParseJWTToken(ctx *model.JWTContext, token string) *model.JWTResponse {
	// get token from request headers
	resp := model.InitJWTResponse()
	if token == "" {
		token = ctx.C.Request.Header.Get(model.JWTHeaderName)
	}
	if token == "" {
		ctx.Logger().Error().Msg("ParseJWTToken, no token in request headers")
		resp.Err = ErrNoTokenInHeaders
		return resp
	}

	claim := &model.JWTClaim{}

	tkn, err := jwt.ParseWithClaims(token, claim, func(token *jwt.Token) (interface{}, error) {
		return ctx.Opt.JWTOpt.Secret, nil
	})
	if err != nil {
		ctx.Logger().Error().Err(err).Msg("ParseJWTToken, parse token failed")
		resp.Err = err
		return resp
	}

	if !tkn.Valid {
		ctx.Logger().Error().Msg("ParseJWTToken, token is invalid")
		resp.Err = ErrInvalidToken
		return resp
	}

	resp.Claim = claim
	resp.Valid = true
	resp.Token = token
	ctx.Logger().Debug().Msg("parse token success")
	return resp
}

func Auth(ctx *model.JWTContext) *model.JWTResponse {
	// parse token
	authRet := model.InitJWTResponse()
	resp := ParseJWTToken(ctx, "")
	if resp.Err != nil {
		authRet.Err = resp.Err
		ctx.Logger().Error().Err(resp.Err).Msg("Auth, check token failed")
		return authRet
	}

	// check wallet credential exist
	enrollId := resp.Claim.UserId
	if !IsCAUserExist(ctx, enrollId) {
		authRet.Err = ErrNoWalletCredential
		ctx.Logger().Error().Err(authRet.Err).Msg("user don't have wallet credential")
		return authRet
	}

	// save context
	SetCurUser(ctx.C, resp.Claim)

	authRet.Claim = resp.Claim
	return authRet
}

func SetCurUser(c *gin.Context, claim *model.JWTClaim) {
	c.Set(ctxClaimKey, claim)
}

func GetCurUser(c *gin.Context) *model.JWTClaim {
	claim, exist := c.Get(ctxClaimKey)
	if !exist {
		return nil
	}
	result := claim.(*model.JWTClaim)
	return result
}

func registerUser(ctx *model.JWTContext, username, passwd string, role model.UserRole) *model.JWTResponse {
	// two steps
	// 1. register to ca
	// 2. save data into normal db

	salt := util.GetCurNoSpaceTime()
	ua := &model.UserAccount{
		Id:       createUserDataId(username),
		Username: username,
		Salt:     salt,
		Role:     role,
		Valid:    true,
		Created:  util.GetCurTime(),
	}
	ua.PassHash = ua.CreatePassHash(passwd, salt)
	ua.Updated = ua.Created

	// 1. register to ca
	resp := CARegister(ctx, ua.Id, ua.PassHash, role)
	if resp.Err != nil {
		return resp
	}

	// 2. save data into normal db
	resp2 := SaveJWTUser(ctx, ua)
	if resp2.Err != nil {
		return resp2
	}

	resp2.MspClient = resp.MspClient
	return resp2
}

func SaveJWTUser(ctx *model.JWTContext, ua *model.UserAccount) *model.JWTResponse {
	resp := model.InitJWTResponse()

	uaData, _ := json.Marshal(ua)
	err := ctx.Ds(model.DBNameUserAccount).Create(ctx.C.Request.Context(), ua.Id, uaData)
	if err != nil {
		ctx.Logger().Error().Err(err).Str("username", ua.Username).Msg("create user failed")
		resp.Err = err
		return resp
	}

	resp.UserAccount = ua
	return resp
}

func createUserDataId(username string) string {
	// if needed, we can generate a uuid4
	// now we just return the input string
	return username
}
