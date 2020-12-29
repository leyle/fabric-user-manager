package apirouter

import (
	"github.com/gin-gonic/gin"
	"github.com/leyle/fabric-user-manager/jwt"
	"github.com/leyle/fabric-user-manager/model"
	"github.com/leyle/go-api-starter/couchdb"
	"github.com/leyle/go-api-starter/ginhelper"
	"github.com/leyle/go-api-starter/util"
	"strings"
)

type LoginForm struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func LoginHandler(ctx *model.JWTContext) {
	var form LoginForm
	err := ctx.C.BindJSON(&form)
	ginhelper.StopExec(err)

	form.Username = strings.TrimSpace(form.Username)
	form.Password = strings.TrimSpace(form.Password)

	// we need to init system admin's user account
	// if username and password equal ca's enrollId and secret
	// we insert into db

	caUser := ctx.Opt.Registrar.EnrollId
	caPasswd := ctx.Opt.Registrar.Secret

	if caUser == form.Username && caPasswd == form.Password {
		// check if user exist
		resp := insureSystemAdmin(ctx, form.Username, form.Password)
		if resp.Err != nil {
			ctx.Logger().Error().Err(err).Msg("init system admin failed")
			ginhelper.ReturnErrJson(ctx.C, resp.Err.Error())
			return
		}
	}

	resp := jwt.JWTLogin(ctx, form.Username, form.Password)
	if resp.Err != nil {
		ginhelper.ReturnErrJson(ctx.C, resp.Err.Error())
		return
	}

	resp.UserAccount.PassHash = ""
	resp.UserAccount.Salt = ""
	retData := gin.H{
		"token": resp.Token,
		"user":  resp.UserAccount,
	}
	ginhelper.ReturnOKJson(ctx.C, retData)
	return
}

type CreateUserForm struct {
	Username string         `json:"username" binding:"required"`
	Password string         `json:"password" binding:"required"`
	Role     model.UserRole `json:"role" binding:"required"`
}

func CreateUserHandler(ctx *model.JWTContext) {
	var form CreateUserForm
	err := ctx.C.BindJSON(&form)
	ginhelper.StopExec(err)

	form.Username = strings.TrimSpace(form.Username)
	form.Password = strings.TrimSpace(form.Password)

	resp := jwt.JWTRegister(ctx, form.Username, form.Password, form.Role)

	if resp.Err != nil {
		if resp.Err == jwt.ErrContextNoClaim {
			ginhelper.Return401Json(ctx.C, resp.Err.Error())
			return
		}
		if resp.Err == jwt.ErrUserNoPermission {
			ginhelper.Return403Json(ctx.C, resp.Err.Error())
			return
		}

		ginhelper.ReturnErrJson(ctx.C, resp.Err.Error())
		return
	}

	ua := resp.UserAccount
	passHash := ua.PassHash
	ua.PassHash = ""

	// enroll
	resp2 := jwt.CAEnroll(ctx, ua.Id, passHash)
	if resp2.Err != nil {
		ctx.Logger().Error().Err(resp2.Err).Str("username", form.Username).Msg("create user failed, enroll failed")
		ginhelper.ReturnErrJson(ctx.C, resp2.Err.Error())
		return
	}

	ginhelper.ReturnOKJson(ctx.C, ua)
	return
}

type CheckTokenForm struct {
	Token string `json:"token" binding:"required"`
}

func CheckTokenHandler(ctx *model.JWTContext) {
	var form CheckTokenForm
	err := ctx.C.BindJSON(&form)
	ginhelper.StopExec(err)

	resp := jwt.ParseJWTToken(ctx, form.Token)

	ginhelper.ReturnOKJson(ctx.C, resp)
}

func insureSystemAdmin(ctx *model.JWTContext, username, passwd string) *model.JWTResponse {
	resp := model.InitJWTResponse()

	var ua *model.UserAccount
	_, err := ctx.Ds(model.DBNameUserAccount).GetById(ctx.C.Request.Context(), username, &ua)
	if err != nil {
		if err == couchdb.NoIdData {
			// do insert
			resp = insertSystemAdmin(ctx, username, passwd)
			return resp
		} else {
			// other error, we need to process it
			resp.Err = err
			return resp
		}
	}
	resp.UserAccount = ua

	// enroll it
	resp2 := jwt.CAEnroll(ctx, username, passwd)
	if resp2.Err != nil {
		resp.Err = resp2.Err
		ctx.Logger().Error().Err(resp.Err).Msg("enroll system admin failed")
	}
	return resp
}

func insertSystemAdmin(ctx *model.JWTContext, username, passwd string) *model.JWTResponse {
	salt := util.GetCurNoSpaceTime()
	ua := &model.UserAccount{
		Id:       username,
		Username: username,
		Salt:     salt,
		Role:     model.UserRoleAdmin,
		Valid:    true,
		Created:  util.GetCurTime(),
	}
	ua.PassHash = ua.CreatePassHash(passwd, salt)
	ua.Updated = ua.Created
	resp := jwt.SaveJWTUser(ctx, ua)
	return resp
}
