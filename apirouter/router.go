package apirouter

import (
	"github.com/gin-gonic/gin"
	"github.com/leyle/fabric-user-manager/jwt"
	"github.com/leyle/fabric-user-manager/model"
	"github.com/leyle/go-api-starter/ginhelper"
)

func HandlerWrapper(f func(ctx *model.JWTContext), ctx *model.JWTContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		nctx := ctx.New(c)
		f(nctx)
	}
}

func auth(ctx *model.JWTContext, c *gin.Context) {
	newCtx := ctx.New(c)
	resp := jwt.Auth(newCtx)
	if resp.Err != nil {
		ginhelper.Return401Json(c, resp.Err.Error())
	}

	c.Next()
}

func JWTRouter(ctx *model.JWTContext, g *gin.RouterGroup) {
	// need auth api
	authG := g.Group("/jwt", func(c *gin.Context) {
		auth(ctx, c)
	})
	{
		// create user
		authG.POST("/user/create", HandlerWrapper(CreateUserHandler, ctx))
	}

	// don't need auth api
	noG := g.Group("/jwt")
	{
		// login
		noG.POST("/user/login", HandlerWrapper(LoginHandler, ctx))

		// check token
		noG.POST("/token/check", HandlerWrapper(CheckTokenHandler, ctx))
	}
}
