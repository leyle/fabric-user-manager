package model

import (
	"github.com/gin-gonic/gin"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
	"github.com/leyle/go-api-starter/couchdb"
	"github.com/leyle/go-api-starter/logmiddleware"
	"github.com/rs/zerolog"
)

type JWTContext struct {
	C   *gin.Context
	Opt *Option

	// temp value
	Wallet *gateway.Wallet
}

func (jwtc *JWTContext) New(c *gin.Context) *JWTContext {
	n := &JWTContext{
		C:      c,
		Opt:    jwtc.Opt,
		Wallet: jwtc.Wallet,
	}
	return n
}

func (jwtc *JWTContext) Logger() *zerolog.Logger {
	if jwtc.C == nil {
		l := logmiddleware.GetLogger(logmiddleware.LogTargetConsole)
		return &l
	}
	logger := zerolog.Ctx(jwtc.C.Request.Context())
	return logger
}

func (jwtc *JWTContext) Ds(dbName string) *couchdb.CouchDBClient {
	return couchdb.New(jwtc.Opt.CouchDBOpt, dbName)
}
