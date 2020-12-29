package model

import (
	"github.com/gin-gonic/gin"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
	"github.com/leyle/go-api-starter/couchdb"
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
	logger := zerolog.Ctx(jwtc.C.Request.Context())
	return logger
}

func (jwtc *JWTContext) Ds(dbName string) *couchdb.CouchDB {
	ds := couchdb.NewCouchDB(jwtc.Opt.Couchdb.HostPort, jwtc.Opt.Couchdb.User, jwtc.Opt.Couchdb.Passwd, dbName)
	_ = ds.SetDBName(jwtc.C, dbName)
	return ds
}
