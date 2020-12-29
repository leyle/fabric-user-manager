package apirouter

import (
	"github.com/leyle/fabric-user-manager/model"
	"github.com/leyle/go-api-starter/ginhelper"
	"github.com/rs/zerolog"
	"os"
	"testing"
)

func setupCtx() *model.JWTContext {
	dbOpt := &model.CouchdbOption{
		HostPort:      "192.168.2.40:5984",
		User:          "admin",
		Passwd:        "passwd",
		DefaultDBName: "fabric",
	}

	registerOpt := &model.FabricCARegistrar{
		EnrollId: "orgadmin",
		Secret:   "passwd",
	}

	gwOpt := &model.FabricGWOption{
		CCPath:     "/tmp/fabric/connection.yaml",
		WalletPath: "/tmp/fabric/wallet",
		OrgName:    "org1",
	}

	jwtOpt := &model.JWTOption{
		Secret:      []byte("hello"),
		ExpireHours: 30 * 24,
	}

	opt := &model.Option{
		Couchdb:        dbOpt,
		Registrar:      registerOpt,
		FabricGWOption: gwOpt,
		JWTOpt:         jwtOpt,
	}

	ctx := &model.JWTContext{
		Opt: opt,
	}

	return ctx
}

func TestJWTRouter(t *testing.T) {
	// setup gin
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	e := ginhelper.SetupGin(&logger)

	ctx := setupCtx()

	apiRouter := e.Group("/api")
	JWTRouter(ctx, apiRouter.Group(""))

	e.Run(":8000")
}
