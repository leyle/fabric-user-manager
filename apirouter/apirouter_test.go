package apirouter

import (
	"github.com/leyle/fabric-user-manager/model"
	"github.com/leyle/go-api-starter/couchdb"
	"github.com/leyle/go-api-starter/ginhelper"
	"github.com/rs/zerolog"
	"os"
	"testing"
)

func setupCtx() *model.JWTContext {
	dbOpt := &couchdb.CouchDBOption{
		HostPort: "localhost:5984",
		User:     "admin",
		Passwd:   "passwd",
		Protocol: "http",
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
		CouchDBOpt:     dbOpt,
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

	err := Init(ctx)
	if err != nil {
		t.Fatal(err)
	}

	apiRouter := e.Group("/api")
	JWTRouter(ctx, apiRouter.Group(""))

	e.Run(":9000")
}
