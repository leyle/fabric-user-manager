package apirouter

import (
	"context"
	"github.com/leyle/fabric-user-manager/model"
	"github.com/leyle/go-api-starter/logmiddleware"
)

// init couchdb database and index
func Init(ctx *model.JWTContext) error {
	// create database for user account
	tmpCtx := context.Background()
	logger := logmiddleware.GetLogger(logmiddleware.LogTargetStdout)
	tmpCtx = logger.WithContext(tmpCtx)
	logger.Debug().Msg("start to Init database")
	err := ctx.Ds(model.DBNameUserAccount).CreateDatabase(tmpCtx)
	if err != nil {
		return err
	}

	// create index
	fields := []string{
		"username",
		"role",
		"valid",
		"created.second",
		"updated.second",
	}

	err = ctx.Ds(model.DBNameUserAccount).CreateIndex(tmpCtx, fields)
	if err != nil {
		return err
	}

	logger.Debug().Msg("Init database success")
	return nil
}
