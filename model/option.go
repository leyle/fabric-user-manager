package model

import "github.com/leyle/go-api-starter/couchdb"

type Option struct {
	// couchdb config
	CouchDBOpt *couchdb.CouchDBOption

	// default fabric ca admin account
	Registrar *FabricCARegistrar

	// fabric gateway connection option
	FabricGWOption *FabricGWOption

	// JWT config
	JWTOpt *JWTOption
}

type FabricCARegistrar struct {
	EnrollId string
	Secret   string
}

type FabricGWOption struct {
	// connection config file path
	CCPath string

	// file type fabric wallet path
	WalletPath string

	OrgName string
}

type JWTOption struct {
	Secret      []byte
	ExpireHours int // unit is hour
}
