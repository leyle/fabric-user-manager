package model

type Option struct {
	// couchdb config
	Couchdb *CouchdbOption

	// default fabric ca admin account
	Registrar *FabricCARegistrar

	// fabric gateway connection option
	FabricGWOption *FabricGWOption

	// JWT config
	JWTOpt *JWTOption
}

type CouchdbOption struct {
	// HostPort is host:port format e.g 127.0.0.1:5984
	HostPort      string
	User          string
	Passwd        string
	DefaultDBName string
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
