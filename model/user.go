package model

import (
	"github.com/leyle/go-api-starter/util"
)

// user role is the same as fabric ou type

type UserRole string

const (
	UserRoleAdmin   UserRole = "admin"
	UserRoleUser    UserRole = "client"
	UserRolePeer    UserRole = "peer"
	UserRoleOrderer UserRole = "orderer"
)

func (ur UserRole) String() string {
	switch ur {
	case UserRoleAdmin:
		return "admin"
	case UserRoleUser:
		return "client"
	case UserRolePeer:
		return "peer"
	case UserRoleOrderer:
		return "orderere"
	}
	return "client"
}

const DBNameUserAccount = "useraccount"

type UserAccount struct {
	Id       string        `json:"id"`
	Rev      string        `json:"_rev,omitempty"`
	Username string        `json:"username"`
	Salt     string        `json:"salt,omitempty"`
	PassHash string        `json:"passHash,omitempty"`
	Role     UserRole      `json:"role"`
	Valid    bool          `json:"valid"`
	Created  *util.CurTime `json:"created"`
	Updated  *util.CurTime `json:"updated"`
}

// fabric ca user
const DBNameCaUser = "causer"

type CaUser struct {
	// enrollId equals User.Id
	EnrollId string        `json:"enrollId"`
	Rev      string        `json:"_rev,omitempty"`
	Secret   string        `json:"secret"`
	Created  *util.CurTime `json:"created"`
}

func (u *UserAccount) IsPasswdEqual(passwd string) bool {
	// input passwd is normal text
	tmp := u.CreatePassHash(passwd, u.Salt)
	if tmp == u.PassHash {
		return true
	}
	return false
}

func (u *UserAccount) CreatePassHash(passwd, salt string) string {
	return util.GenerateHashPasswd(passwd, salt)
}
