package model

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
)

const JWTHeaderName = "X-TOKEN"

type JWTClaim struct {
	UserId   string   `json:"userId"`
	UserName string   `json:"username"`
	Role     UserRole `json:"role"`
	jwt.StandardClaims
}

type JWTResponse struct {
	Err   error  `json:"-"`
	Token string `json:"token"`

	// when parse token, this may has value
	Valid bool      `json:"valid"`
	Claim *JWTClaim `json:"claim"`

	// when create user account
	UserAccount *UserAccount `json:"-"`

	// when create ca account
	MspClient *msp.Client `json:"-"`
}

func InitJWTResponse() *JWTResponse {
	return &JWTResponse{}
}
