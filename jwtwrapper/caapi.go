package jwtwrapper

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
	"github.com/leyle/fabric-user-manager/model"
)

func NewWallet(ctx *model.JWTContext) (*gateway.Wallet, error) {
	if ctx.Wallet != nil {
		return ctx.Wallet, nil
	}
	walletPath := ctx.Opt.FabricGWOption.WalletPath
	wallet, err := gateway.NewFileSystemWallet(walletPath)
	if err != nil {
		ctx.Logger().Error().Err(err).Str("wallet", walletPath).Msg("create file wallet failed")
		return nil, err
	}
	ctx.Wallet = wallet
	return wallet, nil
}

func NewGateway(ctx *model.JWTContext, enrollId string) (*gateway.Gateway, error) {
	// 1. get user identity option
	wallet, err := NewWallet(ctx)
	if err != nil {
		ctx.Logger().Error().Err(err).Msg("create new gateway failed")
		return nil, err
	}
	identityOpt := gateway.WithIdentity(wallet, enrollId)

	// 2. get gateway config
	ccPath := ctx.Opt.FabricGWOption.CCPath
	gwCfg := gateway.WithConfig(config.FromFile(ccPath))

	// 3. connect to fabric
	gw, err := gateway.Connect(gwCfg, identityOpt)
	if err != nil {
		ctx.Logger().Error().Err(err).Str("enrollId", enrollId).Msg("connect to fabric failed")
		return nil, err
	}
	ctx.Logger().Debug().Str("enrollId", enrollId).Msg("create new gateway success")
	return gw, nil
}

func CARegister(ctx *model.JWTContext, enrollId, secret string, role model.UserRole) *model.JWTResponse {
	resp := getMSPClient(ctx)
	if resp.Err != nil {
		ctx.Logger().Error().Err(resp.Err).Str("enrollId", enrollId).Msg("create ca user, get msp client failed")
		return resp
	}

	// check if enrollId has exists
	if IsCAUserExist(ctx, enrollId) {
		resp.Err = ErrUserIdExist
		ctx.Logger().Error().Err(ErrUserIdExist).Str("enrollId", enrollId).Msg("create ca user, enrollId has exists")
		return resp
	}

	regForm := &msp.RegistrationRequest{
		Name:           enrollId,
		Type:           role.String(),
		MaxEnrollments: -1,
		Secret:         secret,
	}

	mspClient := resp.MspClient
	_, err := mspClient.Register(regForm)
	if err != nil {
		ctx.Logger().Error().Err(err).Str("enrollId", enrollId).Msg("register ca user failed")
		resp.Err = err
		return resp
	}

	ctx.Logger().Debug().Str("enrollId", enrollId).Msg("register ca user success")

	return resp
}

func CAEnroll(ctx *model.JWTContext, enrollId, secret string) *model.JWTResponse {
	resp := getMSPClient(ctx)
	if resp.Err != nil {
		ctx.Logger().Error().Err(resp.Err).Str("enrollId", enrollId).Msg("enroll ca user, get msp client failed")
		return resp
	}

	mspClient := resp.MspClient
	err := mspClient.Enroll(enrollId, msp.WithSecret(secret))
	if err != nil {
		ctx.Logger().Error().Err(err).Str("enrollId", enrollId).Msg("enroll ca user failed")
		resp.Err = err
		return resp
	}

	si, err := mspClient.GetSigningIdentity(enrollId)
	if err != nil {
		resp.Err = err
		ctx.Logger().Error().Err(err).Str("enrollId", enrollId).Msg("enroll ca user, get signing identity failed")
		return resp
	}

	publicKey := si.EnrollmentCertificate()
	privateKey, err := si.PrivateKey().Bytes()
	if err != nil {
		resp.Err = err
		ctx.Logger().Error().Err(err).Str("enrollId", enrollId).Msg("enroll ca user, get private key failed")
		return resp
	}

	newIdentity := gateway.NewX509Identity(si.PublicVersion().Identifier().MSPID, string(publicKey), string(privateKey))
	var wallet *gateway.Wallet
	if ctx.Wallet != nil {
		wallet = ctx.Wallet
	} else {
		wallet, err = NewWallet(ctx)
		if err != nil {
			resp.Err = err
			return resp
		}
	}

	err = wallet.Put(enrollId, newIdentity)
	if err != nil {
		resp.Err = err
		ctx.Logger().Error().Err(err).Str("enrollId", enrollId).Msg("enroll ca user, put it into wallet failed")
		return resp
	}

	ctx.Logger().Debug().Str("enrollId", enrollId).Msg("enroll ca user success")

	return resp
}

func IsCAUserExist(ctx *model.JWTContext, enrollId string) bool {
	if ctx.Wallet != nil {
		return ctx.Wallet.Exists(enrollId)
	} else {
		wallet, err := NewWallet(ctx)
		if err != nil {
			return false
		}
		ctx.Wallet = wallet
		return wallet.Exists(enrollId)
	}
}

func getMSPClient(ctx *model.JWTContext) *model.JWTResponse {
	resp := model.InitJWTResponse()

	wallet, err := NewWallet(ctx)
	if err != nil {
		resp.Err = err
		ctx.Logger().Error().Err(err).Msg("get file wallet failed")
		return resp
	}
	ctx.Wallet = wallet

	ccPath := ctx.Opt.FabricGWOption.CCPath
	sdk, err := fabsdk.New(config.FromFile(ccPath))
	if err != nil {
		ctx.Logger().Error().Err(err).Msg("create new fabric sdk failed")
		resp.Err = err
		return resp
	}
	defer sdk.Close()

	curOrg := ctx.Opt.FabricGWOption.OrgName
	client, err := msp.New(sdk.Context(), msp.WithOrg(curOrg))
	if err != nil {
		ctx.Logger().Error().Err(err).Msg("create new msp client failed")
		resp.Err = err
		return resp
	}
	resp.MspClient = client

	return resp
}
