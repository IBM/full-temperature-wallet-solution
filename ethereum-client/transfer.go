package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/ethclient"
	resty "github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
	"github.com/vrischmann/envconfig"
)

func main() {
	config, err := loadConfigFromEnv()
	if err != nil {
		log.WithError(err).Fatal("fail to load config.")
	}
	log.WithField("config", config).Info("load config success.")

	// Create a rest Client to call signing server
	restClient := resty.New()

	// get public key and address
	getPublicKeyResponseBody := &struct {
		EthereumPublicKey string
		Address           string
	}{}

	getPublicKeyendpoint := fmt.Sprintf("http://%s:%s:/v1/grep11/key/secp256k1/get_ethereum_key/%s", config.SigningServerAddress, config.SigningServerPort, config.KeyUUID)
	log.WithField("endpoint", getPublicKeyendpoint).Info("start call signing server to get public address")

	_, err = restClient.R().EnableTrace().SetResult(getPublicKeyResponseBody).Get(getPublicKeyendpoint)
	if err != nil {
		log.WithError(err).Fatal("fail to get public key from signing server")
	}
	log.WithField("from_address", getPublicKeyResponseBody.Address).WithField("public key", getPublicKeyResponseBody.Address).Info("success get public key")

	// connect to ethereum
	client, err := ethclient.Dial(config.EthClient)
	if err != nil {
		log.WithField("ethereum endpoint", config.EthClient).WithError(err).Fatal("fail to connect ethereum")
	}

	pubString := getPublicKeyResponseBody.EthereumPublicKey
	pubByte, err := hexutil.Decode(pubString)
	if err != nil {
		log.WithError(err).Fatal("fail to decode public key")
	}

	publickey, err := crypto.UnmarshalPubkey(pubByte)
	if err != nil {
		log.WithError(err).Fatal("fail to unmarshal public key")
	}

	fromAddress := crypto.PubkeyToAddress(*publickey)
	log.WithField("from address", fromAddress).Info("extract from address from public key")

	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.WithError(err).Fatal("failed to get nonce")
	}
	log.WithField("nonce", nonce).Info("success get nonce")

	value := big.NewInt(int64(config.Value * 1000000000000000000)) // in wei (0.001 eth)
	gasLimit := uint64(21000)                                      // in units
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.WithError(err).Fatal("fail to get gas price")
	}
	toAddress := common.HexToAddress(config.ToAddress)
	var data []byte
	log.WithField("nonce", nonce).WithField("to_address", toAddress).WithField("value", value).WithField("gas_price", gasPrice).WithField("gas_limit", gasLimit).Info("start a new transaction")
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, data)

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.WithError(err).Fatal("fail to get chain ID")
	}
	log.WithField("chain_id", chainID).Info("chain_id")

	signer := types.NewEIP155Signer(chainID)
	hs := signer.Hash(tx)

	// sign by signing server
	sigResponse := &struct {
		Uuid      string `json:"uuid"`
		Action    string `json:"action"`
		Signature string `json:"signature"`
	}{}

	signEndpoint := fmt.Sprintf("http://%s:%s:/v1/grep11/key/secp256k1/sign/%s", config.SigningServerAddress, config.SigningServerPort, config.KeyUUID)
	log.WithField("endpoint", getPublicKeyendpoint).Info("start call signing server to sign")
	_, err = restClient.R().EnableTrace().SetResult(sigResponse).SetBody(map[string]interface{}{"data": toString(hs.Bytes())}).Post(signEndpoint)
	if err != nil {
		log.WithError(err).Fatal("fail to call signing server to sign")
	}

	sig := toByte(sigResponse.Signature)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])

	sig2 := LocalChange(r, s)
	log.WithField("public_key_len", len(pubByte)).WithField("signature_len", len(sig2)).WithField("signature", toString(sig2)).Info("sign by HPCS")

	signatureNoRecoverID := sig2[:len(sig2)-1] // remove recovery id
	localVerifyResult := crypto.VerifySignature(pubByte, hs.Bytes(), signatureNoRecoverID)
	log.WithField("result", localVerifyResult).Info("local verify result")

	signedTx, err := tx.WithSignature(signer, sig2)
	if err != nil {
		log.WithError(err).Fatal("failed to sign ")
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.WithError(err).Fatal("fail to broadcast to ethereum")
	}
	fmt.Println("Pls check result with following link:")
	fmt.Printf("		https://rinkeby.etherscan.io/tx/%s \n", signedTx.Hash().Hex())
}

func toString(src []byte) string {
	return base64.RawStdEncoding.EncodeToString(src)
}

func toByte(src string) []byte {
	result, _ := base64.RawStdEncoding.DecodeString(src)
	return result
}

func LocalChange(R, S *big.Int) []byte {
	sig := make([]byte, 65)

	denTwo := big.NewInt(2)
	rightS := big.NewInt(0)
	curve := secp256k1.S256()

	/*
		URL: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
		All transaction signatures whose s-value is greater than secp256k1n/2 are now considered invalid.
		The ECDSA recover precompiled contract remains unchanged and will keep accepting high s-values; this is useful
		e.g. if a contract recovers old Bitcoin signatures.
	*/
	rightS = rightS.Div(curve.Params().N, denTwo)

	if rightS.Cmp(S) == -1 {
		S = S.Sub(curve.Params().N, S)
		log.Println("S: ", S.String())
		rbytes, sbytes := R.Bytes(), S.Bytes()
		copy(sig[32-len(rbytes):32], rbytes)
		copy(sig[64-len(sbytes):64], sbytes)
		//	log.Println("Result : ", verifyECRecover(hash.Bytes(), sig, expectedPubKey))
	} else {
		rbytes, sbytes := R.Bytes(), S.Bytes()
		copy(sig[32-len(rbytes):32], rbytes)
		copy(sig[64-len(sbytes):64], sbytes)
		//	log.Println("Else Result : ", verifyECRecover(hash.Bytes(), sig, expectedPubKey))
	}
	return sig
}

type Config struct {
	EthClient              string
	KeyUUID                string
	ToAddress              string
	SigningServerAddress   string
	SigningServerPort      string
	SIGNING_SERVER_ADDRESS string
	Value                  float32
}

func (c *Config) String() string {
	v, _ := json.Marshal(c)
	return string(v)
}

func loadConfigFromEnv() (*Config, error) {
	config := &Config{}
	if err := envconfig.Init(&config); err != nil {
		return nil, err
	}
	return config, nil
}
