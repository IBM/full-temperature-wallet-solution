package main

import (
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func main() {
	log.Info("start signing server...")
	router := gin.Default()

	//get getMechanismInfo
	router.GET("/v1/grep11/get_mechanismsc", getMechanismInfo)

	// generage key pair
	router.POST("/v1/grep11/key/secp256k1/generate_key_pair", generageECkeyPair)

	// get public key
	router.GET("/v1/grep11/key/secp256k1/:keyType/:id", findKeyByUUID)

	// get ethereum key
	router.GET("/v1/grep11/key/secp256k1/get_ethereum_key/:id", getEthereumKey)

	// 使用secp256k1类型的私钥在HPCS 上签名，签名后使用ethereum类型的公钥验证签名，
	// 验证签名方法直接调用以太坊的库执行  crypto.VerifySignature
	router.POST("/v1/grep11/key/secp256k1/verify_ethereum_pub_key/:id", verifyEthereumKey)

	// sign
	router.POST("/v1/grep11/key/secp256k1/sign/:id", sign)

	// verify signature
	router.POST("/v1/grep11/key/secp256k1/verify/:id", verifySignature)

	// import aes key
	router.POST("/v1/grep11/key/aes/import", importAESKey)

	// verify imported aes key
	router.POST("/v1/grep11/key/aes/verify/:id", verifyImportAESKey)

	// import ec key
	router.POST("/v1/grep11/key/import_ec", importECKey)

	router.Run()
}
