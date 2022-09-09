
export SIGN_HOST=localhost
export SIGNING_PORT=8080

# 测试连通性
curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/get_mechanismsc

# 产生椭圆曲线Key pair
curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/key/secp256k1/generate_key_pair -X POST -s | jq

# 获取公钥
curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/key/secp256k1/public/${KEY_UUID} -s | jq

# 获取ethereum 格式的公钥
curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/key/secp256k1/get_ethereum_key/${KEY_UUID}  -s | jq

# 使用secp256k1类型的私钥在HPCS 上签名，签名后使用ethereum类型的公钥验证签名，
# 验证签名方法直接调用以太坊的库执行  crypto.VerifySignature
# 以太坊的签名摘要必须是32位
curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/key/secp256k1/verify_ethereum_pub_key/${KEY_UUID} -X POST  -s -d '{"data":"fad9c8855b740a0b7ed4c221dbad0f33","ethereum_pub_key":"0x0474618a3e3a8a7207c008d9a993b611b2f38f281c53cb8e1e67e5f2c9f0fd8fe572037924791385a203afe1c45149f3918b6df86918a020a822df3d1fc8508b3a"}' | jq

·# 获取被包裹的私钥
curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/key/secp256k1/private/${KEY_UUID} -s | jq

# 使用私钥签名数据
curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/key/secp256k1/sign/${KEY_UUID}  -s -X POST -d '{"data":"the text need to encrypted to verify kay."}' | jq

# 使用公钥验证签名
curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/key/secp256k1/verify/${KEY_UUID}  -s -X POST -d '{"data":"the text need to encrypted to verify kay.","signature":"Tw/Dk0NUNbklut31DQctitAFeFwkCtdRP7hAcMU84dYRkdXFlCB9mEFzaGpZ+dK/786k7iVQ8a8WRCNF0U7r/Q"}' |jq

# 使用master key包裹导入的AES，并持久化到HPDBaaS
curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/key/aes/import -X POST -s -d '{"key_content":"E5E9FA1BA31ECD1AE84F75CAAA474F3A"}' |jq

#使用导入到AESkey 加密数据与明文AES加密数据结果对比，如果一样就证明导入到key是正确的，并且被master key 包裹了
curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/key/aes/verify/${KEY_UUID}  -X POST -d '{"key_content":"E5E9FA1BA31ECD1AE84F75CAAA474F3A","data":"E5E9FA1BA31ECD1AE84F75CAAA474F3A"}'

# 产生EC 私钥 PEM 格式
openssl ecparam -genkey -name secp256k1 -noout -out secp256k1-key-pair.pem -param_enc explicit

# 提取公钥
openssl ec -in secp256k1-key-pair.pem -pubout > secp256k1-key-pub.pem

# 上传私钥并持久化
curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/key/import_ec -X POST -s  -F "file=@./secp256k1-key-pair.pem" | jq

# 签名ec
curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/key/sign/${KEY_UUID} -s -X POST -d '{"data":"the text need to encrypted to verify kay."}' | jq

# 使用公钥验证签名
curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/key/verify/${KEY_UUID} -s -X POST -d '{"data":"the text need to encrypted to verify kay.","signature":"vW3UVySThT4qQRmocPQiIus8gz1e5+Ch0XHs2YY7LlNN6HWfgWLtYcIjkZdsp0PTYYY73ffF1PnLQ1tTqmyaaQ"}'

#  签名ec 返回ANS1
curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/key/sign/${KEY_UUID}  -s -X POST -d '{"data":"the text need to encrypted to verify kay.","sig_format":"ans1"}' | jq

# 使用本地公钥验证签名
echo -n "the text need to encrypted to verify kay." > test.data
echo -n "MEUCIAgZXWc826mQ9ogdt6lVYiYYHp16rDyutc4Hb8OQdH3CAiEA3OOoTPtz9QW13+RlDTO8DCSOPv4M2Q1HKlf/xXJS6+c" |gbase64 --decode -w 0  > signature.sig
openssl pkeyutl -verify -in test.data -sigfile  signature.sig  -pubin  -inkey ec256-key-pub.pem