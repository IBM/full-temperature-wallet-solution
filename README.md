
- [1. Signature Server](#1-signature-server)
  - [1.1. 环境介绍](#11-环境介绍)
  - [1.2. The client communicates with the signature server through the following endpoints](#12-the-client-communicates-with-the-signature-server-through-the-following-endpoints)
  - [1.3. Sequence diagram and description of GREP11 API usage example](#13-sequence-diagram-and-description-of-grep11-api-usage-example)
    - [1.3.1. Step-by-step instructions](#131-step-by-step-instructions)
  - [1.4. Import key process](#14-import-key-process)
    - [1.4.1. GREP11 AP1 import private key sequence diagram and description](#141-grep11-ap1-import-private-key-sequence-diagram-and-description)
    - [1.4.2. Step-by-step instructions](#142-step-by-step-instructions)
- [2. Deploy the signature server](#2-deploy-the-signature-server)
  - [2.1. Introduction to HPVS](#21-introduction-to-hpvs)
    - [2.1.1. Main Features of HPVS](#211-main-features-of-hpvs)
  - [2.2. Main step description and role separation design](#22-main-step-description-and-role-separation-design)
    - [2.2.1. Overview of the main steps](#221-overview-of-the-main-steps)
  - [2.3. Role Definition](#23-role-definition)
  - [2.4. Preparations](#24-preparations)
    - [2.4.1. Installing IBM CLI](#241-installing-ibm-cli)
    - [2.4.2. Install IBM Container Registry](#242-install-ibm-container-registry)
    - [2.4.3. Install Docker](#243-install-docker)
  - [2.5. Building the image](#25-building-the-image)
    - [2.5.1. Clone the repository](#251-clone-the-repository)
    - [2.5.2. Building an Image](#252-building-an-image)
    - [2.5.3. Tag image](#253-tag-image)
  - [2.6. After the version manager inspects the code, execute the signing operation.](#26-after-the-version-manager-inspects-the-code-execute-the-signing-operation)
    - [2.6.1. Create a trust key](#261-create-a-trust-key)
    - [2.6.2. Enable DCT(Docker Content Trust)](#262-enable-dctdocker-content-trust)
    - [2.6.3. Upload image and sign](#263-upload-image-and-sign)
    - [2.6.4. Obtaining the signed public key](#264-obtaining-the-signed-public-key)
  - [2.7. `role 1` Build the WORKLOAD template](#27-role-1-build-the-workload-template)
    - [2.7.1. Convert the compose template file to base64](#271-convert-the-compose-template-file-to-base64)
    - [2.7.2. Building a Workload Template](#272-building-a-workload-template)
    - [2.7.3. Download ibm public key](#273-download-ibm-public-key)
    - [2.7.4. Encrypting workloads](#274-encrypting-workloads)
  - [2.8. `role2`Build an ENV template](#28-role2build-an-env-template)
    - [2.8.1. 创建env 模版](#281-创建env-模版)
    - [2.8.2. Download ibm public key](#282-download-ibm-public-key)
    - [2.8.3. Encrypted env template](#283-encrypted-env-template)
  - [2.9. Operation and maintenance personnel deploy applications](#29-operation-and-maintenance-personnel-deploy-applications)
    - [2.9.1. buile `user-data.yaml`](#291-buile-user-datayaml)
    - [2.9.2. Creating an instance through the IBM console](#292-creating-an-instance-through-the-ibm-console)
    - [2.9.3. Check the deployment status through logDNA](#293-check-the-deployment-status-through-logdna)
    - [2.9.4. Verifying Application Deployment](#294-verifying-application-deployment)
  - [2.10. Deploying an application via a plaintext template](#210-deploying-an-application-via-a-plaintext-template)
- [3. Sign the transaction using HPCS and broadcast the transaction on the test chain](#3-sign-the-transaction-using-hpcs-and-broadcast-the-transaction-on-the-test-chain)
  - [3.1. Description of main steps](#31-description-of-main-steps)
    - [3.1.1. Generate wallet through HPCS](#311-generate-wallet-through-hpcs)
    - [3.1.2. Apply for test coins](#312-apply-for-test-coins)
    - [3.1.3. Get a target address](#313-get-a-target-address)
    - [3.1.4. Use ethereum-client to broadcast transactions to the test chain rinkeby](#314-use-ethereum-client-to-broadcast-transactions-to-the-test-chain-rinkeby)
    - [3.1.5. Signing transactions on the test chain](#315-signing-transactions-on-the-test-chain)
    - [3.1.6. View transaction results](#316-view-transaction-results)
- [4. Reference Documentation](#4-reference-documentation)

# 1. Signature Server
 
 The signature server shows a scenario of [Hyper Protect Service](https://ibm-hyper-protect.github.io/) 

## 1.1. 环境介绍
![](./img/5.jpg)
- Deploy the signature server to the trusted execution environment HPVS in a manner similar to a multi-party contract
- The client communicates with the signature server through RestAPI (the production environment also requires TLS certificate verification)
- Since the signature server is deployed in HPVS in the form of a black box, the log information is sent to logDNA through the intranet to collect and visualize the log.
- The signing server communicates with HPCS through the GREP11 API (MTLS mutual certificate verification is also required in the production environment)
- Encrypted key, persisted in HPDBaaS
- IAM authenticates access and controls permissions
- VPC's security group and Network ACL control intranet communication on the network
- All communications are within the intranet
- Support IPsec to connect with private network intranet, or expose services through Floating IP+ firewall

## 1.2. The client communicates with the signature server through the following endpoints

```sh

export SIGN_HOST=<ip-address>
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



####################### 导入外部密钥 (TBD: 需要调试)
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

```
## 1.3. Sequence diagram and description of GREP11 API usage example
![](./img/GREP11%20API%20%20使用场景说明-详细版本.jpg)

### 1.3.1. Step-by-step instructions


## 1.4. Import key process

###  1.4.1. GREP11 AP1 import private key sequence diagram and description
![](./img/grep11_import_key.jpg)

### 1.4.2. Step-by-step instructions
   - Note: All the private keys generated by HPCS are wrapped by the internal master key and returned. The life cycle of the plaintext key cannot leave the HSM encryption card inside the HPCS. Before the key is used, HPCS will unwrap (decrypt) the wrapped key internally. After the key is used, the plaintext key will be discarded inside the HSM. These steps all take place inside the HPCS, and the client has no Perceived, so this part of the content will not be specifically explained below.
   - The general process is as follows: The imported key needs to be encrypted before being imported, and then decrypted inside the HSM. Inside the HSM, the master key wraps the decrypted plaintext private key, and HPCS returns the wrapped private key to the signature server. The second-encrypted private key is persisted in HPDBaaS.
   - The client request corresponding to the above steps is
     ```sh
      curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/key/import_ec -X POST -s  -F "file=@./ec256-key-pair.pem" | jq
     ```
   - Question 1: After HPCS wraps the private key with the master key, it is equivalent to that the key has been encrypted by the master key. Why is it necessary to use the KEK in the signature server for secondary encryption? This step is optional. The purpose of this step is that the KEK of the signing server is stored in the trusted execution environment within the security boundary of the secure enclave in HPVS, so this ensures that all operations must be performed by the signing server. Initiate because only the signature server has a KEK in it
   - Question 2: How to ensure the security and persistence of the KEK in the signature server? The signature server runs in a trusted execution environment (confidential computing) within HPVS and is deployed through a multi-party contract. The secure enclave in the signature server can be used for snapshots and cross-region backups, and it is encrypted with the seed generated during multi-party deployment, which means that only the client can enter the decryption, because the seed holder is through The form of multi-party deployment is controlled by multiple holders of the client.

# 2. Deploy the signature server

## 2.1. Introduction to HPVS

Based on the [confidential computing architecture](https://www.ibm.com/cloud/learn/confidential-computing), [HPVS for VPC](https://cloud.ibm.com/docs/vpc?topic=vpc-about-se#about_hyperprotect_vs_forvpc) provides a safe, reliable and credible way of deploying applications to computing resources. Compared with traditional CICD and business specification processes, the deployment process provided by IBM can ensure that images and environments cannot be It is tampered with and provides role isolation to ensure that holders of sensitive information or service endpoints cannot access the production environment, and at the same time, it can ensure that deployers cannot access sensitive information.

### 2.1.1. [Main Features of HPVS](https://www.ibm.com/cloud/blog/announcements/ibm-hyper-protect-virtual-servers-for-virtual-private-cloud)

- **Secure Execution**：Ensure that unauthorized users, including IBM Cloud administrators, cannot access applications through technology, not process. Workloads are locked down by separate instance-level security perimeters.
- **Multi-party contracts and proof of deployment**：Apply zero trust principles from workload development to deployment. With multiple roles and legal entities collaborating, segregation of responsibilities and access rights is critical. Hyper Protect Virtual Servers for VPC is based on the concept of cryptographic contracts, enabling each role to provide its own contribution while ensuring that no other role can access this data or IP through encryption. Deployments can be verified by auditors with attestation records, which are signed and encrypted to ensure that only auditors have this insight.
- **Malware Protection**：Use Secure Build to set up a verification process to ensure that only authorized code runs in the application. Hyper Protect Virtual Servers for VPC only deploy container versions, which are verified at deployment time.
- **Bring Your Own OCI Image**：Use any Open Container Initiative (OCI) image and get the benefits of a confidential computing solution for an extra level of protection
- **Flexible Deployment**：Choose from a variety of profile sizes and scale as needed to secure containerized applications and pay by the hour.

## 2.2. Main step description and role separation design
![byoi](./img/1.jpg)

### 2.2.1. Overview of the main steps

- 1 The developer pushes the code, triggers the CICD process, and the version server builds the version image
- 2 The version manager inspects the code, passes the inspection, and signs it with his own private key. Only images signed by the version manager can be deployed
- 3 The signed image is pushed to the mirror repository
- 4 Generate a deployment template through compose, and use the public key to encrypt the deployment template (encryption is an optional step)
- 5 Construct an environment template and use the public key to encrypt the environment variables (encryption is an optional step)
- 6 Merge the template and variables, and use the private key to digest the signature of the template (signature digest is an optional step)
- 7 Operation and maintenance personnel deploy applications through templates
- 8 After the server obtains the template, it decrypts it with the private key, and extracts the public key in the environment variable to perform fingerprint verification on the template.
- 9 The server extracts the public key in the deployment template to verify the image
- After the verification is passed, the application is successfully deployed

(Only the operation and maintenance personnel need to access the production environment, but the authority of the operation and maintenance personnel is the lowest. If the deployment template is encrypted, the operation and maintenance personnel cannot obtain any information.) (The workload template is some deployment image information and some non-sensitive variables. , the env template is usually information about some environment variables)

## 2.3. Role Definition

   角色 | work content | security and isolation
  --|:--|:--
  version manager | View code and version build server logs, sign images. Push the image through the CICD process or manually. If you push the image manually, you need permission to access the image repository | No need to touch production environment 
  role 1 | Build the workload template | No need to touch production environment
  role 2 | Build environment variable template | No need to touch production environment
  Operation and maintenance personnel | The encrypted deployment file is obtained from role 1 and role 2 to deploy the application, but the content of the deployment file cannot be read | No access to sensitive information, only applications can be deployed

## 2.4. Preparations

### 2.4.1. [Installing IBM CLI](https://cloud.ibm.com/docs/cli?topic=cli-getting-started)
### 2.4.2. Install IBM Container Registry
```
ibmcloud plugin repo-plugins -r 'IBM Cloud'  # list all of plugin
ibmcloud plugin install container-registry
```
### 2.4.3. [Install Docker](https://docs.docker.com/engine/install/)
  

## 2.5. Building the image

 The step of building and uploading the image to the IBM container registry is usually triggered automatically by the CICD tool or the build server. We simulate this process manually here.
 
### 2.5.1. Clone the repository
```sh
git clone https://github.com/threen134/signing_server.git
```

### 2.5.2. Building an Image
```sh
# 创建镜像
cd ./signing_server
docker build -t signing_server:v3  .
# 如果是非s39x架构， 使用下面对命令
docker buildx build --platform=linux/s390x  -t signing_server:v1 .  
```

### 2.5.3. Tag image
```sh
# tag 镜像
# au.icr.io 为上文中 IBM CR的endpoint 
# spark-demo 为上文创建的namespce
# s390x-signing-server:v3 为image：tag*  
docker tag signing_server:v1 au.icr.io/poc-demo/signing-server:v1
```

## 2.6. After the version manager inspects the code, execute the signing operation.
###  2.6.1. Create a trust key
```sh
# 创建的密钥需要输入密码，后面签名镜像的时候需要使用这个密钥读取私钥进行签名
docker trust key generate poc-test-sign-key
```
###  2.6.2. Enable DCT[(Docker Content Trust)](https://docs.docker.com/engine/security/trust/#signing-images-with-docker-content-trust)
```sh
# DCT 环境变量的语法格式为https://notary.<region>.icr.io， 记得调整为自己对应的region
# 亚洲地区有au，北美区域有us支持 notary
export DOCKER_CONTENT_TRUST=1
export DOCKER_CONTENT_TRUST_SERVER=https://notary.au.icr.io
```
### 2.6.3. Upload image and sign
```sh
# 登陆ibm container registry 
ibmcloud login --apikey <your api key> -g Default -r jp-tok
# 设置区域
ibmcloud cr region-set ap-south
ibmcloud cr login 
#为IBM CR 创建namespce，名字必须全局唯一
ibmcloud cr namespace-add poc-demo
# 上载镜像， 上传的时候需要输入私钥的密钥，如果是第一次使用notary，还需要设置notary的密码
docker push au.icr.io/poc-demo/signing-server:v1
# 查看签名信息
docker trust inspect au.icr.io/poc-demo/signing-server:v1 
```

### 2.6.4. Obtaining the signed public key

To share this public key `role 1`, role 1 needs to add the public key to the build template. When the subsequent image is deployed (step 9 in the topology diagram), this public key is required to verify the signature to ensure the integrity of the image.

```sh
# cat ~/.docker/trust/tuf/au.icr.io/<username>/<imagename>/metadata/root.json
cat ~/.docker/trust/tuf/au.icr.io/poc-demo/signing-server/metadata/root.json  |jq
```
**At this point, the version manager or CICD process has built an image and signed the image with its own private key.**  


## 2.7. `role 1` Build the WORKLOAD template
### 2.7.1. Convert the compose template file to base64

```sh
cd build
tar czvf - -C compose . | base64 -w0
H4sIAOG4/GIAA+3TTW+CMBwGcM77FD3syoui4k....
```
Note: If the execution environment is MAC, please use the gnu version of tar and base64

```sh
brew install coreutils
brew install gnu-tar
alias tar=gtar
alias base64=gbase64
```


### 2.7.2. Building a Workload Template
```yaml
# workload.yaml
type: workload
auths:
  # au.icr.io 为container registry 的endpoint， 
  au.icr.io:
    # 指定用户CR的用户名和密钥，IBM CR的用户名为iamapikey
    password: xxxx
    username: iamapikey
compose:
  # archive 的内容为 1.7.1 把compose模版文件转码为base64的输出
  archive: H4sIAOG4/GIAA+3TTW....
images:
  dct:
      # 如果镜像有被签名，需要指定notary的信息，如果镜像没有被签名，那么compose里的镜像需要指定摘要信息
      # 对应compose里的image信息
    au.icr.io/spark-demo/s390x-signing-server:
      # notary endpoint
      notary: "https://notary.au.icr.io"
      # 步骤1.6.5 中获取到的公钥
      publicKey: LS0tLS1CRUdJTiBDRVJ....
env:
  # 设置一些非敏感环境变量，这些变量对应compose里的信息
  POSTGRESS_ADDRESS: "dbaas905.hyperp-dbaas.cloud.ibm.com"
  POSTGRESS_PORT: "30025"
  POSTGRESS_USERNAME: "admin"
  POSTGRESS_DBNAME: "admin"
  HPCS_ADDRESS: ep11.us-east.hs-crypto.cloud.ibm.com
  HPCS_PORT: "13412"
  HPCS_INSTANCE_ID: "4ad01aec-dc81-4158....."
  HPCS_IAM_ENDPOINT: "https://iam.cloud.ibm.com"
  SECURE_ENCLAVE_PATH: "/etc/secure_enclave"
#数据卷的加密是根据workload里的seed 和 env 字段里的seed 来共同产生的密钥。
#特别注意： boot volume 不可以用来做持久化。重启后boot volume 修改的内容被丢弃
#（boot volume 的任何改动都被视为代码被修改，从而破坏完整性，检测将不会被通过，计算实例将无法部署或者启动）
volumes:
    volume1:
        mount: /etc/secure_enclave
        seed: stsolutiontest
        filesystem: btrfs
```


### 2.7.3. Download ibm public key 
```sh
wget https://cloud.ibm.com/media/docs/downloads/hyper-protect-container-runtime/ibm-hyper-protect-container-runtime-1-0-s390x-3-encrypt.crt
```

### 2.7.4. Encrypting workloads 
```sh
# 设置变量
WORKLOAD=./workload.yaml
CONTRACT_KEY=./ibm-hyper-protect-container-runtime-1-0-s390x-3-encrypt.crt
# 随机产生一个32位密码
PASSWORD="$(openssl rand 32 | base64 -w0)"
# 使用证书加密密码
ENCRYPTED_PASSWORD="$(echo -n "$PASSWORD" | base64 -d | openssl rsautl -encrypt -inkey $CONTRACT_KEY -certin | base64 -w0 )"
#使用密码加密workload
ENCRYPTED_WORKLOAD="$(echo -n "$PASSWORD" | base64 -d | openssl enc -aes-256-cbc -pbkdf2 -pass stdin -in "$WORKLOAD" | base64 -w0)"
#把加密后的密码，与加密后对workload 组合起来
#把得到的输出交给部署人员
echo "hyper-protect-basic.${ENCRYPTED_PASSWORD}.${ENCRYPTED_WORKLOAD}"
#当HPVS第一次构建的时候它会用私钥对密码进行解密，得到明文的密码后，用密码对workload进行解密  
```
如果加密报这个错误 `unknown option '-pbkdf2'`，需要[升级openssh](https://gist.github.com/fernandoaleman/5459173e24d59b45ae2cfc618e20fe06)

备注： 如果执行环境是MAC, 使用openssl 代替默认的 LibreSSL
```
brew update
brew install openssl
# if it is already installed, update it:
brew upgrade openssl@1.1
echo 'export PATH="/opt/homebrew/opt/openssl@3/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc 
```

## 2.8. `role2`Build an ENV template

### 2.8.1. 创建env 模版
这里主要是[设置logDNA的字段](https://cloud.ibm.com/docs/vpc?topic=vpc-about-se&interface=ui#hpcr_setup_logging),可选的数据卷与环境变量

```yaml
# env.yaml
type: env
logging:
  logDNA:
    hostname: syslog-a.private.jp-tok.logging.cloud.ibm.com
    ingestionKey: 7a98add3.....
    port: 6514
volumes:
  volume1:
    seed: thisisatest
env:
  # 设置一些敏感环境信息
  POSTGRESS_PASSWORD: xxxxx
  # PG 的证书base64 编码信息
  # echo ./cert.pem | base64 -w0
  POSTGRESS_SSLROOTCERT: "LS0tLS1CRUdJTiBDRVJUSU....."
  HPCS_IAM_KEY: "xxxx...."
```

部署的所有日志和后续应用程序的日志，可以通过logDNA来获取日志，请[参考这个文档](https://cloud.ibm.com/docs/vpc?topic=vpc-about-se&interface=ui#hpcr_setup_logging)创建并获取LogDNA实例的信息，同时logDNA可以使用[内网链接](https://cloud.ibm.com/docs/log-analysis?topic=log-analysis-service-connection#endpoint-setup)    

### 2.8.2. Download ibm public key 
```sh
wget https://cloud.ibm.com/media/docs/downloads/hyper-protect-container-runtime/ibm-hyper-protect-container-runtime-1-0-s390x-3-encrypt.crt
```

### 2.8.3. Encrypted env template
```sh
# 设置变量
ENV=./env.yaml
CONTRACT_KEY=./ibm-hyper-protect-container-runtime-1-0-s390x-3-encrypt.crt
# 随机产生一个32位密码
PASSWORD="$(openssl rand 32 | base64 -w0)"
# 使用证书加密密码
ENCRYPTED_PASSWORD="$(echo -n "$PASSWORD" | base64 -d | openssl rsautl -encrypt -inkey $CONTRACT_KEY -certin | base64 -w0 )"
#使用密码加密workload
ENCRYPTED_ENV="$(echo -n "$PASSWORD" | base64 -d | openssl enc -aes-256-cbc -pbkdf2 -pass stdin -in "$ENV" | base64 -w0)"
#把加密后的密码，与加密后对env 组合起来
#把得到输出交给部署人员
echo "hyper-protect-basic.${ENCRYPTED_PASSWORD}.${ENCRYPTED_ENV}"
#当HPVS第一次构建的时候它会用私钥对密码进行解密，得到明文的密码后，用密码对env进行解密  
```

## 2.9. Operation and maintenance personnel deploy applications

### 2.9.1. buile `user-data.yaml`
从角色1与角色2拿到加密后对数据后构建类似下面的文件
```yaml
  workload: hyper-protect-basic.js7TGt77EQ5bgTIKk5C0pViFTRHqWtn..............
  env: hyper-protect-basic.VWg/5/SWE+9jLfhr8q4i.........
```
### 2.9.2. Creating an instance through the IBM console 
The configuration is as shown below  
<img src="./img/2.jpeg" width="500" alt="图片名称" align=center>  

### 2.9.3. Check the deployment status through logDNA
<img src="./img/3.jpg" width="500" alt="图片名称" align=center>

### 2.9.4. Verifying Application Deployment
Mount a floating IP to the deployed signature server, then list the state machine ·
```sh
curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/get_mechanismsc
```

## 2.10. Deploying an application via a plaintext template
If you do not need encrypted deployment, you can also deploy the application through the clear text template, which is usually used in the development environment or when testing the deployment.

```yaml
# cat user-data.yaml
workload: |
  type: workload
  auths:
    au.icr.io:
      password: Do0JROuGXO....
      username: iamapikey
  compose:
    archive: H4sIAOG4/GIAA+3TTW....
  images:
    dct:
      au.icr.io/spark-demo/s390x-signing-server:
        notary: "https://notary.au.icr.io"
        publicKey: LS0tLS1CRUdJTiBDRVJUSUZ.....
  env:
    POSTGRESS_ADDRESS: dbaas905.hyperp-dbaas.c....
    POSTGRESS_PORT: "30025"
    POSTGRESS_USERNAME: "admin"
    POSTGRESS_DBNAME: "admin"
    HPCS_ADDRESS: ep11.us-east.hs-crypto.cloud.ibm.com
    HPCS_PORT: "13412"
    HPCS_INSTANCE_ID: ad01aec-dc81.....
    HPCS_IAM_ENDPOINT: "https://iam.cloud.ibm.com"
    SECURE_ENCLAVE_PATH: "/etc/secure_enclave"
  volumes:
    volume1:
      mount: /etc/secure_enclave
      seed: stsolutiontest
      filesystem: btrfs
env: |
  type: env
  logging:
    logDNA:
      hostname: syslog-a.private.jp-tok.logging.cloud.ibm.com
      ingestionKey: 7a98add39999e9.....
      port: 6514
  volumes:
    volume1:
      seed: thisisatest
  env:
    POSTGRESS_PASSWORD: "......"
    POSTGRESS_SSLROOTCERT: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t....."
    HPCS_IAM_KEY: "3lHSZqcuCh4b_....
```

# 3. Sign the transaction using HPCS and broadcast the transaction on the test chain
## 3.1. Description of main steps
### 3.1.1. Generate wallet through HPCS
```sh

export SIGN_HOST=localhost
export SIGNING_PORT=8080
curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/key/secp256k1/generate_key_pair -X POST -s | jq
# 获取钱吧的UUID并设置到环境变量
export KEY_UUID=c006f05e-002c-4fcf-b530-6e9820db03db
#获取 from_address 交易地址
curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/key/secp256k1/get_ethereum_key/${KEY_UUID}  -s | jq
```

### 3.1.2. Apply for test coins
拿到上一步产生的地址，在[水管](https://fauceth.komputing.org/)上申请`rinkeby`测试币
### 3.1.3. Get a target address
获取一个目标交易地址, 或者通过上面的步骤生产一个新的钱包并获取 `to address`
### 3.1.4. Use ethereum-client to broadcast transactions to the test chain rinkeby
- 加载环境变量
```sh
cd ./ethereum-client
cp ./env.sh.template ./env.sh
# 编辑env.sh
source ./ethereum-client/env.sh
```

### 3.1.5. Signing transactions on the test chain
```sh 
  go run ./... 
  # 得到输出
  https://rinkeby.etherscan.io/tx/0x71231d85bfa7497f09a54023535874779a3e73a2c0084fa8a1612f9cb709a7a1 
```

### 3.1.6. View transaction results

![6](./img/6.jpg)

# 4. Reference Documentation
- [About the contract](https://cloud.ibm.com/docs/vpc?topic=vpc-about-contract_se#hpcr_contract_encrypt_workload)
- [signing-images-with-docker-content-trust](https://docs.docker.com/engine/security/trust/#signing-images-with-docker-content-trust) 
- [How to Sign Your Docker Images](https://www.cloudsavvyit.com/12388/how-to-sign-your-docker-images-to-increase-trust)
- [Docker Notary服务架构](https://blog.csdn.net/weixin_41335923/article/details/121702125)

