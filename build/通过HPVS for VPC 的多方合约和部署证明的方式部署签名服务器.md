


# 1. 通过[HPVS for VPC](https://www.ibm.com/cloud/blog/announcements/ibm-hyper-protect-virtual-servers-for-virtual-private-cloud) 的多方合约和部署证明的方式部署签名服务器
作者： 刘建国 spark.liu@cn.ibm.com
- [1. 通过HPVS for VPC 的多方合约和部署证明的方式部署签名服务器](#1-通过hpvs-for-vpc-的多方合约和部署证明的方式部署签名服务器)
  - [1.1. HPVS 介绍](#11-hpvs-介绍)
    - [1.1.1. HPVS 的主要特性](#111-hpvs-的主要特性)
  - [1.2. 主要步骤描述与角色分离设计](#12-主要步骤描述与角色分离设计)
    - [1.2.1. 主要步骤概述](#121-主要步骤概述)
  - [1.3. 角色定义](#13-角色定义)
  - [1.4. 准备工作](#14-准备工作)
    - [1.4.1. 安装IBMCLI](#141-安装ibmcli)
    - [1.4.2. 安装IBM Container Registry](#142-安装ibm-container-registry)
    - [1.4.3. 安装Docker](#143-安装docker)
  - [1.5. 构建镜像](#15-构建镜像)
    - [1.5.1. 克隆代码仓库](#151-克隆代码仓库)
    - [1.5.2. 构建镜像](#152-构建镜像)
    - [1.5.3. tag镜像](#153-tag镜像)
  - [1.6. 版本经理检视代码后，执行签名操作。](#16-版本经理检视代码后执行签名操作)
    - [1.6.1. 创建trust key](#161-创建trust-key)
    - [1.6.2. 开启DCT(Docker Content Trust)](#162-开启dctdocker-content-trust)
    - [1.6.3. 上传镜像并签名](#163-上传镜像并签名)
    - [1.6.4. 获取签名的公钥](#164-获取签名的公钥)
  - [1.7. `角色1`构建WORKLOAD模版](#17-角色1构建workload模版)
    - [1.7.1. 把compose模版文件转码为base64](#171-把compose模版文件转码为base64)
    - [1.7.2. 构建workload模版](#172-构建workload模版)
    - [1.7.3. 下载ibm的公钥](#173-下载ibm的公钥)
    - [1.7.4. 加密workload](#174-加密workload)
  - [1.8. `角色2`构建ENV模版](#18-角色2构建env模版)
    - [1.8.1. 创建env 模版](#181-创建env-模版)
    - [1.8.2. 下载ibm的公钥](#182-下载ibm的公钥)
    - [1.8.3. 加密env 模版](#183-加密env-模版)
  - [1.9. 运维人员部署应用](#19-运维人员部署应用)
    - [1.9.1. 构建`user-data.yaml`文件](#191-构建user-datayaml文件)
    - [1.9.2. 通过IBM console 创建实例](#192-通过ibm-console-创建实例)
    - [1.9.3. 通过logDNA 查看部署情况](#193-通过logdna-查看部署情况)
    - [1.9.4. 验证应用部署](#194-验证应用部署)
  - [1.10. 通过明文模版部署应用](#110-通过明文模版部署应用)
  - [1.11. 参考文档](#111-参考文档)

## 1.1. HPVS 介绍
[HPVS for VPC](https://cloud.ibm.com/docs/vpc?topic=vpc-about-se#about_hyperprotect_vs_forvpc) 基于[机密计算](https://www.ibm.com/cloud/learn/confidential-computing)的体系结构下，提供了一种安全可靠可信的部署应用到计算资源的方式，和传统的CICD与业务规范流程相比，IBM提供的部署流程能保证镜像与环境无法被篡改，同时提供了角色隔离，保证敏感信息的持有者或者服务端点无法接触到生产环境，同时可以保证部署人员无法接触到敏感信息。

### 1.1.1. [HPVS 的主要特性](https://www.ibm.com/cloud/blog/announcements/ibm-hyper-protect-virtual-servers-for-virtual-private-cloud)

- **安全执行**：通过技术而不是流程保证未经授权的用户（包括 IBM Cloud 管理员）无法访问应用程序。工作负载被单独的实例级安全边界锁定。
- **多方合同和部署证明**：从工作负载开发到部署应用零信任原则。随着多个角色和法人实体的协作，区分职责和访问权限至关重要。适用于 VPC 的 Hyper Protect Virtual Servers 基于加密合同概念，使每个角色都能够提供自己的贡献，同时通过加密确保其他角色都无法访问此数据或IP。部署可以由审计人员通过证明记录进行验证，该记录经过签名和加密，以确保只有审计人员具有这种洞察力。
- **恶意软件保护**：利用 Secure Build 设置验证过程，以确保只有授权代码在应用程序中运行。Hyper Protect Virtual Servers for VPC 仅部署容器版本，这些版本在部署时进行验证。
- **自带 OCI 映像**：使用任何开放容器倡议 (OCI) 映像并获得机密计算解决方案的好处，以提供额外级别的保护
- **灵活的部署**：从各种配置文件大小中进行选择，并根据需要进行扩展，以保护容器化应用程序并按小时付费。

## 1.2. 主要步骤描述与角色分离设计
![byoi](./img/1.jpg)

### 1.2.1. 主要步骤概述
  
- 1 开发人员push 代码，触发CICD流程，版本服务器构建版本镜像
- 2 版本经理检视代码，检视通过，使用自己的私钥进行签名，只有经过版本经理签名的镜像才能够被部署
- 3 签名后的镜像被推送到镜像仓库
- 4 通过compose 生成部署模版，使用公钥对部署模版加密（加密为可选步骤）
- 5 构造环境模版，使用公钥对环境变量进行加密（加密为可选步骤）
- 6 合并模版与变量，使用私钥对模版进行摘要签名 （签名摘要为可选步骤）
- 7 运维人员通过模版部署应用
- 8 服务器获取到模版后，使用私钥进行解密，并提取环境变量里的公钥对模版进行指纹验证。
- 9 服务器提取部署模版里的公钥对镜像进行验证
- 验证通过后，应用成功部署

（只有运维人员需要接触生产环境，但是运维人员的权限是最低的，如果部署模版经过加密，那么运维人员获取不到任何信息。）
（workload模版为一些部署镜像信息以及一些非敏感变量，env模版通常为一些环境变量的信息）
## 1.3. 角色定义

   角色 | 工作内容 | 安全与隔离性
  --|:--|:--
  版本经理 | 检视代码与版本构建服务器的日志，签名镜像。通过CICD流程或者手动推送镜像，如果手动推送镜像，需要访问镜像仓库的权限 | 不需要接触生产环境 
  角色1 | 构建workload模版 | 不需要接触生产环境
  角色2 | 构建环境变量模版 | 不需要接触生产环境
  运维人员 | 从角色1和角色2拿到被加密的部署文件部署应用，但是无法读取部署文件的内容 | 不能接触敏感信息，只能部署应用

## 1.4. 准备工作

### 1.4.1. [安装IBMCLI](https://cloud.ibm.com/docs/cli?topic=cli-getting-started)
### 1.4.2. 安装IBM Container Registry
```
ibmcloud plugin repo-plugins -r 'IBM Cloud'  # list all of plugin
ibmcloud plugin install container-registry
```
### 1.4.3. [安装Docker](https://docs.docker.com/engine/install/)
  

## 1.5. 构建镜像

 构建并上传镜像到IBM container registry  
 这一步通常由CICD工具或者构建服务器自动触发，我们这里手动模拟这个流程。
 
### 1.5.1. 克隆代码仓库
```sh
git clone https://github.com/threen134/signing_server.git
```

### 1.5.2. 构建镜像
```sh
# 创建镜像
cd ./signing_server
docker build -t signing_server:v3  .
```

### 1.5.3. tag镜像
```sh
# tag 镜像
# au.icr.io 为上文中 IBM CR的endpoint 
# spark-demo 为上文创建的namespce
# s390x-signing-server:v3 为image：tag*  
docker tag signing_server:v3 au.icr.io/spark-demo/s390x-signing-server:v3
```

## 1.6. 版本经理检视代码后，执行签名操作。
###  1.6.1. 创建trust key
```sh
# 创建的密钥需要输入密码，后面签名镜像的时候需要使用这个密钥读取私钥进行签名
docker trust key generate spark1234
```
###  1.6.2. 开启DCT[(Docker Content Trust)](https://docs.docker.com/engine/security/trust/#signing-images-with-docker-content-trust)
```sh
# DCT 环境变量的语法格式为https://notary.<region>.icr.io， 记得调整为自己对应的region
# 亚洲地区有au，北美区域有us支持 notary
export DOCKER_CONTENT_TRUST=1
export DOCKER_CONTENT_TRUST_SERVER=https://notary.au.icr.io
```
### 1.6.3. 上传镜像并签名
```sh
# 登陆ibm container registry 
ibmcloud login --sso --apikey <your api key> -g Default
# 设置区域
ibmcloud cr region-set ap-south
ibmcloud cr login 
#为IBM CR 创建namespce，名字必须全局唯一
ibmcloud cr namespace-add spark-demo
# 上载镜像， 上传的时候需要输入私钥的密钥，如果是第一次使用notary，还需要设置notary的密码
docker push au.icr.io/spark-demo/s390x-signing-server:v3
# 查看签名信息
docker trust inspect au.icr.io/spark-demo/s390x-signing-server:v3 
```
### 1.6.4. 获取签名的公钥
 把这个公钥分享给`角色1`, 角色1需要把公钥加入到构建模版，后续镜像被部署的时候(拓扑图步骤9)，需要这个公钥验证签名来保证镜像的完整性。
```sh
# cat ~/.docker/trust/tuf/au.icr.io/<username>/<imagename>/metadata/root.json
cat ~/.docker/trust/tuf/au.icr.io/spark-demo/s390x-signing-server/metadata/root.json  |jq
```
**至此，版本经理或者CICD流程，构建了一个image，并且使用自己的私钥签名了这个image。**  


## 1.7. `角色1`构建WORKLOAD模版
### 1.7.1. 把compose模版文件转码为base64

```sh
cd build
tar czvf - -C compose . | base64 -w0
H4sIAOG4/GIAA+3TTW+CMBwGcM77FD3syoui4k....
```

### 1.7.2. 构建workload模版
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


### 1.7.3. 下载ibm的公钥 
```sh
wget https://cloud.ibm.com/media/docs/downloads/hyper-protect-container-runtime/ibm-hyper-protect-container-runtime-1-0-s390x-3-encrypt.crt
```

### 1.7.4. 加密workload 
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

## 1.8. `角色2`构建ENV模版

### 1.8.1. 创建env 模版
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

### 1.8.2. 下载ibm的公钥 
```sh
wget https://cloud.ibm.com/media/docs/downloads/hyper-protect-container-runtime/ibm-hyper-protect-container-runtime-1-0-s390x-3-encrypt.crt
```

### 1.8.3. 加密env 模版
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

## 1.9. 运维人员部署应用

### 1.9.1. 构建`user-data.yaml`文件
从角色1与角色2拿到加密后对数据后构建类似下面的文件
```yaml
  workload: hyper-protect-basic.js7TGt77EQ5bgTIKk5C0pViFTRHqWtn..............
  env: hyper-protect-basic.VWg/5/SWE+9jLfhr8q4i.........
```
### 1.9.2. 通过IBM console 创建实例 
配置如下图  
<img src="./img/2.jpeg" width="500" alt="图片名称" align=center>  

### 1.9.3. 通过logDNA 查看部署情况
<img src="./img/3.jpg" width="500" alt="图片名称" align=center>

### 1.9.4. 验证应用部署
挂载一个floating IP 到部署的签名服务器, 然后list 状态机·
```sh
curl ${SIGN_HOST}:${SIGNING_PORT}/v1/grep11/get_mechanismsc
```

## 1.10. 通过明文模版部署应用
 如果你没有加密部署的需求，也可以通过明文模版的方式部署应用，这通常用于开发环境或者对部署进行测试时使用。
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


## 1.11. 参考文档
- [About the contract](https://cloud.ibm.com/docs/vpc?topic=vpc-about-contract_se#hpcr_contract_encrypt_workload)
- [signing-images-with-docker-content-trust](https://docs.docker.com/engine/security/trust/#signing-images-with-docker-content-trust) 
- [How to Sign Your Docker Images](https://www.cloudsavvyit.com/12388/how-to-sign-your-docker-images-to-increase-trust)
- [Docker Notary服务架构](https://blog.csdn.net/weixin_41335923/article/details/121702125)
