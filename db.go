package main

import (
	"fmt"
	"io/ioutil"
	"path"

	log "github.com/sirupsen/logrus"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const PostGresCertName = "db_cert.pem"

func getDB(config *Config) *gorm.DB {
	dbCertPath := path.Join(config.SecureEnclavePath, PostGresCertName)
	log.WithField("DB_PATH", dbCertPath).Info("start load DB Cert")
	if err := ValidateConfigPath(dbCertPath); err != nil {
		log.Info("start build cert file to secure enclave")
		ioutil.WriteFile(dbCertPath, toByte(config.Postgress.SSLRootCert), 0466)
	}

	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s dbname=%s password=%s sslrootcert=%s sslmode=verify-full TimeZone=Asia/Shanghai",
		config.Postgress.Address,
		config.Postgress.Port,
		config.Postgress.Username,
		config.Postgress.Dbname,
		config.Postgress.Password,
		dbCertPath,
	)
	log.Println(dsn)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		log.Println("DB连接失败！")
		log.Fatal(fmt.Sprintf("err: %v", err))
	} else {
		log.Println("DB连接成功！")
	}

	log.Println("Successfully connected to database!", db)
	err = db.AutoMigrate(&KeyStore{})
	if err != nil {
		log.Println("Unable to migrate table. Err:", err)
		log.Fatal(fmt.Sprintf("err: %v", err))
		return nil
	}
	return db
}

func insertKey(db *gorm.DB, privateKey, publicKey string) (*KeyStore, error) {
	keyId := uuid.New().String()
	key := &KeyStore{
		Uuid:       keyId,
		Name:       keyId,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
	if err := db.Create(key).Error; err != nil {
		log.WithField("key", key).WithError(err).Error("fail to insert to DB")
		log.Println("", err)
		return nil, err
	}
	log.WithField("key", key).Println("插入成功！")
	return key, nil
}

func getKeyByUUID(db *gorm.DB, keyUuid string) *KeyStore {
	log.WithField("key_uuid", keyUuid).Info("start search key")
	key := &KeyStore{}
	db.First(key, "uuid=?", keyUuid)
	return key
}
