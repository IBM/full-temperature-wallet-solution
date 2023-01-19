package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"path"
	"time"

	log "github.com/sirupsen/logrus"

	"crypto/tls"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	gmsql "gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const PostGresCertName = "db_cert.pem"

// path to cert-files hard coded
// Most of this is copy pasted from the internet
// and used without much reflection
func createTLSConf(ca string) tls.Config {

	rootCertPool := x509.NewCertPool()
	pem, err := ioutil.ReadFile(ca)
	if err != nil {
		log.Fatal(err)
	}
	if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
		log.Fatal("Failed to append PEM.")
	}
	// clientCert := make([]tls.Certificate, 0, 1)

	// certs, err := tls.LoadX509KeyPair("cert/client-cert.pem", "cert/client-key.pem")
	// if err != nil {
	//     log.Fatal(err)
	// }

	// clientCert = append(clientCert, certs)

	return tls.Config{
		RootCAs: rootCertPool,
		//    Certificates:       clientCert,
		InsecureSkipVerify: true, // needed for self signed certs
	}
}

func getDB(config *Config) *gorm.DB {
	dbCertPath := path.Join(config.SecureEnclavePath, PostGresCertName)
	log.WithField("DB_PATH", dbCertPath).Info("start load DB Cert")
	if err := ValidateConfigPath(dbCertPath); err != nil {
		log.Info("start build cert file to secure enclave")
		ioutil.WriteFile(dbCertPath, toByte(config.DB.SSLRootCert), 0466)
	}

	dsn := ""

	if config.DbType == "mysql" {
		// When I realized that the tls/ssl/cert thing was handled separately
		// it became easier, the following two lines are the important bit
		tlsConf := createTLSConf(dbCertPath)
		err := mysql.RegisterTLSConfig("custom", &tlsConf)
		if err != nil {
			log.Panic(err)
		}
		// try to connect to mysql database.
		cfg := mysql.Config{
			User:                 config.DB.Username,
			Passwd:               config.DB.Password,
			Addr:                 fmt.Sprintf("%s:%s", config.DB.Address, config.DB.Port), //IP:PORT
			Net:                  "tcp",
			DBName:               config.DB.Dbname,
			Loc:                  time.Local,
			AllowNativePasswords: true,
			TLSConfig:            "custom",
		}
		dsn = cfg.FormatDSN()
	} else {
		dsn = fmt.Sprintf(
			"host=%s port=%s user=%s dbname=%s password=%s sslrootcert=%s sslmode=verify-full TimeZone=Asia/Shanghai",
			//   "host=%s port=%s user=%s dbname=%s password=%s TimeZone=Asia/Shanghai",
			config.DB.Address,
			config.DB.Port,
			config.DB.Username,
			config.DB.Dbname,
			config.DB.Password,
			dbCertPath,
		)
	}

	log.Println(dsn)

	var db *gorm.DB
	var err error
	if config.DbType == "mysql" {
		db, err = gorm.Open(gmsql.Open(dsn), &gorm.Config{})
	} else {
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	}

	if err != nil {
		log.Println("Connect DB failed.")
		log.Fatal(fmt.Sprintf("err: %v", err))
	} else {
		log.Println("Connect DB success.")
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
	log.WithField("key", key).Println("insert success")
	return key, nil
}

func getKeyByUUID(db *gorm.DB, keyUuid string) *KeyStore {
	log.WithField("key_uuid", keyUuid).Info("start search key")
	key := &KeyStore{}
	db.First(key, "uuid=?", keyUuid)
	return key
}
