package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"

	"github.com/IBM-Cloud/hpcs-grep11-go/util"
	log "github.com/sirupsen/logrus"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gorm.io/gorm"
)

var cfg = loadCfg()
var db = getDB(cfg)
var kek = []byte{}

type KeyStore struct {
	gorm.Model
	Name       string `json:"name"`
	Uuid       string `json:"uuid"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

func ( k *KeyStore) String() string{
	ks, _ := json.Marshal(k)
	return string(ks)
}

type global struct {
	cfg        *Config
	db         *gorm.DB
	grpcClient func() (*grpc.ClientConn, error)
}

func getGlobal() global {
	if cfg == nil {
		cfg = loadCfg()
	}
	if db == nil {
		db = getDB(cfg)
	}
	return global{
		cfg:        cfg,
		db:         db,
		grpcClient: grpcCall,
	}
}

func loadCfg() *Config {
	config, err := loadConfigFromEnv()
	if err != nil {
		log.Fatal(fmt.Sprintf("err: %v", err))
	}
	return config
}

func grpcCall() (*grpc.ClientConn, error) {
	cfg := getGlobal().cfg
	callOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})),
		grpc.WithPerRPCCredentials(&util.IAMPerRPCCredentials{
			APIKey:   cfg.Hpcs.IAMKey,
			Endpoint: cfg.Hpcs.IAMEndpoint,
		}),
	}
	endpoint := fmt.Sprintf("%s:%s", cfg.Hpcs.Address, cfg.Hpcs.Port)
	return grpc.Dial(endpoint, callOpts...)
}
