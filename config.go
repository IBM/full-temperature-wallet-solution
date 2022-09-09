package main

import (
	"fmt"
	"os"

	"github.com/vrischmann/envconfig"
	"gopkg.in/yaml.v2"
)

// Config struct
type Config struct {
	Postgress struct {
		Address     string `yaml:"address"`
		Port        string `yaml:"port"`
		Username    string `yaml:"username"`
		Password    string `yaml:"password"`
		Dbname      string `yaml:"dbname"`
		SSLRootCert string `yaml:"sslrootcert"`
	} `yaml:"postgress"`
	Hpcs struct {
		Address     string `yaml:"host"`
		Port        string `yaml:"port"`
		InstanceId  string `yaml:"instance_id"`
		IAMKey      string `yaml:"iam_key"`
		IAMEndpoint string `yaml:"iam_endpoint"`
	}
	SecureEnclavePath string `yaml:"secure_enclave_path"` 
}

// NewConfig returns a new decoded Config struct
func NewDBConfig(configPath string) (*Config, error) {
	// Create config structure
	config := &Config{}

	// Open config file
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Init new YAML decode
	d := yaml.NewDecoder(file)

	// Start YAML decoding from file
	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

// ValidateConfigPath just makes sure, that the path provided is a file,
// that can be read
func ValidateConfigPath(path string) error {
	s, err := os.Stat(path)
	if err != nil {
		return err
	}
	if s.IsDir() {
		return fmt.Errorf("'%s' is a directory, not a normal file", path)
	}
	return nil
}

func loadConfigFromEnv() (*Config, error) {
	config := &Config{}
	if err := envconfig.Init(&config); err != nil {
		return nil, err
	}
	return config, nil
}
