package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	App struct {
		Port int    `yaml:"port"`
		Mode string `yaml:"mode"` // debug | release
		// Issuer is the OIDC issuer URL. Everything the service
		// signs uses this as the `iss` claim, and `/.well-known/`
		// discovery points back at it. Moving this after users are
		// in the wild requires re-signing keys — change with care.
		Issuer string `yaml:"issuer"`
	} `yaml:"app"`

	MySQL struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		Database string `yaml:"database"`
	} `yaml:"mysql"`

	Redis struct {
		Addr     string `yaml:"addr"`
		Password string `yaml:"password"`
		DB       int    `yaml:"db"`
	} `yaml:"redis"`

	Signing struct {
		// Path to a directory containing RS256 keypairs.
		// Each .pem file is one key; filename (sans ext) becomes kid.
		// At least one key must be present at startup.
		KeyDir string `yaml:"key_dir"`
	} `yaml:"signing"`

	JWT struct {
		AccessTTLSec  int `yaml:"access_ttl_sec"`  // 15 min default
		RefreshTTLSec int `yaml:"refresh_ttl_sec"` // 30 days default
	} `yaml:"jwt"`

	OAuth struct {
		Google struct {
			ClientID     string `yaml:"client_id"`
			ClientSecret string `yaml:"client_secret"`
			RedirectURI  string `yaml:"redirect_uri"`
		} `yaml:"google"`
		GitHub struct {
			ClientID     string `yaml:"client_id"`
			ClientSecret string `yaml:"client_secret"`
			RedirectURI  string `yaml:"redirect_uri"`
		} `yaml:"github"`
	} `yaml:"oauth"`

	Legacy struct {
		// During the shadow phase we read from QuantArena's MySQL so
		// existing rm_pat_* tokens keep working without a data migration.
		// Flip `enabled` off once Phase 3 ships.
		Enabled       bool   `yaml:"enabled"`
		DSN           string `yaml:"dsn"` // trading_community MySQL DSN
	} `yaml:"legacy"`
}

var G *Config

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, err
	}
	G = c
	return c, nil
}
