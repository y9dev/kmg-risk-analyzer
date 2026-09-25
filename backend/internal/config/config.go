package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type config struct {
	databaseURL string
}

var conf config

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Panicf("env %q not set", key)
	}
	return v
}

func Init() {
	if os.Getenv("DATABASE_URL") == "" {
		_ = godotenv.Load()
	}

	conf.databaseURL = mustEnv("DATABASE_URL")
}

func DatabaseURL() string {
	return conf.databaseURL
}
