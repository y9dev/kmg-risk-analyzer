package config

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type config struct {
	databaseURL string
	redisURL    string
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Panicf("env %q not set", key)
	}
	return v
}

func mustEnvInt(key string) int {
	v := mustEnv(key)
	i, err := strconv.Atoi(v)
	if err != nil {
		log.Panicf("invalid int in %q: %v", key, err)
	}
	return i
}

func envIntDefault(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		log.Panicf("invalid int in %q: %v", key, err)
	}
	return i
}

func envBoolDefault(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		log.Panicf("invalid bool in %q: %v", key, err)
	}
	return b
}

func envStringDefault(key string, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func envBool(key string) bool {
	return os.Getenv(key) == "true"
}

var conf config

func Init() {
	if os.Getenv("BOT_TOKEN") == "" {
		if err := godotenv.Load(); err != nil {
			panic(fmt.Sprintf("failed to load .env file: %v", err))
		}
	}
	conf.databaseURL = mustEnv("DATABASE_URL")
	conf.redisURL = mustEnv("REDIS_URL")
}

func DatabaseURL() string {
	return conf.databaseURL
}

func RedisURL() string {
	return conf.redisURL
}
