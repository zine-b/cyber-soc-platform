package config

import "os"

type Config struct {
	AppName     string
	AppVersion  string
	DatabaseURL string
	FrontendURL string
	Port        string
}

func Load() Config {
	return Config{
		AppName:     env("APP_NAME", "Cyber SOC Platform API"),
		AppVersion:  env("APP_VERSION", "0.1.0"),
		DatabaseURL: env("DATABASE_URL", "sqlite:///./cyber_soc.db"),
		FrontendURL: env("FRONTEND_URL", "http://localhost:5173"),
		Port:        env("PORT", "8000"),
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
