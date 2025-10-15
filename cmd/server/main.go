package main

import (
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"os"
	"path/filepath"

	"github.com/joho/godotenv"
	"github.com/shreeyash-ugale/secureFile/internal/api"
	"github.com/shreeyash-ugale/secureFile/internal/config"
)

func main() {
	// Try loading .env from common locations so `go run cmd/server/main.go` works
	tryLoadEnv := []string{".env", filepath.Join("..", ".env"), filepath.Join("..", "..", ".env")}
	for _, p := range tryLoadEnv {
		if _, err := os.Stat(p); err == nil {
			_ = godotenv.Load(p)
			break
		}
	}
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	api.RegisterRoutes(r, cfg)

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("server listening on :%s", cfg.Port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}
