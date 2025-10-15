package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
    Port       string
    Region     string
    Bucket     string
    KMSKeyID   string
    AdminToken string
    DynamoTable string
}

func loadDotEnvOnce() {
    paths := []string{
        ".env",
        filepath.Join("..", ".env"),
        filepath.Join("..", "..", ".env"),
    }
    for _, p := range paths {
        if _, err := os.Stat(p); err == nil {
            _ = godotenv.Load(p)
            return
        }
    }
}

func envOrDefault(key, def string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return def
}

func firstNonEmpty(values ...string) string {
    for _, v := range values {
        if strings.TrimSpace(v) != "" {
            return v
        }
    }
    return ""
}

func Load() (*Config, error) {
    loadDotEnvOnce()
    cfg := &Config{
        Port:       envOrDefault("PORT", "8080"),
        Region:     firstNonEmpty(os.Getenv("AWS_REGION"), os.Getenv("aws_region")),
        Bucket:     firstNonEmpty(os.Getenv("S3_BUCKET"), os.Getenv("s3_bucket")),
        KMSKeyID:   firstNonEmpty(os.Getenv("KMS_KEY_ID"), os.Getenv("kms_key_id")),
        AdminToken: firstNonEmpty(os.Getenv("ADMIN_TOKEN"), os.Getenv("admin_token")),
        DynamoTable: firstNonEmpty(os.Getenv("DDB_TABLE"), os.Getenv("ddb_table")),
    }
    if cfg.Region == "" {
        return nil, fmt.Errorf("AWS_REGION is required (or aws_region)")
    }
    if cfg.Bucket == "" {
        return nil, fmt.Errorf("S3_BUCKET is required (or s3_bucket)")
    }
    if cfg.KMSKeyID == "" {
        return nil, fmt.Errorf("KMS_KEY_ID is required (or kms_key_id)")
    }
    if cfg.AdminToken == "" {
        return nil, fmt.Errorf("ADMIN_TOKEN is required (or admin_token)")
    }
    return cfg, nil
}
