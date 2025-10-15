package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/golang-jwt/jwt/v5"
)

// TokenRecord represents metadata about an issued JWT token
type TokenRecord struct {
	ID        string `json:"id"`
	IssuedAt  int64  `json:"issuedAt"`
	ExpiresAt int64  `json:"expiresAt"`
	Revoked   bool   `json:"revoked"`
}

// TokenClaims represents the JWT claims structure
type TokenClaims struct {
	TokenID string `json:"jti"`
	jwt.RegisteredClaims
}

type TokenStore struct {
	s3        *s3.Client
	bucket    string
	key       string
	jwtSecret []byte
	cache     map[string]TokenRecord
}

// NewTokenStore creates a new JWT-based token store
// jwtSecret should be the ADMIN token from environment
func NewTokenStore(s3c *s3.Client, bucket string, jwtSecret string) *TokenStore {
	return &TokenStore{
		s3:        s3c,
		bucket:    bucket,
		key:       "config/tokens.json",
		jwtSecret: []byte(jwtSecret),
		cache:     map[string]TokenRecord{},
	}
}

// defaultTokenTTL defines how long a JWT token remains valid from creation
const defaultTokenTTL = 24 * time.Hour

func (t *TokenStore) load(ctx context.Context) error {
	out, err := t.s3.GetObject(ctx, &s3.GetObjectInput{Bucket: &t.bucket, Key: &t.key})
	if err != nil {
		// treat as empty if not found
		t.cache = map[string]TokenRecord{}
		return nil
	}
	defer out.Body.Close()
	var list []TokenRecord
	if err := json.NewDecoder(out.Body).Decode(&list); err != nil {
		return err
	}
	t.cache = map[string]TokenRecord{}
	for _, r := range list {
		t.cache[r.ID] = r
	}
	return nil
}

func (t *TokenStore) save(ctx context.Context) error {
	list := make([]TokenRecord, 0, len(t.cache))
	for _, r := range t.cache {
		list = append(list, r)
	}
	b, _ := json.MarshalIndent(list, "", "  ")
	_, err := t.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &t.bucket,
		Key:         &t.key,
		Body:        strings.NewReader(string(b)),
		ContentType: ptr("application/json"),
	})
	return err
}

// CreateToken generates a new JWT token with 24h validity
func (t *TokenStore) CreateToken(ctx context.Context) (id string, token string, expiresAt int64, err error) {
	_ = t.load(ctx)

	now := time.Now()
	expiryTime := now.Add(defaultTokenTTL)
	expiresAt = expiryTime.Unix()

	// Generate unique token ID
	id = fmt.Sprintf("tok_%d", now.UnixNano())

	// Create JWT claims
	claims := TokenClaims{
		TokenID: id,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiryTime),
			Issuer:    "secureFile",
		},
	}

	// Create and sign the token
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err = jwtToken.SignedString(t.jwtSecret)
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to sign JWT: %w", err)
	}

	// Store token metadata
	t.cache[id] = TokenRecord{
		ID:        id,
		IssuedAt:  now.Unix(),
		ExpiresAt: expiresAt,
		Revoked:   false,
	}

	err = t.save(ctx)
	return
}

// Revoke marks a token as revoked
func (t *TokenStore) Revoke(ctx context.Context, id string) error {
	_ = t.load(ctx)
	rec, ok := t.cache[id]
	if !ok {
		return errors.New("not found")
	}
	rec.Revoked = true
	t.cache[id] = rec
	return t.save(ctx)
}

// List returns all token records
func (t *TokenStore) List(ctx context.Context) ([]TokenRecord, error) {
	_ = t.load(ctx)
	list := make([]TokenRecord, 0, len(t.cache))
	for _, r := range t.cache {
		list = append(list, r)
	}
	return list, nil
}

// Validate verifies a JWT token's signature and checks if it's revoked
func (t *TokenStore) Validate(tokenString string) bool {
	// Parse and validate JWT token
	claims := &TokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return t.jwtSecret, nil
	})

	if err != nil {
		return false
	}

	if !token.Valid {
		return false
	}

	// Load token metadata to check revocation status
	if len(t.cache) == 0 {
		if err := t.load(context.Background()); err != nil {
			return false
		}
	}

	// Check if token is revoked
	if rec, ok := t.cache[claims.TokenID]; ok {
		if rec.Revoked {
			return false
		}
	}

	return true
}

func ptr[T any](v T) *T { return &v }

// Middleware for JWT bearer token authentication
func (t *TokenStore) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}

		// Extract token - handle both "Bearer " and "bearer " case-insensitively
		tok := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		tok = strings.TrimSpace(strings.TrimPrefix(tok, "bearer "))

		if tok == "" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}

		// Load latest tokens from S3 before validation
		// This ensures we check against the current revocation list
		if err := t.load(r.Context()); err != nil {
			// If load fails, try to validate with cached tokens
			// but log the error for debugging
			fmt.Fprintf(os.Stderr, "Warning: failed to load tokens from S3: %v\n", err)
		}

		if !t.Validate(tok) {
			http.Error(w, "invalid or expired token", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Admin middleware with static ADMIN_TOKEN
func AdminMiddleware(adminToken string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Admin-Token")
		if token == "" {
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
				token = strings.TrimSpace(auth[len("Bearer "):])
			}
		}
		if token != adminToken {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
