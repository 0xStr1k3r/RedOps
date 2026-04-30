// Package auth provides password hashing (Argon2id), JWT issuance/validation,
// and HTTP middleware for RBAC. Phase 1 roles: admin > operator > viewer.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/argon2"
)

const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

var validRoles = map[string]int{
	RoleViewer:   1,
	RoleOperator: 2,
	RoleAdmin:    3,
}

// Argon2id parameters (OWASP-ish, balanced for lab + CI speed).
const (
	argonTime    = 2
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPassword returns a portable string: "argon2id$v=19$m=...,t=...,p=...$salt$b64hash".
func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("password must be at least 8 characters")
	}
	if len(password) > 256 {
		return "", errors.New("password too long")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

// VerifyPassword checks password against an encoded hash. Constant-time compare.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" {
		return false
	}
	var mem uint32
	var tim uint32
	var thr uint8
	// parts[1] = v=19, parts[2] = m=..,t=..,p=..
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &mem, &tim, &thr); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, tim, mem, thr, uint32(len(want))) // #nosec G115 -- len(want) is a decoded hash length (32), always fits uint32.
	return subtle.ConstantTimeCompare(got, want) == 1
}

// Claims carried in every RedOps JWT.
type Claims struct {
	UserID   string `json:"uid"`
	Username string `json:"sub"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Issue creates a signed JWT valid for ttl.
func Issue(secret, userID, username, role string, ttl time.Duration) (string, error) {
	if _, ok := validRoles[role]; !ok {
		return "", fmt.Errorf("unknown role %q", role)
	}
	now := time.Now()
	c := Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(secret))
}

// Parse validates a token and returns claims. Rejects wrong methods and expired tokens.
func Parse(secret, tokenStr string) (*Claims, error) {
	tok, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	c, ok := tok.Claims.(*Claims)
	if !ok || !tok.Valid {
		return nil, errors.New("invalid token")
	}
	if _, ok := validRoles[c.Role]; !ok {
		return nil, errors.New("token carries unknown role")
	}
	return c, nil
}

// CanAct reports whether role satisfies at least the required role.
func CanAct(role, required string) bool {
	return validRoles[role] >= validRoles[required]
}

// NormalizeRole lowercases and validates; defaults empty to viewer for safe reads.
func NormalizeRole(r string) (string, error) {
	r = strings.ToLower(strings.TrimSpace(r))
	if r == "" {
		return RoleViewer, nil
	}
	if _, ok := validRoles[r]; !ok {
		return "", fmt.Errorf("unknown role %q", r)
	}
	return r, nil
}
