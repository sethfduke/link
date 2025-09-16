package auth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AuthSpec describes authentication requirements for a message type.
type AuthSpec struct {
	Require   bool
	Validator JWTValidator
}

// JWTClaims represents the structure of JWT token claims with standard registered claims
// and additional custom fields for email and scopes.
type JWTClaims struct {
	jwt.RegisteredClaims
	Email  string   `json:"email,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
}

// JWTValidator defines the interface for JWT token validation implementations.
type JWTValidator interface {
	ParseAndValidate(token string) (*JWTClaims, error)
}

// JwtHS256 implements JWTValidator for HS256 signing algorithm using a shared Secret.
type JwtHS256 struct {
	Secret []byte
}

// ParseAndValidate parses and validates a JWT token string using HS256 algorithm.
// It returns the parsed claims if the token is valid, or an error if validation fails.
func (v *JwtHS256) ParseAndValidate(tokenStr string) (*JWTClaims, error) {
	tok, err := jwt.ParseWithClaims(tokenStr, &JWTClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok || t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return v.Secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(*JWTClaims)
	if !ok || !tok.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

// CreateTokenHS256 creates and signs a new JWT token using HS256 algorithm.
// It accepts standard claims (subject, issuer, audience) and custom claims (email, scopes).
func CreateTokenHS256(
	secret []byte,
	subject string,
	expiresIn time.Duration,
	issuer string,
	audience string,
	email string,
	scopes []string,
) (string, error) {
	now := time.Now().UTC()
	rc := jwt.RegisteredClaims{
		Subject:   subject,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
	}
	if expiresIn > 0 {
		rc.ExpiresAt = jwt.NewNumericDate(now.Add(expiresIn))
	}
	if issuer != "" {
		rc.Issuer = issuer
	}
	if audience != "" {
		rc.Audience = jwt.ClaimStrings{audience}
	}

	claims := &JWTClaims{
		RegisteredClaims: rc,
	}
	if email != "" {
		claims.Email = email
	}
	if len(scopes) > 0 {
		claims.Scopes = scopes
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(secret)
}

// BearerFromRequest extracts a bearer token from the HTTP request.
// It checks both the Authorization header and access_token query parameter.
func BearerFromRequest(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[len("Bearer "):]), true
	}
	if q := r.URL.Query().Get("access_token"); q != "" {
		return q, true
	}
	return "", false
}
