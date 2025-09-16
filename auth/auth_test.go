package auth

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJwtHS256_ParseAndValidate(t *testing.T) {
	secret := []byte("test-secret")
	validator := &JwtHS256{Secret: secret}

	t.Run("valid token", func(t *testing.T) {
		// Create a valid token
		token, err := CreateTokenHS256(
			secret,
			"user-123",
			time.Hour,
			"test-issuer",
			"test-audience",
			"user@example.com",
			[]string{"read", "write"},
		)
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		// Parse and validate
		claims, err := validator.ParseAndValidate(token)
		if err != nil {
			t.Fatalf("failed to validate token: %v", err)
		}

		// Verify claims
		if claims.Subject != "user-123" {
			t.Errorf("expected subject 'user-123', got %q", claims.Subject)
		}
		if claims.Email != "user@example.com" {
			t.Errorf("expected email 'user@example.com', got %q", claims.Email)
		}
		if len(claims.Scopes) != 2 || claims.Scopes[0] != "read" || claims.Scopes[1] != "write" {
			t.Errorf("expected scopes [read, write], got %v", claims.Scopes)
		}
		if claims.Issuer != "test-issuer" {
			t.Errorf("expected issuer 'test-issuer', got %q", claims.Issuer)
		}
	})

	t.Run("invalid token - wrong secret", func(t *testing.T) {
		wrongSecret := []byte("wrong-secret")
		token, err := CreateTokenHS256(
			wrongSecret,
			"user-123",
			time.Hour,
			"test-issuer",
			"test-audience",
			"user@example.com",
			nil,
		)
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		_, err = validator.ParseAndValidate(token)
		if err == nil {
			t.Error("expected validation to fail with wrong secret")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		// Create a token that expires very soon, then wait for it to expire
		token, err := CreateTokenHS256(
			secret,
			"user-123",
			time.Millisecond, // Expires in 1ms
			"test-issuer",
			"test-audience",
			"user@example.com",
			nil,
		)
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		// Wait for the token to expire
		time.Sleep(10 * time.Millisecond)

		_, err = validator.ParseAndValidate(token)
		if err == nil {
			t.Error("expected validation to fail for expired token")
		}
	})

	t.Run("malformed token", func(t *testing.T) {
		malformedToken := "not.a.jwt.token"
		_, err := validator.ParseAndValidate(malformedToken)
		if err == nil {
			t.Error("expected validation to fail for malformed token")
		}
	})

	t.Run("wrong signing method", func(t *testing.T) {
		// Test with a token that uses RS256 instead of HS256
		tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyJ9.invalid"
		
		_, err := validator.ParseAndValidate(tokenString)
		if err == nil {
			t.Error("expected validation to fail for wrong signing method")
		}
	})

	t.Run("empty token", func(t *testing.T) {
		_, err := validator.ParseAndValidate("")
		if err == nil {
			t.Error("expected validation to fail for empty token")
		}
	})
}

func TestCreateTokenHS256(t *testing.T) {
	secret := []byte("test-secret")

	t.Run("basic token creation", func(t *testing.T) {
		token, err := CreateTokenHS256(
			secret,
			"user-123",
			time.Hour,
			"test-issuer",
			"test-audience",
			"user@example.com",
			[]string{"read"},
		)
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		if token == "" {
			t.Error("expected non-empty token")
		}

		// Verify token structure (should have 3 parts separated by dots)
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Errorf("expected 3 token parts, got %d", len(parts))
		}
	})

	t.Run("token without expiration", func(t *testing.T) {
		token, err := CreateTokenHS256(
			secret,
			"user-123",
			0, // No expiration
			"test-issuer",
			"test-audience",
			"user@example.com",
			nil,
		)
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		// Parse to verify no expiration is set
		validator := &JwtHS256{Secret: secret}
		claims, err := validator.ParseAndValidate(token)
		if err != nil {
			t.Fatalf("failed to validate token: %v", err)
		}

		if claims.ExpiresAt != nil {
			t.Error("expected no expiration, but ExpiresAt is set")
		}
	})

	t.Run("token with minimal claims", func(t *testing.T) {
		token, err := CreateTokenHS256(
			secret,
			"user-123",
			time.Hour,
			"", // Empty issuer
			"", // Empty audience
			"", // Empty email
			nil, // No scopes
		)
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		validator := &JwtHS256{Secret: secret}
		claims, err := validator.ParseAndValidate(token)
		if err != nil {
			t.Fatalf("failed to validate token: %v", err)
		}

		if claims.Subject != "user-123" {
			t.Errorf("expected subject 'user-123', got %q", claims.Subject)
		}
		if claims.Email != "" {
			t.Errorf("expected empty email, got %q", claims.Email)
		}
		if len(claims.Scopes) != 0 {
			t.Errorf("expected no scopes, got %v", claims.Scopes)
		}
	})

	t.Run("empty secret", func(t *testing.T) {
		_, err := CreateTokenHS256(
			[]byte{}, // Empty secret
			"user-123",
			time.Hour,
			"test-issuer",
			"test-audience",
			"user@example.com",
			nil,
		)
		// Should not error with empty secret, but token won't be secure
		if err != nil {
			t.Fatalf("unexpected error with empty secret: %v", err)
		}
	})
}

func TestBearerFromRequest(t *testing.T) {
	t.Run("authorization header with bearer token", func(t *testing.T) {
		req := &http.Request{
			Header: make(http.Header),
		}
		req.Header.Set("Authorization", "Bearer token123")

		token, ok := BearerFromRequest(req)
		if !ok {
			t.Error("expected to find bearer token")
		}
		if token != "token123" {
			t.Errorf("expected token 'token123', got %q", token)
		}
	})

	t.Run("authorization header case insensitive", func(t *testing.T) {
		req := &http.Request{
			Header: make(http.Header),
		}
		req.Header.Set("Authorization", "bearer token123")

		token, ok := BearerFromRequest(req)
		if !ok {
			t.Error("expected to find bearer token")
		}
		if token != "token123" {
			t.Errorf("expected token 'token123', got %q", token)
		}
	})

	t.Run("authorization header with extra spaces", func(t *testing.T) {
		req := &http.Request{
			Header: make(http.Header),
		}
		req.Header.Set("Authorization", "Bearer   token123   ")

		token, ok := BearerFromRequest(req)
		if !ok {
			t.Error("expected to find bearer token")
		}
		if token != "token123" {
			t.Errorf("expected token 'token123', got %q", token)
		}
	})

	t.Run("query parameter access_token", func(t *testing.T) {
		req := &http.Request{
			URL: &url.URL{
				RawQuery: "access_token=querytoken123",
			},
		}

		token, ok := BearerFromRequest(req)
		if !ok {
			t.Error("expected to find bearer token")
		}
		if token != "querytoken123" {
			t.Errorf("expected token 'querytoken123', got %q", token)
		}
	})

	t.Run("authorization header takes precedence over query param", func(t *testing.T) {
		req := &http.Request{
			Header: make(http.Header),
			URL: &url.URL{
				RawQuery: "access_token=querytoken123",
			},
		}
		req.Header.Set("Authorization", "Bearer headertoken123")

		token, ok := BearerFromRequest(req)
		if !ok {
			t.Error("expected to find bearer token")
		}
		if token != "headertoken123" {
			t.Errorf("expected header token 'headertoken123', got %q", token)
		}
	})

	t.Run("no token in request", func(t *testing.T) {
		req := &http.Request{
			Header: make(http.Header),
			URL:    &url.URL{},
		}

		_, ok := BearerFromRequest(req)
		if ok {
			t.Error("expected no token to be found")
		}
	})

	t.Run("invalid authorization header format", func(t *testing.T) {
		req := &http.Request{
			Header: make(http.Header),
			URL:    &url.URL{},
		}
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz") // Basic auth, not Bearer

		_, ok := BearerFromRequest(req)
		if ok {
			t.Error("expected no bearer token to be found")
		}
	})

	t.Run("authorization header without token", func(t *testing.T) {
		req := &http.Request{
			Header: make(http.Header),
			URL:    &url.URL{},
		}
		req.Header.Set("Authorization", "Bearer")

		token, ok := BearerFromRequest(req)
		if ok {
			t.Error("expected no bearer token to be found for empty Bearer header")
		}
		if token != "" {
			t.Errorf("expected empty token, got %q", token)
		}
	})

	t.Run("empty query parameter", func(t *testing.T) {
		req := &http.Request{
			URL: &url.URL{
				RawQuery: "access_token=",
			},
		}

		_, ok := BearerFromRequest(req)
		if ok {
			t.Error("expected no token to be found for empty query param")
		}
	})
}

func TestJWTClaims(t *testing.T) {
	t.Run("claims structure", func(t *testing.T) {
		claims := &JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "user-123",
				Issuer:  "test-issuer",
			},
			Email:  "user@example.com",
			Scopes: []string{"read", "write"},
		}

		if claims.Subject != "user-123" {
			t.Errorf("expected subject 'user-123', got %q", claims.Subject)
		}
		if claims.Email != "user@example.com" {
			t.Errorf("expected email 'user@example.com', got %q", claims.Email)
		}
		if len(claims.Scopes) != 2 {
			t.Errorf("expected 2 scopes, got %d", len(claims.Scopes))
		}
	})
}

func TestAuthSpec(t *testing.T) {
	t.Run("auth spec creation", func(t *testing.T) {
		validator := &JwtHS256{Secret: []byte("secret")}
		spec := &AuthSpec{
			Require:   true,
			Validator: validator,
		}

		if !spec.Require {
			t.Error("expected Require to be true")
		}
		if spec.Validator != validator {
			t.Error("expected validator to match")
		}
	})

	t.Run("auth spec without validator", func(t *testing.T) {
		spec := &AuthSpec{
			Require: true,
		}

		if !spec.Require {
			t.Error("expected Require to be true")
		}
		if spec.Validator != nil {
			t.Error("expected validator to be nil")
		}
	})
}