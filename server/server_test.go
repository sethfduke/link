package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sethfduke/link/auth"
	"github.com/sethfduke/link/messages"

	"github.com/gorilla/websocket"
)

// Test message types
type TestMessage struct {
	Content string `json:"content"`
	Number  int    `json:"number"`
}

type SecureMessage struct {
	Data string `json:"data"`
}

func TestLinkServerCreation(t *testing.T) {
	t.Run("new link server with options", func(t *testing.T) {
		srv := NewLinkServer(
			Host("localhost"),
			WithPort(8080),
			WithCompression(true),
			WithLogLevel(int(slog.LevelDebug)),
		)

		if srv.Host != "localhost" {
			t.Errorf("expected host 'localhost', got %q", srv.Host)
		}
		if srv.Port != 8080 {
			t.Errorf("expected port 8080, got %d", srv.Port)
		}
		if !srv.Upgrader.EnableCompression {
			t.Error("expected compression to be enabled")
		}
		if srv.LogLevel != int(slog.LevelDebug) {
			t.Errorf("expected log level %d, got %d", int(slog.LevelDebug), srv.LogLevel)
		}
	})

	t.Run("new default server", func(t *testing.T) {
		srv := NewDefaultServer()

		if srv.Host != "localhost" {
			t.Errorf("expected default host 'localhost', got %q", srv.Host)
		}
		if srv.Port != 9999 {
			t.Errorf("expected default port 9999, got %d", srv.Port)
		}
		if !srv.Upgrader.EnableCompression {
			t.Error("expected compression to be enabled by default")
		}
		if srv.LogLevel != int(slog.LevelInfo) {
			t.Errorf("expected default log level %d, got %d", int(slog.LevelInfo), srv.LogLevel)
		}
	})
}

func TestServerOptions(t *testing.T) {
	t.Run("with check origin", func(t *testing.T) {
		checkOrigin := func(r *http.Request) bool { return true }
		srv := NewLinkServer(WithCheckOrigin(checkOrigin))

		if srv.Upgrader.CheckOrigin == nil {
			t.Error("expected check origin function to be set")
		}
	})

	t.Run("with compression", func(t *testing.T) {
		srv := NewLinkServer(WithCompression(false))

		if srv.Upgrader.EnableCompression {
			t.Error("expected compression to be disabled")
		}
	})

	t.Run("with HS256 JWT", func(t *testing.T) {
		secret := []byte("test-secret")
		srv := NewLinkServer(WithHS256JWT(secret, true))

		if srv.jwtValidator == nil {
			t.Error("expected JWT validator to be set")
		}
		if !srv.requireJWT {
			t.Error("expected JWT to be required")
		}

		// Test validator
		validator, ok := srv.jwtValidator.(*auth.JwtHS256)
		if !ok {
			t.Errorf("expected *auth.JwtHS256, got %T", srv.jwtValidator)
		}
		if string(validator.Secret) != string(secret) {
			t.Error("expected secret to match")
		}
	})

	t.Run("with custom JWT validator", func(t *testing.T) {
		customValidator := &auth.JwtHS256{Secret: []byte("custom")}
		srv := NewLinkServer(WithJWTValidator(customValidator, false))

		if srv.jwtValidator != customValidator {
			t.Error("expected custom validator to be set")
		}
		if srv.requireJWT {
			t.Error("expected JWT not to be required")
		}
	})

	t.Run("with TLS", func(t *testing.T) {
		srv := NewLinkServer(WithTLS("cert.pem", "key.pem", false))

		if !srv.tlsEnabled {
			t.Error("expected TLS to be enabled")
		}
		if srv.tlsDev {
			t.Error("expected TLS dev mode to be disabled")
		}
		if srv.tlsCert != "cert.pem" {
			t.Errorf("expected cert 'cert.pem', got %q", srv.tlsCert)
		}
		if srv.tlsKey != "key.pem" {
			t.Errorf("expected key 'key.pem', got %q", srv.tlsKey)
		}
	})

	t.Run("with TLS dev mode", func(t *testing.T) {
		srv := NewLinkServer(WithTLS("", "", true))

		if !srv.tlsEnabled {
			t.Error("expected TLS to be enabled")
		}
		if !srv.tlsDev {
			t.Error("expected TLS dev mode to be enabled")
		}
	})

	t.Run("with TLS config", func(t *testing.T) {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		srv := NewLinkServer(WithTLSConfig(tlsConfig))

		if !srv.tlsEnabled {
			t.Error("expected TLS to be enabled")
		}
		if srv.tlsDev {
			t.Error("expected TLS dev mode to be disabled")
		}
		if srv.tlsConfig != tlsConfig {
			t.Error("expected TLS config to match")
		}
	})

	t.Run("with ping options", func(t *testing.T) {
		srv := NewLinkServer(WithDefaultPing())

		if srv.pingInterval != 30*time.Second {
			t.Errorf("expected ping interval 30s, got %v", srv.pingInterval)
		}
		if srv.pingTimeout != 5*time.Second {
			t.Errorf("expected ping timeout 5s, got %v", srv.pingTimeout)
		}
	})

	t.Run("with custom ping", func(t *testing.T) {
		srv := NewLinkServer(WithPing(10*time.Second, 2*time.Second))

		if srv.pingInterval != 10*time.Second {
			t.Errorf("expected ping interval 10s, got %v", srv.pingInterval)
		}
		if srv.pingTimeout != 2*time.Second {
			t.Errorf("expected ping timeout 2s, got %v", srv.pingTimeout)
		}
	})

	t.Run("with ping handlers", func(t *testing.T) {
		pingHandler := func(string) error { return nil }
		pongHandler := func(string) error { return nil }
		srv := NewLinkServer(
			WithPingHandler(pingHandler),
			WithPongHandler(pongHandler),
		)

		if srv.pingHandler == nil {
			t.Error("expected ping handler to be set")
		}
		if srv.pongHandler == nil {
			t.Error("expected pong handler to be set")
		}
	})

	t.Run("with health endpoint", func(t *testing.T) {
		srv := NewLinkServer(WithHealthEndpoint("/health"))

		if srv.healthEndpoint != "/health" {
			t.Errorf("expected health endpoint '/health', got %q", srv.healthEndpoint)
		}
	})

	t.Run("with max connections", func(t *testing.T) {
		srv := NewLinkServer(WithMaxConnections(100))

		if srv.maxConnections != 100 {
			t.Errorf("expected max connections 100, got %d", srv.maxConnections)
		}
	})

	t.Run("with connection timeout", func(t *testing.T) {
		srv := NewLinkServer(WithConnectionTimeout(30 * time.Second))

		if srv.connectionTimeout != 30*time.Second {
			t.Errorf("expected connection timeout 30s, got %v", srv.connectionTimeout)
		}
	})

	t.Run("with message rate limit", func(t *testing.T) {
		srv := NewLinkServer(WithMessageRateLimit(60))

		if srv.messageRateLimit != 60 {
			t.Errorf("expected message rate limit 60, got %d", srv.messageRateLimit)
		}
		if srv.clientRateMap == nil {
			t.Error("expected client rate map to be initialized")
		}
	})
}

func TestMessageRegistration(t *testing.T) {
	t.Run("register messages", func(t *testing.T) {
		srv := NewLinkServer()

		handlerCalled := false
		handler := func(ctx context.Context, msg *TestMessage) error {
			handlerCalled = true
			return nil
		}

		srv.Register(messages.Message("test", handler))

		if len(srv.MessageRegistry) != 1 {
			t.Errorf("expected 1 registered message, got %d", len(srv.MessageRegistry))
		}

		entry, exists := srv.MessageRegistry["test"]
		if !exists {
			t.Error("expected 'test' message to be registered")
		}

		// Test handler
		testMsg := &TestMessage{Content: "hello", Number: 42}
		err := entry.Handler(context.Background(), testMsg)
		if err != nil {
			t.Fatalf("handler failed: %v", err)
		}

		if !handlerCalled {
			t.Error("expected handler to be called")
		}
	})

	t.Run("register message with auth", func(t *testing.T) {
		secret := []byte("test-secret")
		srv := NewLinkServer(WithHS256JWT(secret, false))

		handler := func(ctx context.Context, msg *SecureMessage) error { return nil }
		srv.Register(messages.Message("secure", handler, messages.WithAuth()))

		entry, exists := srv.MessageRegistry["secure"]
		if !exists {
			t.Error("expected 'secure' message to be registered")
		}

		if entry.Auth == nil {
			t.Error("expected auth to be set")
		}
		if !entry.Auth.Require {
			t.Error("expected auth to be required")
		}
		if entry.Auth.Validator != srv.jwtValidator {
			t.Error("expected validator to be server's JWT validator")
		}
	})
}

func TestClientManagement(t *testing.T) {
	t.Run("add and remove clients", func(t *testing.T) {
		srv := NewLinkServer()

		// Mock WebSocket connection
		conn := &websocket.Conn{}
		client := NewClient("test-client", conn, 10)

		srv.addClient("test-client", client)

		if len(srv.clients) != 1 {
			t.Errorf("expected 1 client, got %d", len(srv.clients))
		}

		retrievedClient, exists := srv.clients["test-client"]
		if !exists {
			t.Error("expected client to exist")
		}
		if retrievedClient != client {
			t.Error("expected retrieved client to match")
		}

		srv.removeClient("test-client")

		if len(srv.clients) != 0 {
			t.Errorf("expected 0 clients, got %d", len(srv.clients))
		}
	})
}

func TestRateLimiting(t *testing.T) {
	t.Run("rate limiting functionality", func(t *testing.T) {
		srv := NewLinkServer(WithMessageRateLimit(2)) // 2 messages per minute

		clientID := "test-client"

		// First message should be allowed
		if !srv.checkRateLimit(clientID) {
			t.Error("expected first message to be allowed")
		}

		// Second message should be allowed
		if !srv.checkRateLimit(clientID) {
			t.Error("expected second message to be allowed")
		}

		// Third message should be blocked
		if srv.checkRateLimit(clientID) {
			t.Error("expected third message to be blocked")
		}
	})

	t.Run("rate limit cleanup", func(t *testing.T) {
		srv := NewLinkServer(WithMessageRateLimit(10))

		clientID := "test-client"
		srv.checkRateLimit(clientID) // Create rate limiter

		if len(srv.clientRateMap) != 1 {
			t.Errorf("expected 1 rate limiter, got %d", len(srv.clientRateMap))
		}

		// Simulate cleanup (this would normally be time-based)
		srv.removeClient(clientID)

		if len(srv.clientRateMap) != 0 {
			t.Errorf("expected 0 rate limiters after cleanup, got %d", len(srv.clientRateMap))
		}
	})
}

func TestBroadcast(t *testing.T) {
	t.Run("broadcast function exists", func(t *testing.T) {
		srv := NewLinkServer()

		// Test that broadcast doesn't panic with no clients
		srv.Broadcast("test", "1.0", map[string]string{"hello": "world"})

		// This test mainly verifies the function exists and handles empty client list
		if len(srv.clients) != 0 {
			t.Errorf("expected no clients, got %d", len(srv.clients))
		}
	})
}

func TestContextFunctions(t *testing.T) {
	t.Run("client ID context", func(t *testing.T) {
		ctx := WithClientID(context.Background(), "test-client")

		clientID, ok := ClientIDFrom(ctx)
		if !ok {
			t.Error("expected to find client ID in context")
		}
		if clientID != "test-client" {
			t.Errorf("expected client ID 'test-client', got %q", clientID)
		}
	})

	t.Run("JWT claims context", func(t *testing.T) {
		claims := &auth.JWTClaims{
			Email: "test@example.com",
		}
		ctx := WithClaims(context.Background(), claims)

		retrievedClaims, ok := ClaimsFrom(ctx)
		if !ok {
			t.Error("expected to find claims in context")
		}
		if retrievedClaims.Email != "test@example.com" {
			t.Errorf("expected email 'test@example.com', got %q", retrievedClaims.Email)
		}
	})

	t.Run("token context", func(t *testing.T) {
		ctx := WithToken(context.Background(), "test-token")

		token, ok := TokenFrom(ctx)
		if !ok {
			t.Error("expected to find token in context")
		}
		if token != "test-token" {
			t.Errorf("expected token 'test-token', got %q", token)
		}
	})
}

func TestMessagingContext(t *testing.T) {
	t.Run("messaging context creation", func(t *testing.T) {
		srv := NewLinkServer()
		base := context.Background()
		mctx := newMctx(base, srv, "client-123", "corr-456")

		if mctx.CorrelationID() != "corr-456" {
			t.Errorf("expected correlation ID 'corr-456', got %q", mctx.CorrelationID())
		}

		// Test with correlation
		newMctx := mctx.WithCorrelation("new-corr")
		if newMctx.CorrelationID() != "new-corr" {
			t.Errorf("expected new correlation ID 'new-corr', got %q", newMctx.CorrelationID())
		}
	})

	t.Run("messaging context send options", func(t *testing.T) {
		// Test send options
		opts := &sendOpts{}

		WithFrom("sender")(opts)
		WithVersion("2.0")(opts)
		WithCorrelation("test-corr")(opts)
		WithAckRequested()(opts)

		if opts.from != "sender" {
			t.Errorf("expected from 'sender', got %q", opts.from)
		}
		if opts.version != "2.0" {
			t.Errorf("expected version '2.0', got %q", opts.version)
		}
		if opts.cid != "test-corr" {
			t.Errorf("expected correlation ID 'test-corr', got %q", opts.cid)
		}
		if !opts.ackRequested {
			t.Error("expected ack requested to be true")
		}
	})
}

func TestHealthHandler(t *testing.T) {
	t.Run("health endpoint", func(t *testing.T) {
		srv := NewLinkServer(WithHealthEndpoint("/health"))

		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		srv.healthHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}

		contentType := w.Header().Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("expected content type 'application/json', got %q", contentType)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("failed to unmarshal response: %v", err)
		}

		if response["status"] != "ok" {
			t.Errorf("expected status 'ok', got %v", response["status"])
		}

		clients, ok := response["clients"].(float64)
		if !ok {
			t.Errorf("expected clients to be a number, got %T", response["clients"])
		}
		if clients != 0 {
			t.Errorf("expected 0 clients, got %v", clients)
		}
	})
}

func TestClientCreation(t *testing.T) {
	t.Run("new client", func(t *testing.T) {
		conn := &websocket.Conn{}
		client := NewClient("test-client", conn, 64)

		if client.ID != "test-client" {
			t.Errorf("expected ID 'test-client', got %q", client.ID)
		}
		if client.Conn != conn {
			t.Error("expected connection to match")
		}
		if len(client.sendCh) != 0 {
			t.Errorf("expected empty send channel, got %d items", len(client.sendCh))
		}
	})

	t.Run("new client with ping", func(t *testing.T) {
		conn := &websocket.Conn{}
		pingHandler := func(string) error { return nil }
		pongHandler := func(string) error { return nil }

		client := NewClientWithPing("test-client", conn, 64,
			30*time.Second, 5*time.Second, pingHandler, pongHandler)

		if client.pingInterval != 30*time.Second {
			t.Errorf("expected ping interval 30s, got %v", client.pingInterval)
		}
		if client.pingTimeout != 5*time.Second {
			t.Errorf("expected ping timeout 5s, got %v", client.pingTimeout)
		}
	})
}

func TestUtilityFunctions(t *testing.T) {
	t.Run("is normal disconnect", func(t *testing.T) {
		// Test various error types that should be considered normal disconnects
		normalErrors := []error{
			&websocket.CloseError{Code: websocket.CloseNormalClosure},
			&websocket.CloseError{Code: websocket.CloseGoingAway},
			fmt.Errorf("use of closed network connection"),
			fmt.Errorf("connection reset by peer"),
		}

		for _, err := range normalErrors {
			if !isNormalDisconnect(err) {
				t.Errorf("expected error to be normal disconnect: %v", err)
			}
		}

		// Test error that should not be considered normal
		if isNormalDisconnect(fmt.Errorf("unexpected error")) {
			t.Error("expected error not to be normal disconnect")
		}

		// Test nil error
		if isNormalDisconnect(nil) {
			t.Error("expected nil error not to be normal disconnect")
		}
	})

	t.Run("must JSON", func(t *testing.T) {
		data := map[string]string{"hello": "world"}
		result := mustJSON(data)

		var unmarshaled map[string]string
		if err := json.Unmarshal(result, &unmarshaled); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}

		if unmarshaled["hello"] != "world" {
			t.Errorf("expected 'world', got %q", unmarshaled["hello"])
		}
	})
}

func TestConcurrentAccess(t *testing.T) {
	t.Run("concurrent client management", func(t *testing.T) {
		srv := NewLinkServer()
		var wg sync.WaitGroup

		// Simulate concurrent client additions and removals
		for i := 0; i < 50; i++ {
			wg.Add(2)

			go func(id int) {
				defer wg.Done()
				clientID := fmt.Sprintf("client-%d", id)
				// Just test the removal without adding (to avoid type issues)
				srv.removeClient(clientID)
			}(i)

			go func(id int) {
				defer wg.Done()
				clientID := fmt.Sprintf("client-%d", id+50)
				srv.removeClient(clientID)
			}(i)
		}

		wg.Wait()

		// Test should complete without race conditions
		// This tests that concurrent removeClient calls don't cause issues
		if len(srv.clients) != 0 {
			t.Errorf("expected no clients after concurrent operations, got %d", len(srv.clients))
		}
	})
}

// Additional tests to improve coverage

func TestClientMethods(t *testing.T) {
	t.Run("client send buffer full", func(t *testing.T) {
		// Create a client with buffer size 0 to test buffer full condition
		conn := &websocket.Conn{} // Mock connection for testing
		client := NewClient("test-client", conn, 0)

		// This should return buffer full error immediately
		err := client.Send("test", "1.0", map[string]string{"hello": "world"})
		if err != ErrSendBufferFull {
			t.Errorf("expected ErrSendBufferFull, got %v", err)
		}
	})

	t.Run("client send envelope buffer full", func(t *testing.T) {
		conn := &websocket.Conn{} // Mock connection for testing
		client := NewClient("test-client", conn, 0)

		envelope := &messages.Envelope{
			Type: "test",
			Data: mustJSON(map[string]string{"hello": "world"}),
		}

		err := client.SendEnvelope(envelope)
		if err != ErrSendBufferFull {
			t.Errorf("expected ErrSendBufferFull, got %v", err)
		}
	})
}

func TestLoggingMethods(t *testing.T) {
	t.Run("slog logger methods", func(t *testing.T) {
		handler := slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{})
		logger := slog.New(handler)
		slogLogger := &slogLogger{l: logger}

		// Test all logging methods
		slogLogger.Debug("debug message", "key", "value")
		slogLogger.Info("info message", "key", "value")
		slogLogger.Warn("warn message", "key", "value")
		slogLogger.Error("error message", "key", "value")

		// Test With method
		newLogger := slogLogger.With("context", "test")
		if newLogger == slogLogger {
			t.Error("With should return a new logger instance")
		}

		// Use the new logger
		newLogger.Info("test message with context")
	})
}

func TestDevTLS(t *testing.T) {
	t.Run("generate dev cert", func(t *testing.T) {
		cert, err := GenerateDevCert(24 * time.Hour)
		if err != nil {
			t.Fatalf("failed to generate dev cert: %v", err)
		}

		if len(cert.Certificate) == 0 {
			t.Error("expected certificate to be generated")
		}

		if cert.PrivateKey == nil {
			t.Error("expected private key to be generated")
		}

		// Test that certificate is valid (remove unused variable warning)
		_ = cert
	})
}

func TestServerMethods(t *testing.T) {
	t.Run("setup logging", func(t *testing.T) {
		srv := NewLinkServer()
		srv.setupLogging(int(slog.LevelDebug))
		// Test that logging setup doesn't panic
	})

	t.Run("ensure registry", func(t *testing.T) {
		srv := NewLinkServer()
		srv.MessageRegistry = nil
		srv.ensureRegistry()

		if srv.MessageRegistry == nil {
			t.Error("expected message registry to be initialized")
		}
	})

	t.Run("cleanup rate limiters", func(t *testing.T) {
		srv := NewLinkServer(WithMessageRateLimit(10))

		// Add some old rate limiters
		srv.rateMu.Lock()
		srv.clientRateMap["old-client"] = &rateLimiter{
			count:     1,
			resetTime: time.Now().Add(-10 * time.Minute),
		}
		srv.clientRateMap["new-client"] = &rateLimiter{
			count:     1,
			resetTime: time.Now().Add(time.Minute),
		}
		srv.rateMu.Unlock()

		srv.cleanupRateLimiters()

		srv.rateMu.RLock()
		if _, exists := srv.clientRateMap["old-client"]; exists {
			t.Error("expected old client rate limiter to be cleaned up")
		}
		if _, exists := srv.clientRateMap["new-client"]; !exists {
			t.Error("expected new client rate limiter to remain")
		}
		srv.rateMu.RUnlock()
	})

	t.Run("add client with nil map", func(t *testing.T) {
		srv := NewLinkServer()
		srv.clients = nil

		conn := &websocket.Conn{} // Mock connection
		client := NewClient("test-client", conn, 10)
		srv.addClient("test-client", client)

		if srv.clients == nil {
			t.Error("expected clients map to be initialized")
		}
		if _, exists := srv.clients["test-client"]; !exists {
			t.Error("expected client to be added")
		}
	})
}

func TestMessagingContextMethods(t *testing.T) {
	t.Run("context interface methods", func(t *testing.T) {
		srv := NewLinkServer()
		baseCtx := context.Background()
		mctx := newMctx(baseCtx, srv, "client1", "corr123")

		// Test context interface methods
		deadline, ok := mctx.Deadline()
		if ok {
			t.Error("expected no deadline")
		}
		_ = deadline

		done := mctx.Done()
		if done != nil {
			select {
			case <-done:
				t.Error("expected done channel not to be closed")
			default:
				// Expected
			}
		}

		err := mctx.Err()
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		value := mctx.Value("test-key")
		if value != nil {
			t.Errorf("expected nil value, got %v", value)
		}

		corrID := mctx.CorrelationID()
		if corrID != "corr123" {
			t.Errorf("expected correlation ID 'corr123', got %q", corrID)
		}

		newMctx := mctx.WithCorrelation("new-corr")
		if newMctx.CorrelationID() != "new-corr" {
			t.Errorf("expected new correlation ID 'new-corr', got %q", newMctx.CorrelationID())
		}
	})

	t.Run("send to non-existent client", func(t *testing.T) {
		srv := NewLinkServer()
		baseCtx := context.Background()
		mctx := newMctx(baseCtx, srv, "sender", "corr123")

		// Test SendTo to non-existent client
		err := mctx.SendTo("non-existent", "test-msg", map[string]string{"data": "test"})
		if err == nil {
			t.Error("expected error for SendTo to non-existent client")
		}

		// Test with marshaling error
		invalidData := make(chan int) // channels can't be marshaled to JSON
		err = mctx.SendTo("non-existent", "test-msg", invalidData)
		if err == nil {
			t.Error("expected marshaling error, got nil")
		}
	})
}

func TestOptionsNotCovered(t *testing.T) {
	t.Run("with logger", func(t *testing.T) {
		customLogger := &slogLogger{l: slog.Default()}
		srv := NewLinkServer(WithLogger(customLogger))

		if srv.Log != customLogger {
			t.Error("expected custom logger to be set")
		}
	})

	t.Run("with slog", func(t *testing.T) {
		customSlog := slog.Default()
		srv := NewLinkServer(WithSlog(customSlog))

		slogLogger, ok := srv.Log.(*slogLogger)
		if !ok {
			t.Error("expected slog logger to be set")
		}
		if slogLogger.l != customSlog {
			t.Error("expected slog logger to wrap custom slog instance")
		}
	})
}

func TestBroadcastMethod(t *testing.T) {
	t.Run("broadcast with marshal error", func(t *testing.T) {
		srv := NewLinkServer()

		// Try to broadcast unmarshalable data (test marshal error path)
		invalidData := make(chan int)
		srv.Broadcast("test", "1.0", invalidData)
		// This tests the marshal error path in Broadcast method
	})
}
