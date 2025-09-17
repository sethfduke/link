package server

import (
	"crypto/tls"
	"github.com/sethfduke/link/auth"
	"log/slog"
	"net/http"
	"time"
)

// Option is a function type used to configure LinkServer instances.
type Option func(*LinkServer)

// WithCheckOrigin sets a function to check the origin of WebSocket upgrade requests.
func WithCheckOrigin(fn func(r *http.Request) bool) Option {
	return func(s *LinkServer) {
		s.Upgrader.CheckOrigin = fn
	}
}

// WithCompression enables or disables WebSocket compression.
func WithCompression(enabled bool) Option {
	return func(s *LinkServer) {
		s.Upgrader.EnableCompression = enabled
	}
}

// Host sets the host address for the server to bind to.
func Host(host string) Option {
	return func(s *LinkServer) {
		s.Host = host
	}
}

// WithPort sets the port number for the server to listen on.
func WithPort(port int) Option {
	return func(s *LinkServer) {
		s.Port = port
	}
}

// WithLogLevel sets the logging level for the server.
func WithLogLevel(logLevel int) Option {
	return func(s *LinkServer) {
		s.LogLevel = logLevel
	}
}

// WithHS256JWT enables JWT authentication using HS256 signing algorithm with the provided secret.
// If require is true, all connections must provide a valid JWT token.
func WithHS256JWT(secret []byte, require bool) Option {
	return func(s *LinkServer) {
		s.jwtValidator = &auth.JwtHS256{Secret: secret}
		s.requireJWT = require
	}
}

// WithJWTValidator enables JWT authentication using a custom JWTValidator implementation.
// If require is true, all connections must provide a valid JWT token.
func WithJWTValidator(v auth.JWTValidator, require bool) Option {
	return func(s *LinkServer) {
		s.jwtValidator = v
		s.requireJWT = require
	}
}

// WithTLS enables TLS. If dev==true, a self-signed cert is generated at runtime.
// If dev==false, certFile/keyFile must point to valid PEM files.
func WithTLS(certFile, keyFile string, dev bool) Option {
	return func(s *LinkServer) {
		s.tlsEnabled = true
		s.tlsDev = dev
		s.tlsCert = certFile
		s.tlsKey = keyFile
	}
}

// WithTLSConfig is to allow injecting a ready tls.Config (e.g., for mTLS/custom ciphers)
func WithTLSConfig(cfg *tls.Config) Option {
	return func(s *LinkServer) {
		s.tlsEnabled = true
		s.tlsDev = false
		s.tlsConfig = cfg
	}
}

// WithLogger sets a custom logger implementation for the server.
func WithLogger(l Logger) Option {
	return func(s *LinkServer) { s.Log = l }
}

// WithSlog sets an slog.Logger instance as the server's logger.
func WithSlog(l *slog.Logger) Option {
	return func(s *LinkServer) { s.Log = &slogLogger{l: l} }
}

// WithDefaultPing enables default ping/pong behavior with standard intervals.
// Uses 30 second ping interval and 5 second timeout to keep connections alive.
func WithDefaultPing() Option {
	return func(s *LinkServer) {
		s.pingInterval = 30 * time.Second
		s.pingTimeout = 5 * time.Second
	}
}

// WithPing enables ping/pong behavior with the specified interval and timeout.
// Custom ping messages are sent automatically to keep connections alive.
func WithPing(interval, timeout time.Duration) Option {
	return func(s *LinkServer) {
		s.pingInterval = interval
		s.pingTimeout = timeout
	}
}


// WithHealthEndpoint enables a health check endpoint at the specified path.
// The endpoint returns a 200 OK response with basic server status information.
func WithHealthEndpoint(path string) Option {
	return func(s *LinkServer) {
		s.healthEndpoint = path
	}
}

// WithMaxConnections sets the maximum number of concurrent WebSocket connections.
// When the limit is reached, new connections will be rejected with a 503 Service Unavailable response.
func WithMaxConnections(max int) Option {
	return func(s *LinkServer) {
		s.maxConnections = max
	}
}

// WithConnectionTimeout sets the timeout for WebSocket connections.
// Connections that don't send messages within this duration may be closed.
func WithConnectionTimeout(timeout time.Duration) Option {
	return func(s *LinkServer) {
		s.connectionTimeout = timeout
	}
}

// WithMessageRateLimit sets the maximum number of messages per minute per client.
// Clients exceeding this rate will have their messages rejected.
func WithMessageRateLimit(messagesPerMinute int) Option {
	return func(s *LinkServer) {
		s.messageRateLimit = messagesPerMinute
		if s.clientRateMap == nil {
			s.clientRateMap = make(map[string]*rateLimiter)
		}
	}
}

// WithReadTimeout sets the read timeout for the HTTP server.
// This is the maximum duration for reading the entire request, including the body.
func WithReadTimeout(timeout time.Duration) Option {
	return func(s *LinkServer) {
		s.readTimeout = timeout
	}
}

// WithWriteTimeout sets the write timeout for the HTTP server.
// This is the maximum duration before timing out writes of the response.
func WithWriteTimeout(timeout time.Duration) Option {
	return func(s *LinkServer) {
		s.writeTimeout = timeout
	}
}

// WithIdleTimeout sets the idle timeout for the HTTP server.
// This is the maximum amount of time to wait for the next request when keep-alives are enabled.
func WithIdleTimeout(timeout time.Duration) Option {
	return func(s *LinkServer) {
		s.idleTimeout = timeout
	}
}
