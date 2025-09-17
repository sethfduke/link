package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sethfduke/link/auth"
	"github.com/sethfduke/link/messages"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// ctxKey is a custom type for context keys to avoid collisions.
type ctxKey string

const (
	// ctxKeyClientID is the context key used to store client IDs.
	ctxKeyClientID ctxKey = "clientID"
	// ctxKeyClaims is the context key used to store JWT claims.
	ctxKeyClaims ctxKey = "claims"
	// ctxKeyToken is the context key for storing the JWT token
	ctxKeyToken ctxKey = "jwtToken"
)

// rateLimiter tracks message rate for a client
type rateLimiter struct {
	count     int
	resetTime time.Time
	mu        sync.Mutex
}

// LinkServer represents a WebSocket server that handles message routing and client management.
// It provides type-safe message handling with support for client-to-client routing.
type LinkServer struct {
	Upgrader websocket.Upgrader
	Log      Logger

	MessageRegistry map[string]messages.RegEntry
	regMu           sync.RWMutex

	clients   map[string]*Client
	clientsMu sync.RWMutex

	Port     int
	Host     string
	LogLevel int

	jwtValidator auth.JWTValidator
	requireJWT   bool

	tlsEnabled bool
	tlsDev     bool
	tlsCert    string
	tlsKey     string
	tlsConfig  *tls.Config

	pingInterval time.Duration
	pingTimeout  time.Duration

	healthEndpoint string

	maxConnections    int
	connectionTimeout time.Duration
	messageRateLimit  int // messages per minute per client

	clientRateMap map[string]*rateLimiter
	rateMu        sync.RWMutex

	readTimeout  time.Duration
	writeTimeout time.Duration
	idleTimeout  time.Duration
}

// NewLinkServer creates a new LinkServer instance with the provided options.
// It initializes default logging, WebSocket upgrader, and applies all given options.
func NewLinkServer(opts ...Option) *LinkServer {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.Level(0),
	})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	s := &LinkServer{
		Upgrader:        websocket.Upgrader{EnableCompression: true},
		MessageRegistry: make(map[string]messages.RegEntry),
		clients:         make(map[string]*Client),
		clientRateMap:   make(map[string]*rateLimiter),
		Log:             &slogLogger{l: logger},
		readTimeout:     15 * time.Second,
		writeTimeout:    15 * time.Second,
		idleTimeout:     60 * time.Second,
	}
	for _, opt := range opts {
		opt(s)
	}

	if s.messageRateLimit > 0 {
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				s.cleanupRateLimiters()
			}
		}()
	}

	return s
}

// NewDefaultServer creates a LinkServer with a sensible default configuration.
// It sets localhost:9999, enables compression, and uses Info log level.
func NewDefaultServer() *LinkServer {
	return NewLinkServer(
		Host("localhost"),
		WithPort(9999),
		WithCompression(true),
		WithLogLevel(int(slog.LevelInfo)),
	)
}

// Serve starts the LinkServer HTTP server and begins listening for WebSocket connections.
// It configures logging, registers the WebSocket handler at /ws endpoint, and starts the server.
func (s *LinkServer) Serve() error {
	s.setupLogging(s.LogLevel)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.wsHandler)

	if s.healthEndpoint != "" {
		mux.HandleFunc(s.healthEndpoint, s.healthHandler)
	}

	addr := s.Host + ":" + strconv.Itoa(s.Port)
	httpSrv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  s.readTimeout,
		WriteTimeout: s.writeTimeout,
		IdleTimeout:  s.idleTimeout,
	}

	if !s.tlsEnabled {
		s.Log.Info("http listen", "addr", addr)
		return httpSrv.ListenAndServe()
	}

	if s.tlsDev {
		cert, err := GenerateDevCert(365 * 24 * time.Hour)
		if err != nil {
			s.Log.Error("dev tls cert generation failed", "err", err)
			return err
		}
		tcfg := &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		}
		s.tlsConfig = tcfg

		ln, err := net.Listen("tcp", addr)
		if err != nil {
			s.Log.Error("listen failed", "addr", addr, "err", err)
			return err
		}
		s.Log.Info("https (dev) listen", "addr", addr)
		tlsLn := tls.NewListener(ln, tcfg)
		return httpSrv.Serve(tlsLn)
	}

	if s.tlsConfig != nil {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			s.Log.Error("listen failed", "addr", addr, "err", err)
			return err
		}
		s.Log.Info("https (cfg) listen", "addr", addr)
		tlsLn := tls.NewListener(ln, s.tlsConfig)
		return httpSrv.Serve(tlsLn)
	}

	s.Log.Info("https listen", "addr", addr, "cert", s.tlsCert, "key", s.tlsKey)
	return httpSrv.ListenAndServeTLS(s.tlsCert, s.tlsKey)
}

// setupLogging configures the server's logging system with the specified log level.
func (s *LinkServer) setupLogging(level int) {
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.Level(level)})
	l := slog.New(h)
	slog.SetDefault(l)
	if _, ok := s.Log.(*slogLogger); ok {
		s.Log = &slogLogger{l: l}
	}
}

// ensureRegistry initializes the MessageRegistry map if it hasn't been created yet.
func (s *LinkServer) ensureRegistry() {
	if s.MessageRegistry == nil {
		s.Log.Debug("initializing message registry")
		s.MessageRegistry = make(map[string]messages.RegEntry)
	}
}

// healthHandler handles health check requests
func (s *LinkServer) healthHandler(w http.ResponseWriter, r *http.Request) {
	s.clientsMu.RLock()
	clientCount := len(s.clients)
	s.clientsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"clients":   clientCount,
		"uptime":    time.Since(time.Now()).String(),
	}

	if maxConn := s.maxConnections; maxConn > 0 {
		response["max_connections"] = maxConn
	}

	_ = json.NewEncoder(w).Encode(response)
}

// checkRateLimit checks if a client has exceeded their message rate limit
func (s *LinkServer) checkRateLimit(clientID string) bool {
	if s.messageRateLimit <= 0 {
		return true // No rate limiting
	}

	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	now := time.Now()
	limiter, exists := s.clientRateMap[clientID]
	if !exists {
		limiter = &rateLimiter{
			count:     1,
			resetTime: now.Add(time.Minute),
		}
		s.clientRateMap[clientID] = limiter
		return true
	}

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	if now.After(limiter.resetTime) {
		limiter.count = 1
		limiter.resetTime = now.Add(time.Minute)
		return true
	}

	if limiter.count >= s.messageRateLimit {
		return false
	}

	limiter.count++
	return true
}

// cleanupRateLimiters removes old rate limiters to prevent memory leaks
func (s *LinkServer) cleanupRateLimiters() {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	now := time.Now()
	for clientID, limiter := range s.clientRateMap {
		limiter.mu.Lock()
		if now.After(limiter.resetTime.Add(5 * time.Minute)) {
			delete(s.clientRateMap, clientID)
		}
		limiter.mu.Unlock()
	}
}

// wsHandler handles incoming WebSocket connection requests.
// It upgrades the HTTP connection to WebSocket, manages the client lifecycle, and processes messages.
func (s *LinkServer) wsHandler(w http.ResponseWriter, r *http.Request) {
	s.Log.Debug("received request", "method", r.Method, "path", r.URL.Path)

	if s.maxConnections > 0 {
		s.clientsMu.RLock()
		currentConnections := len(s.clients)
		s.clientsMu.RUnlock()

		if currentConnections >= s.maxConnections {
			s.Log.Warn("connection limit reached", "current", currentConnections, "max", s.maxConnections)
			http.Error(w, "Service Unavailable: Connection limit reached", http.StatusServiceUnavailable)
			return
		}
	}

	var rawToken string
	if tok, ok := auth.BearerFromRequest(r); ok {
		rawToken = tok
	}

	c, err := s.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.Log.Error("upgrade failed", "error", err)
		return
	}
	defer func() {
		_ = c.Close()
	}()

	id := uuid.NewString()
	s.Log.Debug("registering client", "id", id)

	pingInterval := s.pingInterval
	pingTimeout := s.pingTimeout

	// Set up pong handler with configurable timeout
	if pingInterval > 0 {
		pongWait := pingTimeout
		if pongWait <= 0 {
			pongWait = 90 * time.Second // sensible default as you suggested
		}

		// Install pong handler so control PONGs keep the connection alive
		_ = c.SetReadDeadline(time.Now().Add(pongWait))
		c.SetPongHandler(func(appData string) error {
			return c.SetReadDeadline(time.Now().Add(pongWait))
		})
	}

	client := NewClientWithPing(id, c, 128, pingInterval, pingTimeout)
	s.addClient(id, client)

	go client.writePump()

	if pingInterval > 0 {
		pongWait := pingTimeout
		if pongWait <= 0 {
			pongWait = 5 * time.Second
		}

		// Calculate proper deadline: time until next ping + pong timeout
		pongReadDeadline := pingInterval + pongWait

		c.SetPongHandler(func(string) error {
			// Reset deadline to allow time for next ping cycle plus pong timeout
			_ = c.SetReadDeadline(time.Now().Add(pongReadDeadline))
			return nil
		})

		// Set initial read deadline
		_ = c.SetReadDeadline(time.Now().Add(pongReadDeadline))
	}

	joinedMsg := messages.Joined{ID: id}
	if err := client.Send("joined", "", joinedMsg); err != nil {
		s.Log.Error("failed to send joined message", "id", id, "err", err)
	}

	defer func() {
		s.Log.Debug("unregistering client", "id", id)
		client.Close()
		s.removeClient(id)
	}()

	base := r.Context()
	ctx := WithClientID(base, id)
	if rawToken != "" {
		ctx = WithToken(ctx, rawToken)
	}

	for {
		mt, data, err := c.ReadMessage()
		if err != nil {
			if !isNormalDisconnect(err) {
				s.Log.Error("ws read error", "id", id, "err", err)
			}
			return
		}
		if mt != websocket.TextMessage {
			s.Log.Debug("ws message not text message", "id", id)
			continue
		}

		var env messages.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			s.Log.Error("bad envelope", "id", id, "err", err)
			_ = s.sendError(c, "invalid envelope")
			return
		}

		env.From = id
		if env.ID == "" {
			env.ID = uuid.New().String()
		}

		if !s.checkRateLimit(id) {
			s.Log.Warn("rate limit exceeded", "client", id, "limit", s.messageRateLimit)
			_ = s.sendError(c, "Rate limit exceeded")
			continue
		}

		if env.To != "" {
			if err := s.routeToClient(&env, id); err != nil {
				s.Log.Error("route error", "from", id, "to", env.To, "err", err)
				_ = s.sendError(c, err.Error())
			}
			continue
		}

		msgCtx := newMctx(ctx, s, id, env.CorrelationID)

		reb, err := json.Marshal(env)
		if err != nil {
			s.Log.Error("re-marshal envelope failed", "id", id, "err", err)
			_ = s.sendError(c, "internal marshal error")
			return
		}

		derr := s.dispatch(msgCtx, reb)
		if derr != nil {
			s.Log.Error("dispatch error", "id", id, "err", derr, "raw", string(reb))
			if env.AckRequested {
				_ = s.sendEnvelope(id, &messages.Envelope{
					Type:          messages.ErrorType,
					To:            id,
					From:          "server",
					ID:            uuid.NewString(),
					CorrelationID: env.ID,
					Data:          mustJSON(messages.Error{Msg: derr.Error()}),
				})
			} else {
				_ = s.sendError(c, derr.Error())
			}
			continue
		}

		if env.AckRequested {
			_ = s.sendEnvelope(id, &messages.Envelope{
				Type:          messages.AckType,
				To:            id,
				From:          "server",
				ID:            uuid.NewString(),
				CorrelationID: env.ID,
				Data:          mustJSON(messages.Ack{}),
			})
		}
	}
}

// sendEnvelope sends the message envelope to the destination
func (s *LinkServer) sendEnvelope(to string, env *messages.Envelope) error {
	cl, ok := s.clients[to]
	if !ok {
		return errors.New("client not found")
	}
	return cl.SendEnvelope(env)
}

// routeToClient routes a message envelope from one client to another client.
// It looks up the destination client by ID and forwards the envelope directly.
func (s *LinkServer) routeToClient(env *messages.Envelope, senderID string) error {
	s.clientsMu.RLock()
	dst := s.clients[env.To]
	s.clientsMu.RUnlock()

	if dst == nil {
		return fmt.Errorf("unknown recipient: %s - from %s", env.To, senderID)
	}

	return dst.SendEnvelope(env)
}

// dispatch processes incoming WebSocket messages by un-marshaling the envelope,
// finding the registered handler for the message type, and invoking the handler.
func (s *LinkServer) dispatch(ctx context.Context, raw []byte) error {
	var env messages.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("bad envelope: %w", err)
	}

	clientId, ok := ctx.Value(ctxKeyClientID).(string)
	if !ok {
		clientId = "unknown"
	}
	s.Log.Debug("dispatching message", "type", env.Type, "version", env.Version, "clientId", clientId)

	s.regMu.RLock()
	entry, ok := s.MessageRegistry[env.Type]
	s.regMu.RUnlock()
	if !ok {
		return fmt.Errorf("unknown message type %q", env.Type)
	}

	if entry.Auth != nil && entry.Auth.Require {
		if entry.Auth.Validator == nil {
			return fmt.Errorf("auth required but no validator configured for %q", env.Type)
		}
		tok, ok := TokenFrom(ctx)
		if !ok || tok == "" {
			return fmt.Errorf("unauthorized: token required")
		}
		claims, err := entry.Auth.Validator.ParseAndValidate(tok)
		if err != nil {
			return fmt.Errorf("unauthorized: %w", err)
		}
		ctx = WithClaims(ctx, claims)
	}

	msg := entry.New()
	if err := json.Unmarshal(env.Data, msg); err != nil {
		return fmt.Errorf("decode %s: %w", env.Type, err)
	}
	return entry.Handler(ctx, msg)
}

// addClient registers a new client connection with the server.
func (s *LinkServer) addClient(id string, client *Client) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	if s.clients == nil {
		s.clients = make(map[string]*Client)
	}
	s.clients[id] = client
	s.Log.Info("client connected", "id", id, "clients", len(s.clients))
}

// removeClient unregisters a client connection from the server.
func (s *LinkServer) removeClient(id string) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	delete(s.clients, id)

	s.rateMu.Lock()
	delete(s.clientRateMap, id)
	s.rateMu.Unlock()

	s.Log.Info("client disconnected", "id", id, "clients", len(s.clients))
}

// Broadcast sends a message to all connected clients.
func (s *LinkServer) Broadcast(msgType, version string, payload any) {
	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()
	for _, cl := range s.clients {
		_ = cl.Send(msgType, version, payload)
	}
}

// Register adds one or more message specifications to the server's message registry.
func (s *LinkServer) Register(specs ...messages.MessageSpec) {
	s.regMu.Lock()
	defer s.regMu.Unlock()
	if s.MessageRegistry == nil {
		s.MessageRegistry = make(map[string]messages.RegEntry)
	}
	for _, sp := range specs {
		entry := sp.Reg
		if entry.Auth != nil && entry.Auth.Require && entry.Auth.Validator == nil {
			entry.Auth.Validator = s.jwtValidator
			if entry.Auth.Validator == nil {
				s.Log.Error("auth-required message registered but no default JWT validator set",
					"type", sp.Type)
			}
		}
		s.MessageRegistry[sp.Type] = entry
	}
}

// sendError sends an error message to the specified WebSocket connection.
func (s *LinkServer) sendError(c *websocket.Conn, msg string) error {
	env := messages.Envelope{
		Type: messages.ErrorType,
		Data: mustJSON(messages.Error{Msg: msg}),
	}
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	s.Log.Debug("sending error message", "msg", msg)
	return c.WriteMessage(websocket.TextMessage, b)
}

// isNormalDisconnect checks if an error represents a normal WebSocket disconnection
// that doesn't require error logging.
func isNormalDisconnect(err error) bool {
	if err == nil {
		return false
	}

	if websocket.IsCloseError(err,
		websocket.CloseNormalClosure,
		websocket.CloseGoingAway,
		websocket.CloseNoStatusReceived,
		websocket.CloseAbnormalClosure,
	) {
		return true
	}

	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}

	var ne *net.OpError
	if errors.As(err, &ne) {
		return true
	}

	if errors.Is(err, syscall.EPIPE) {
		return true
	}

	msg := err.Error()
	if strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "unexpected EOF") {
		return true
	}

	return false
}

// mustJSON marshals a value to JSON and panics on error.
func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// WithClientID returns a child context that carries the client id.
func WithClientID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyClientID, id)
}

// ClientIDFrom extracts the client id from context.
func ClientIDFrom(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxKeyClientID).(string)
	return v, ok
}

// WithClaims returns a child context that carries the JWT claims.
func WithClaims(ctx context.Context, c *auth.JWTClaims) context.Context {
	return context.WithValue(ctx, ctxKeyClaims, c)
}

// ClaimsFrom extracts the JWT claims from context.
func ClaimsFrom(ctx context.Context) (*auth.JWTClaims, bool) {
	v, ok := ctx.Value(ctxKeyClaims).(*auth.JWTClaims)
	return v, ok
}

// WithToken returns a child context that carries the JWT token.
func WithToken(ctx context.Context, t string) context.Context {
	return context.WithValue(ctx, ctxKeyToken, t)
}

// TokenFrom extracts the JWT token from the context.
func TokenFrom(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxKeyToken).(string)
	return v, ok
}
