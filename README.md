# Link - Type-Safe WebSocket Messaging Library

Link is a Go library that provides a powerful, type-safe WebSocket server for handling structured messages. Built on top of the proven **[gorilla/websocket](https://github.com/gorilla/websocket)** framework, it offers an easy way to build production-ready real-time applications with custom message types, comprehensive authentication, and enterprise-grade features.

## Features

### Core Features
- **Type-safe message handling** - Use Go generics for compile-time type safety
- **Built on gorilla/websocket** - Leverages the most popular Go WebSocket library
- **Flexible configuration** - Functional options pattern for easy customization
- **Built-in client management** - Automatic client connection lifecycle management
- **Message broadcasting** - Send messages to all connected clients or specific clients
- **Client-to-client routing** - Direct peer-to-peer messaging with automatic routing
- **Structured logging** - Built-in logging with configurable levels and custom logger support

### Advanced Messaging
- **MessagingContext** - Server-initiated messaging with correlation ID tracking
- **Message acknowledgments** - Request-response patterns with automatic ACK handling
- **Correlation tracking** - Built-in support for tracking related messages
- **Message versioning** - Optional message versioning support
- **Per-message authentication** - Flexible authentication requirements per message type

### Production Features  
- **JWT Authentication** - Built-in JWT token validation with HS256 and custom validator support
- **TLS/HTTPS Support** - Secure WebSocket connections with auto-generated or custom certificates
- **Health endpoints** - HTTP health check endpoints for load balancer integration
- **Connection management** - Configurable connection limits, timeouts, and rate limiting
- **Ping/Pong functionality** - Standard WebSocket control frame ping/pong with configurable intervals
- **WebSocket compression** - Optional compression support for bandwidth optimization
- **Graceful error handling** - Proper error messages and connection cleanup

### Scalability & Monitoring
- **Rate limiting** - Per-client message rate limiting to prevent abuse
- **Connection limits** - Maximum concurrent connection enforcement
- **HTTP server timeouts** - Configurable read, write, and idle timeouts
- **Comprehensive logging** - Detailed logging for debugging and monitoring

## Quick Start

### Installation

```bash
go get github.com/yourusername/link  # Update with actual module path
```

### Basic Usage

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "link/messages"
    "link/server"
)

// Define your message type
type HelloMessage struct {
    Name string `json:"name"`
}

func main() {
    // Create server with default settings
    srv := server.NewDefaultServer()
    
    // Register message handler
    srv.Register(
        messages.Message[HelloMessage]("hello", handleHello),
    )
    
    // Start server
    if err := srv.Serve(); err != nil {
        log.Fatal(err)
    }
}

func handleHello(ctx context.Context, msg *HelloMessage) error {
    clientID, _ := server.ClientIDFrom(ctx)
    fmt.Printf("Hello from %s (client: %s)\n", msg.Name, clientID)
    return nil
}
```

### Advanced Server Configuration

```go
srv := server.NewLinkServer(
    server.Host("0.0.0.0"),
    server.WithPort(8080),
    server.WithCompression(true),
    server.WithLogLevel(int(slog.LevelDebug)),
    server.WithMaxConnections(1000),
    server.WithHealthEndpoint("/health"),
    server.WithMessageRateLimit(100), // messages per minute per client
    server.WithDefaultPing(),          // enable ping/pong keep-alive
)
```

## Authentication

Link provides comprehensive JWT authentication with flexible per-message requirements.

### Server-Wide JWT Configuration

```go
// JWT required for all connections
secret := []byte("your-secret-key")
srv := server.NewLinkServer(
    server.Host("localhost"),
    server.WithPort(9999),
    server.WithHS256JWT(secret, true), // true = JWT required
)
```

### Per-Message Authentication

```go
// Mix of public and secure message handlers
srv.Register(
    // Public message - no authentication required
    messages.Message[PublicMessage]("public", handlePublic),
    
    // Secure message - JWT required
    messages.Message[SecureMessage]("secure", handleSecure, messages.WithAuth()),
    
    // Custom validator for specific message
    messages.Message[AdminMessage]("admin", handleAdmin, 
        messages.WithCustomValidator(adminValidator)),
)
```

### Creating JWT Tokens

```go
token, err := auth.CreateTokenHS256(
    []byte("your-secret-key"),
    "user-123",                    // Subject (user ID)
    time.Hour,                     // Expires in 1 hour
    "your-app",                    // Issuer
    "link",                        // Audience
    "user@example.com",            // Email claim
    []string{"read", "write"},     // Custom scopes
)
```

### Client Authentication

**Authorization Header (Recommended):**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Query Parameter (Alternative):**
```
wss://localhost:9999/ws?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Accessing JWT Claims

```go
func handleSecureMessage(ctx context.Context, msg *SecureMessage) error {
    // JWT claims are automatically available in context for authenticated messages
    if claims, ok := server.ClaimsFrom(ctx); ok {
        fmt.Printf("User: %s, Email: %s\n", claims.Subject, claims.Email)
        fmt.Printf("Scopes: %v\n", claims.Scopes)
    }
    return nil
}
```

## Server-Initiated Messaging

Link provides a powerful MessagingContext for server-initiated communication with clients.

### Using MessagingContext

```go
func handleRequest(ctx context.Context, req *EchoRequest) error {
    clientID, _ := server.ClientIDFrom(ctx)
    
    // Use MessagingContext for server-initiated responses
    if mctx, ok := ctx.(server.MessagingContext); ok {
        // Send correlated response back to requesting client
        response := &EchoResponse{Echo: req.Message}
        return mctx.SendTo(clientID, "echo.response", response)
    }
    
    return nil
}
```

### Message Options

```go
// Send with custom options
err := mctx.SendTo(clientID, "notification", data,
    server.WithVersion("2.0"),
    server.WithAckRequested(),        // Request acknowledgment
    server.WithCorrelation("req-123"), // Custom correlation ID
)

// Broadcast to all clients
count := mctx.Broadcast("announcement", announcement)
fmt.Printf("Sent to %d clients\n", count)
```

## TLS/HTTPS Support

### Development TLS (Self-Signed Certificate)

```go
srv := server.NewLinkServer(
    server.Host("localhost"),
    server.WithPort(9999),
    server.WithTLS("", "", true), // Empty cert/key paths, dev=true
)
```

Connect using: `wss://localhost:9999/ws`

### Production TLS (Certificate Files)

```go
srv := server.NewLinkServer(
    server.Host("0.0.0.0"),
    server.WithPort(443),
    server.WithTLS("server.crt", "server.key", false), // dev=false
)
```

### Custom TLS Configuration

```go
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS13,
    // Your custom TLS configuration
}

srv := server.NewLinkServer(
    server.Host("0.0.0.0"),
    server.WithPort(443),
    server.WithTLSConfig(tlsConfig),
)
```

## Ping/Pong Keep-Alive

Link uses standard WebSocket control frame ping/pong functionality to maintain connections and detect disconnected clients. This leverages the built-in ping/pong support from the Gorilla WebSocket library.

### Default Ping Configuration

```go
srv := server.NewLinkServer(
    server.WithDefaultPing(), // 30s ping interval, 5s pong timeout
)
```

### Custom Ping Configuration

```go
srv := server.NewLinkServer(
    server.WithPing(10*time.Second, 3*time.Second), // Custom ping interval and pong timeout
)
```

### How It Works

- The server automatically sends WebSocket ping control frames at the configured interval
- Clients automatically respond with pong control frames (handled by the WebSocket library)
- If a pong response isn't received within the timeout period, the connection is considered dead
- This provides reliable connection health monitoring without custom application-level logic

## Message Format

Messages are sent as JSON with the following envelope structure:

```json
{
    "type": "your-message-type",
    "version": "optional-version",
    "to": "optional-recipient-client-id",
    "from": "sender-client-id",
    "id": "unique-message-id",
    "cid": "correlation-id",
    "ackRequested": false,
    "data": {
        // Your message payload
    }
}
```

## Client-to-Client Routing

Link supports direct client-to-client message routing without server processing.

### Routing Features

- **Direct routing** - Messages with a `to` field are forwarded directly to the specified client
- **Automatic sender identification** - The server automatically sets the `from` field to the sender's client ID  
- **Client ID assignment** - Each client receives their unique ID via a "joined" message upon connection
- **Error handling** - Unknown recipient IDs return appropriate error messages

### Routing Example

```json
{
    "type": "private-message",
    "to": "client-uuid-here",
    "data": {
        "message": "Hello from another client!"
    }
}
```

When clients connect, they automatically receive a "joined" message:

```json
{
    "type": "joined",
    "data": {
        "id": "your-unique-client-id"
    }
}
```

## Configuration Options

### Server Configuration

| Option | Description |
|--------|-------------|
| `Host(string)` | Set the host address to bind to |
| `WithPort(int)` | Set the port number |
| `WithCompression(bool)` | Enable/disable WebSocket compression |
| `WithCheckOrigin(func)` | Set origin check function for CORS |

### Logging & Monitoring  

| Option | Description |
|--------|-------------|
| `WithLogLevel(int)` | Set logging level (slog levels) |
| `WithLogger(Logger)` | Use custom logger implementation |
| `WithSlog(*slog.Logger)` | Use specific slog.Logger instance |
| `WithHealthEndpoint(string)` | Enable health check endpoint at specified path |

### Authentication

| Option | Description |
|--------|-------------|
| `WithHS256JWT(secret, require)` | Enable JWT authentication with HS256 algorithm |
| `WithJWTValidator(validator, require)` | Use custom JWT validator implementation |

### TLS/Security

| Option | Description |
|--------|-------------|
| `WithTLS(certFile, keyFile, dev)` | Enable TLS with certificate files or dev mode |
| `WithTLSConfig(*tls.Config)` | Use custom TLS configuration |

### Connection Management

| Option | Description |
|--------|-------------|
| `WithMaxConnections(int)` | Set maximum concurrent WebSocket connections |
| `WithConnectionTimeout(duration)` | Set timeout for WebSocket connections |
| `WithMessageRateLimit(int)` | Set messages per minute per client limit |

### Ping/Pong

| Option | Description |
|--------|-------------|
| `WithDefaultPing()` | Enable default ping/pong (30s interval, 5s timeout) |
| `WithPing(interval, timeout)` | Enable ping/pong with custom timing |
| `WithPingHandler(func)` | Set custom ping message handler |
| `WithPongHandler(func)` | Set custom pong message handler |

### HTTP Server Timeouts

| Option | Description |
|--------|-------------|
| `WithReadTimeout(duration)` | Set HTTP server read timeout |
| `WithWriteTimeout(duration)` | Set HTTP server write timeout |
| `WithIdleTimeout(duration)` | Set HTTP server idle timeout |

## Production Features

### Health Monitoring

```go
srv := server.NewLinkServer(
    server.WithHealthEndpoint("/health"),
)
```

Access health information at `http://localhost:port/health`:

```json
{
    "status": "ok",
    "timestamp": "2024-01-01T12:00:00Z",
    "clients": 42,
    "max_connections": 1000
}
```

### Connection Limits and Rate Limiting

```go
srv := server.NewLinkServer(
    server.WithMaxConnections(1000),           // Maximum concurrent connections
    server.WithMessageRateLimit(60),           // 60 messages per minute per client
    server.WithConnectionTimeout(30*time.Second), // Connection timeout
)
```

### HTTP Server Timeouts

```go
srv := server.NewLinkServer(
    server.WithReadTimeout(15*time.Second),    // Request read timeout
    server.WithWriteTimeout(15*time.Second),   // Response write timeout  
    server.WithIdleTimeout(60*time.Second),    // Keep-alive idle timeout
)
```

## Examples

The library includes comprehensive examples demonstrating all major features:

### Available Examples

- **`examples/basic/`** - Simple message handling with default configuration
- **`examples/ids/`** - Advanced messaging with correlation IDs and acknowledgments  
- **`examples/jwt/`** - JWT authentication with per-message auth requirements
- **`examples/tls/`** - TLS/HTTPS WebSocket server with auto-generated certificates
- **`examples/ping/`** - Ping/pong functionality with custom handlers
- **`examples/production/`** - Production-ready server with all enterprise features

### Running Examples

**Basic Example:**
```bash
cd examples/basic && go run main.go
```
Then connect to `ws://localhost:9999/ws`

**JWT Authentication Example:**
```bash
cd examples/jwt && go run main.go
```
Includes generated JWT token for testing secure endpoints

**Production Example:**
```bash
cd examples/production && go run main.go
```
Demonstrates health endpoints, rate limiting, connection management

**TLS Example:**
```bash
cd examples/tls && go run main.go
```
Then connect to `wss://localhost:9999/ws` (note the secure protocol)

### Example Message Format

Send messages in this JSON format:

```json
{
    "type": "test",
    "data": {
        "hello": "world"
    }
}
```

For acknowledged messages:

```json
{
    "type": "echo.request",
    "id": "req-123",
    "ackRequested": true,
    "data": {
        "message": "Hello server!"
    }
}
```

## API Reference

### Server Creation

```go
// Create server with default configuration (localhost:9999)
srv := server.NewDefaultServer()

// Create server with custom options
srv := server.NewLinkServer(opts ...Option)
```

### Server Methods

```go
// Start the server (blocking)
err := srv.Serve()

// Register message handlers
srv.Register(specs ...messages.MessageSpec)

// Broadcast to all connected clients
srv.Broadcast(msgType, version string, payload any)
```

### Message Registration

```go
// Basic message handler
messages.Message[T](typeName string, handler func(context.Context, *T) error)

// Message with authentication required
messages.Message[T](typeName, handler, messages.WithAuth())

// Message with custom JWT validator
messages.Message[T](typeName, handler, messages.WithCustomValidator(validator))
```

### Context Helpers

```go
// Extract client ID from context
clientID, ok := server.ClientIDFrom(ctx)

// Extract JWT claims from context (for authenticated messages)
claims, ok := server.ClaimsFrom(ctx)

// Extract JWT token from context
token, ok := server.TokenFrom(ctx)
```

### MessagingContext Methods

```go
// Send to specific client
err := mctx.SendTo(clientID, msgType, payload, opts...)

// Broadcast to all clients  
count := mctx.Broadcast(msgType, payload, opts...)

// Get correlation ID
corrID := mctx.CorrelationID()

// Create context with new correlation ID
newMctx := mctx.WithCorrelation(newCorrID)
```

### Send Options

```go
server.WithFrom(senderID)        // Override sender ID
server.WithVersion(version)      // Set message version
server.WithCorrelation(corrID)   // Set correlation ID
server.WithAckRequested()        // Request acknowledgment
```

## Testing

The library includes comprehensive test coverage for all packages:

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./server
go test ./auth  
go test ./messages
```

## Architecture

Link is built with a clean, modular architecture:

- **`server/`** - Core WebSocket server and client management
- **`auth/`** - JWT authentication and validation  
- **`messages/`** - Message types, envelopes, and registration
- **`examples/`** - Comprehensive usage examples

The library wraps the proven [gorilla/websocket](https://github.com/gorilla/websocket) package while providing a higher-level, type-safe API with enterprise features.

## Performance

Link is designed for production use with:

- **Efficient client management** - Concurrent-safe client registry with minimal locking
- **Message pooling** - Reusable message buffers to reduce GC pressure  
- **Rate limiting** - Per-client rate limiting with automatic cleanup
- **Connection limits** - Configurable limits to prevent resource exhaustion
- **Graceful error handling** - Proper connection cleanup and error recovery

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -am 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)  
5. Create a Pull Request

## License

This project is licensed under the Apache 2.0 License - see the LICENSE file for details.

## Acknowledgments

Built on top of the excellent [gorilla/websocket](https://github.com/gorilla/websocket) library.