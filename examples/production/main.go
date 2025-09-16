package main

import (
	"context"
	"fmt"
	"link/messages"
	"link/server"
	"log"
	"log/slog"
	"time"
)

// TestMessage represents a simple message type for the example
type TestMessage struct {
	Hello string `json:"hello"`
}

// main demonstrates the production-ready features of LinkServer including health endpoints,
// connection limits, timeouts, and rate limiting. This example shows how to configure
// a WebSocket server for production use with proper resource management and monitoring.
func main() {
	// Create a LinkServer with production-ready configuration
	srv := server.NewLinkServer(
		server.Host("localhost"),                         // Bind to localhost interface
		server.WithPort(9999),                            // Listen on port 9999
		server.WithCompression(true),                     // Enable WebSocket compression
		server.WithLogLevel(int(slog.LevelInfo)),         // Set logging to Info level
		server.WithHealthEndpoint("/health"),             // Enable health check endpoint
		server.WithMaxConnections(100),                   // Limit to 100 concurrent connections
		server.WithConnectionTimeout(30*time.Second),     // 30 second connection timeout
		server.WithMessageRateLimit(60),                  // Limit to 60 messages per minute per client
	)

	// Register message handlers
	srv.Register(
		messages.Message[TestMessage]("test", handleTestMessage),
	)

	// Display startup information and feature explanations
	fmt.Println("Starting LinkServer production example...")
	fmt.Println("Server will listen on localhost:9999")
	fmt.Println("")
	fmt.Println("Production features enabled:")
	fmt.Println("- Health endpoint: http://localhost:9999/health")
	fmt.Println("- Max connections: 100")
	fmt.Println("- Connection timeout: 30 seconds")
	fmt.Println("- Rate limit: 60 messages per minute per client")
	fmt.Println("")
	fmt.Println("WebSocket endpoint: ws://localhost:9999/ws")
	fmt.Println("")
	fmt.Println("Example message:")
	fmt.Println(`{"type": "test", "data": {"hello": "world"}}`)
	fmt.Println("")
	fmt.Println("Test the health endpoint:")
	fmt.Println("curl http://localhost:9999/health")
	fmt.Println("")

	// Start the server
	if err := srv.Serve(); err != nil {
		log.Fatal("Server failed:", err)
	}
}

// handleTestMessage processes incoming TestMessage
func handleTestMessage(ctx context.Context, msg *TestMessage) error {
	clientID, ok := server.ClientIDFrom(ctx)
	if !ok {
		return fmt.Errorf("no client ID in context")
	}

	fmt.Printf("Received message from client %s: %s\n", clientID, msg.Hello)
	return nil
}