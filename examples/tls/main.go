package main

import (
	"context"
	"fmt"
	"github.com/sethfduke/link/messages"
	"github.com/sethfduke/link/server"
	"log"
	"log/slog"
)

// TestMessage represents a simple message type for the example
type TestMessage struct {
	Hello string `json:"hello"`
}

// TestReply represents a reply message
type TestReply struct {
	Reply string `json:"reply"`
}

// main demonstrates how to create a LinkServer with TLS/HTTPS enabled.
// This example shows how to configure the server with development TLS using
// auto-generated self-signed certificates for secure WebSocket connections.
func main() {
	// Create a new LinkServer with TLS enabled for secure connections
	// The server uses development mode TLS with auto-generated certificates
	srv := server.NewLinkServer(
		server.Host("localhost"),                 // Bind to localhost interface
		server.WithPort(9999),                    // Listen on port 9999
		server.WithCompression(true),             // Enable WebSocket compression
		server.WithLogLevel(int(slog.LevelInfo)), // Set logging to Info level
		server.WithTLS("", "", true),             // Enable dev TLS (auto-generated cert)
	)

	// Register the TestMessage handler to process incoming test messages
	// This demonstrates secure message handling over TLS connections
	srv.Register(
		messages.Message[TestMessage]("test", handleTestMessage),
	)

	// Display startup information and connection details for TLS
	fmt.Println("Starting LinkServer example...")
	fmt.Println("Server will listen on localhost:9999")
	fmt.Println("Connect to wss://localhost:9999/ws to test")
	fmt.Println("")

	// Show example message format for client testing
	fmt.Println("Example message to send:")
	fmt.Println(`{"type": "test", "data": {"hello": "world"}}`)
	fmt.Println("")

	// Start the server with TLS enabled
	// The server will generate a self-signed certificate automatically
	if err := srv.Serve(); err != nil {
		log.Fatal("Server failed:", err)
	}
}

// handleTestMessage processes incoming TestMessage and sends a reply
func handleTestMessage(ctx context.Context, msg *TestMessage) error {
	fmt.Printf("Received message: %+v\n", msg)

	// Get the client ID from context
	clientID, ok := server.ClientIDFrom(ctx)
	if !ok {
		return fmt.Errorf("no client ID in context")
	}

	fmt.Printf("Message from client %s: %s\n", clientID, msg.Hello)

	// Create a reply message
	reply := TestReply{
		Reply: fmt.Sprintf("Hello %s! I received your message: %s", clientID, msg.Hello),
	}

	// You would typically send the reply back through the server's broadcast or client-specific send
	// For this example, we just log that we would send it
	fmt.Printf("Would send reply to client %s: %+v\n", clientID, reply)

	return nil
}
