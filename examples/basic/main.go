package main

import (
	"context"
	"fmt"
	"github.com/sethfduke/link/messages"
	"github.com/sethfduke/link/server"
	"log"
)

// TestMessage represents a simple message type for the example
type TestMessage struct {
	Hello string `json:"hello"`
}

// TestReply represents a reply message
type TestReply struct {
	Reply string `json:"reply"`
}

// main demonstrates the most basic LinkServer setup with default configuration.
// This example shows how to create a simple WebSocket server with message handling
// using the library's default settings for quick prototyping and development.
func main() {
	// Create a new LinkServer using the convenient default configuration
	// This sets up localhost:9999 with compression enabled and Info-level logging
	srv := server.NewDefaultServer()

	// Register a message handler for the "test" message type
	// This demonstrates type-safe message handling with automatic JSON unmarshaling
	srv.Register(
		messages.Message[TestMessage]("test", handleTestMessage),
	)

	// Display startup information and connection instructions
	fmt.Println("Starting LinkServer example...")
	fmt.Println("Server will listen on localhost:9999")
	fmt.Println("Connect to ws://localhost:9999/ws to test")
	fmt.Println("")

	// Show the expected message format for client testing
	// Clients should send JSON messages with this envelope structure
	fmt.Println("Example message to send:")
	fmt.Println(`{"type": "test", "data": {"hello": "world"}}`)
	fmt.Println("")

	// Start the server and begin accepting WebSocket connections
	// This call blocks until the server encounters an error or is terminated
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
