package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"link/messages"
	"link/server"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// EchoRequest represents a message requesting an echo response
type EchoRequest struct {
	Message string `json:"message"`
}

// EchoResponse represents the server's echo reply
type EchoResponse struct {
	Echo string `json:"echo"`
}

// Event represents a server-generated event message
type Event struct {
	Note string `json:"note"`
}

// main demonstrates advanced LinkServer features including correlation IDs, acknowledgments,
// and server-initiated messaging using the MessagingContext. This example shows how to
// build request-response patterns with automatic correlation tracking and message acknowledgments.
func main() {
	// Create a LinkServer with enhanced messaging capabilities
	// This configuration enables correlation ID tracking and acknowledgment features
	srv := server.NewLinkServer(
		server.Host("localhost"),     // Bind to localhost interface
		server.WithPort(9999),        // Listen on port 9999
		server.WithCompression(true), // Enable WebSocket compression
		server.WithLogLevel(0),       // Set to debug level for detailed logging
	)

	// Register message handler for echo requests
	// This handler demonstrates server-initiated responses using MessagingContext
	srv.Register(
		messages.Message[EchoRequest]("echo.request", handleEcho),
	)

	// Display startup information and feature explanations
	fmt.Println("Starting LinkServer IDs example...")
	fmt.Println("Server will listen on localhost:9999")
	fmt.Println("Connect to ws://localhost:9999/ws to test")
	fmt.Println("")
	fmt.Println("This example demonstrates:")
	fmt.Println("- Message correlation IDs for request-response patterns")
	fmt.Println("- Automatic acknowledgment handling")
	fmt.Println("- Server-initiated messaging using MessagingContext")
	fmt.Println("")
	fmt.Println("Example message with acknowledgment:")
	fmt.Println(`{"type": "echo.request", "id": "req-123", "ackRequested": true, "data": {"message": "hello"}}`)
	fmt.Println("")
	fmt.Println("Running integrated demo client...")
	fmt.Println("")

	// Start server in background
	go func() {
		if err := srv.Serve(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	// Give server a moment to bind
	time.Sleep(300 * time.Millisecond)

	// Run integrated demo client to demonstrate correlation & acknowledgment features
	runDemoClient()
}

// handleEcho demonstrates server-initiated messaging using MessagingContext.
// This handler shows how to send correlated responses back to clients, with
// automatic correlation ID tracking and acknowledgment handling by the server.
func handleEcho(ctx context.Context, req *EchoRequest) error {
	clientID, _ := server.ClientIDFrom(ctx)
	fmt.Printf("Received echo request from client %s: %s\n", clientID, req.Message)

	// Use the MessagingContext to send server-initiated responses
	// This enables request-response patterns with automatic correlation
	if mctx, ok := ctx.(server.MessagingContext); ok {
		// Send a correlated response back to the requesting client
		// The server automatically handles correlation ID tracking
		response := &EchoResponse{Echo: req.Message}
		if err := mctx.SendTo(clientID, "echo.response", response); err != nil {
			return fmt.Errorf("failed to send echo response: %w", err)
		}
		fmt.Printf("Sent echo response to client %s: %s\n", clientID, response.Echo)
	} else {
		// Fallback for contexts without MessagingContext (shouldn't occur in normal operation)
		fmt.Printf("Warning: No MessagingContext available for client %s\n", clientID)
	}

	return nil
}

// runDemoClient demonstrates the correlation ID and acknowledgment features
// by connecting to the server and sending a request with ackRequested=true.
// It shows how clients receive acknowledgments and correlated responses.
func runDemoClient() {
	// Configure WebSocket dialer with compression support
	dialer := websocket.Dialer{
		HandshakeTimeout:  5 * time.Second,
		EnableCompression: true,
	}

	// Connect to the WebSocket server
	conn, _, err := dialer.Dial("ws://localhost:9999/ws", nil)
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Read the initial "joined" message to get our client ID
	_, message, err := conn.ReadMessage()
	if err != nil {
		log.Fatalf("Failed to read joined message: %v", err)
	}

	var joinedEnvelope messages.Envelope
	if err := json.Unmarshal(message, &joinedEnvelope); err != nil {
		log.Fatalf("Failed to unmarshal joined envelope: %v", err)
	}

	var joinedMessage messages.Joined
	if err := json.Unmarshal(joinedEnvelope.Data, &joinedMessage); err != nil {
		log.Fatalf("Failed to unmarshal joined data: %v", err)
	}

	fmt.Printf("✓ Client connected with ID: %s\n", joinedMessage.ID)

	// Create and send an echo request with acknowledgment requested
	requestID := uuid.NewString()
	requestEnvelope := messages.Envelope{
		Type:         "echo.request",
		ID:           requestID,
		AckRequested: true,
		Data:         mustJSON(EchoRequest{Message: "Hello from demo client!"}),
	}

	fmt.Printf("→ Sending echo request (ID: %s)\n", requestID)
	if err := conn.WriteJSON(requestEnvelope); err != nil {
		log.Fatalf("Failed to send echo request: %v", err)
	}

	// Read responses to demonstrate acknowledgment and correlation features
	fmt.Println("\n--- Server Responses ---")
	deadline := time.Now().Add(2 * time.Second)
	_ = conn.SetReadDeadline(deadline)

	for i := 0; i < 3; i++ {
		_, responseBytes, err := conn.ReadMessage()
		if err != nil {
			if i == 0 {
				log.Fatalf("Failed to read server response: %v", err)
			}
			break // Timeout is expected after receiving responses
		}

		var responseEnvelope messages.Envelope
		if err := json.Unmarshal(responseBytes, &responseEnvelope); err != nil {
			log.Printf("Failed to unmarshal response: %v", err)
			continue
		}

		// Handle different response types
		switch responseEnvelope.Type {
		case messages.AckType:
			fmt.Printf("✓ Acknowledgment received (correlates to: %s)\n", responseEnvelope.CorrelationID)

		case "echo.response":
			var echoResponse EchoResponse
			_ = json.Unmarshal(responseEnvelope.Data, &echoResponse)
			fmt.Printf("📢 Echo response received (correlates to: %s): %q\n", responseEnvelope.CorrelationID, echoResponse.Echo)

		case "echo.event":
			var event Event
			_ = json.Unmarshal(responseEnvelope.Data, &event)
			fmt.Printf("📅 Event received (correlates to: %s): %q\n", responseEnvelope.CorrelationID, event.Note)

		default:
			fmt.Printf("❓ Unknown message type: %s (correlates to: %s)\n", responseEnvelope.Type, responseEnvelope.CorrelationID)
		}
	}

	fmt.Println("\n--- Demo completed successfully ---")
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
