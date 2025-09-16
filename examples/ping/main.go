package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sethfduke/link/messages"
	"github.com/sethfduke/link/server"
	"log"
	"log/slog"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// PingMessage represents a simple message type for the example
type PingMessage struct {
	Message string `json:"message"`
}

// main demonstrates the ping/pong functionality of LinkServer with different configurations.
// This example shows how to configure default ping behavior, custom intervals, and custom handlers.
func main() {
	fmt.Println("Starting LinkServer ping/pong example...")
	fmt.Println("This example demonstrates three different ping configurations:")
	fmt.Println("")

	// Start three different servers with different ping configurations
	go startDefaultPingServer()
	go startCustomIntervalServer()
	go startCustomHandlerServer()

	// Give servers time to start
	fmt.Println("Waiting for servers to start...")
	time.Sleep(500 * time.Millisecond)

	// Run demo clients to demonstrate ping/pong functionality
	var wg sync.WaitGroup

	wg.Add(3)
	go func() {
		defer wg.Done()
		runDemoClient("Default Ping Server", "ws://localhost:9999/ws", 35*time.Second)
	}()

	go func() {
		defer wg.Done()
		runDemoClient("Custom Interval Server", "ws://localhost:10000/ws", 15*time.Second)
	}()

	go func() {
		defer wg.Done()
		runDemoClient("Custom Handler Server", "ws://localhost:10001/ws", 20*time.Second)
	}()

	// Wait for all demo clients to complete
	wg.Wait()

	fmt.Println("\nPing/pong demonstration completed successfully!")
	fmt.Println("All servers demonstrated their ping/pong configurations.")
}

// startDefaultPingServer demonstrates the default ping behavior
func startDefaultPingServer() {
	fmt.Println("1. Default Ping Server (localhost:9999)")
	fmt.Println("   - Uses default ping interval (30 seconds)")
	fmt.Println("   - Uses default ping timeout (5 seconds)")
	fmt.Println("   - Connect to: ws://localhost:9999/ws")
	fmt.Println("")

	srv := server.NewLinkServer(
		server.Host("localhost"),
		server.WithPort(9999),
		server.WithCompression(true),
		server.WithLogLevel(int(slog.LevelInfo)),
		server.WithDefaultPing(), // Enable default ping behavior
	)

	srv.Register(
		messages.Message[PingMessage]("ping", handlePingMessage),
	)

	if err := srv.Serve(); err != nil {
		log.Printf("Default ping server failed: %v", err)
	}
}

// startCustomIntervalServer demonstrates custom ping intervals
func startCustomIntervalServer() {
	time.Sleep(100 * time.Millisecond) // Stagger startup

	fmt.Println("2. Custom Interval Server (localhost:10000)")
	fmt.Println("   - Uses custom ping interval (10 seconds)")
	fmt.Println("   - Uses custom ping timeout (3 seconds)")
	fmt.Println("   - Connect to: ws://localhost:10000/ws")
	fmt.Println("")

	srv := server.NewLinkServer(
		server.Host("localhost"),
		server.WithPort(10000),
		server.WithCompression(true),
		server.WithLogLevel(int(slog.LevelInfo)),
		server.WithPing(10*time.Second, 3*time.Second), // Custom ping settings
	)

	srv.Register(
		messages.Message[PingMessage]("ping", handlePingMessage),
	)

	if err := srv.Serve(); err != nil {
		log.Printf("Custom interval server failed: %v", err)
	}
}

// startCustomHandlerServer demonstrates custom ping/pong handlers
func startCustomHandlerServer() {
	time.Sleep(200 * time.Millisecond) // Stagger startup

	fmt.Println("3. Custom Handler Server (localhost:10001)")
	fmt.Println("   - Uses custom ping/pong handlers with logging")
	fmt.Println("   - Uses 15 second ping interval")
	fmt.Println("   - Connect to: ws://localhost:10001/ws")
	fmt.Println("")

	// Define custom ping handler
	customPingHandler := func(appData string) error {
		fmt.Printf("[CUSTOM PING HANDLER] Received ping with data: %q\n", appData)
		return nil // Return nil to send automatic pong response
	}

	// Define custom pong handler
	customPongHandler := func(appData string) error {
		fmt.Printf("[CUSTOM PONG HANDLER] Received pong with data: %q\n", appData)
		return nil
	}

	srv := server.NewLinkServer(
		server.Host("localhost"),
		server.WithPort(10001),
		server.WithCompression(true),
		server.WithLogLevel(int(slog.LevelInfo)),
		server.WithPing(15*time.Second, 5*time.Second), // Custom ping timing
		server.WithPingHandler(customPingHandler),      // Custom ping handler
		server.WithPongHandler(customPongHandler),      // Custom pong handler
	)

	srv.Register(
		messages.Message[PingMessage]("ping", handlePingMessage),
	)

	if err := srv.Serve(); err != nil {
		log.Printf("Custom handler server failed: %v", err)
	}
}

// handlePingMessage processes incoming ping messages
func handlePingMessage(ctx context.Context, msg *PingMessage) error {
	clientID, _ := server.ClientIDFrom(ctx)
	fmt.Printf("Received ping message from client %s: %s\n", clientID, msg.Message)
	return nil
}

// runDemoClient connects to a WebSocket server and demonstrates ping/pong functionality
func runDemoClient(serverName, wsURL string, duration time.Duration) {
	fmt.Printf("\n--- Connecting to %s ---\n", serverName)

	// Configure WebSocket dialer
	dialer := websocket.Dialer{
		HandshakeTimeout:  5 * time.Second,
		EnableCompression: true,
	}

	// Connect to the WebSocket server
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", serverName, err)
		return
	}
	defer conn.Close()

	// Set up ping/pong handlers to show when they're received
	conn.SetPingHandler(func(appData string) error {
		fmt.Printf("[%s CLIENT] 📡 Received PING from server (data: %q)\n", serverName, appData)
		return nil // Returning nil sends automatic pong response
	})

	conn.SetPongHandler(func(appData string) error {
		fmt.Printf("[%s CLIENT] 🏓 Received PONG from server (data: %q)\n", serverName, appData)
		return nil
	})

	// Read the initial "joined" message
	_, message, err := conn.ReadMessage()
	if err != nil {
		log.Printf("Failed to read joined message from %s: %v", serverName, err)
		return
	}

	var joinedEnvelope messages.Envelope
	if err := json.Unmarshal(message, &joinedEnvelope); err != nil {
		log.Printf("Failed to unmarshal joined envelope from %s: %v", serverName, err)
		return
	}

	var joinedMessage messages.Joined
	if err := json.Unmarshal(joinedEnvelope.Data, &joinedMessage); err != nil {
		log.Printf("Failed to unmarshal joined data from %s: %v", serverName, err)
		return
	}

	fmt.Printf("[%s CLIENT] ✅ Connected with ID: %s\n", serverName, joinedMessage.ID)

	// Send a test message to the server
	testEnvelope := messages.Envelope{
		Type: "ping",
		Data: mustJSON(PingMessage{Message: fmt.Sprintf("Hello from %s demo client!", serverName)}),
	}

	if err := conn.WriteJSON(testEnvelope); err != nil {
		log.Printf("Failed to send test message to %s: %v", serverName, err)
		return
	}

	fmt.Printf("[%s CLIENT] 📤 Sent test message to server\n", serverName)

	// Listen for messages and ping/pong activity for the specified duration
	done := make(chan struct{})
	go func() {
		defer close(done)
		deadline := time.Now().Add(duration)
		_ = conn.SetReadDeadline(deadline)

		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("[%s CLIENT] WebSocket error: %v", serverName, err)
				}
				return
			}
			// Messages are handled by the ping/pong handlers set above
		}
	}()

	// Wait for the demo duration
	select {
	case <-done:
		fmt.Printf("[%s CLIENT] 🔌 Connection closed\n", serverName)
	case <-time.After(duration):
		fmt.Printf("[%s CLIENT] ⏰ Demo duration completed\n", serverName)
	}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
