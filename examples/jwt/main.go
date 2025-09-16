package main

import (
	"context"
	"fmt"
	"link/auth"
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

// TestReply represents a reply message
type TestReply struct {
	Reply string `json:"reply"`
}

func main() {
	secret := []byte("test-secret")

	// Build the server. We set a default HS256 validator; auth is enforced per-message.
	srv := server.NewLinkServer(
		server.Host("localhost"),
		server.WithPort(9999),
		server.WithCompression(true),
		server.WithLogLevel(int(slog.LevelInfo)),
		// Set a default validator for convenience. 'require' is ignored in per-message mode.
		server.WithHS256JWT(secret, false),
	)

	srv.Register(
		messages.Message[TestMessage]("test.public", handlePublicMessage),
		messages.Message[TestMessage]("test.secure", handleSecureMessage, messages.WithAuth()),
	)

	// Generate a demo token (valid for 1 hour) you can use with websocat, etc.
	token, _ := auth.CreateTokenHS256(
		secret,
		"user-123",
		time.Hour,
		"example-issuer",
		"link",
		"user@example.com",
		[]string{"read"},
	)

	// Display startup info
	fmt.Println("Starting LinkServer example on ws://localhost:9999/ws")
	fmt.Println()
	fmt.Println("A JWT is required ONLY for type: \"test.secure\".")
	fmt.Println("Public messages (type: \"test.public\") do NOT require a token.")
	fmt.Println()
	fmt.Println("Test token (HS256 with secret \"test-secret\"):")
	fmt.Printf("%s\n\n", token)
	fmt.Println("Connect with websocat (no TLS):")
	fmt.Println("  websocat -H='Authorization: Bearer " + token + "' ws://localhost:9999/ws")
	fmt.Println()
	fmt.Println("Example payloads:")
	fmt.Println("  '{\"type\":\"test.public\",\"data\":{\"hello\":\"world\"}}'")
	fmt.Println("  '{\"type\":\"test.secure\",\"data\":{\"hello\":\"world\"}}'")
	fmt.Println()

	if err := srv.Serve(); err != nil {
		log.Fatal("Server failed:", err)
	}
}

// handlePublicMessage processes a message that does NOT require JWT
func handlePublicMessage(ctx context.Context, msg *TestMessage) error {
	clientID, _ := server.ClientIDFrom(ctx)
	fmt.Printf("[public] From %s: %+v\n", clientID, msg)

	reply := TestReply{
		Reply: fmt.Sprintf("Hello %s! (public) I received: %s", clientID, msg.Hello),
	}
	fmt.Printf("[public] Would send reply to %s: %+v\n", clientID, reply)
	return nil
}

// handleSecureMessage processes a message that DOES require JWT (per-message)
func handleSecureMessage(ctx context.Context, msg *TestMessage) error {
	clientID, _ := server.ClientIDFrom(ctx)

	// Claims are attached by the per-message validator in dispatch
	if claims, ok := server.ClaimsFrom(ctx); ok {
		fmt.Printf("[secure] From %s (sub=%s, email=%s): %+v\n",
			clientID, claims.Subject, claims.Email, msg)
	} else {
		// If per-message auth is wired correctly, we shouldn't hit this.
		return fmt.Errorf("secure handler: missing claims")
	}

	reply := TestReply{
		Reply: fmt.Sprintf("Hello %s! (secure) I received: %s", clientID, msg.Hello),
	}
	fmt.Printf("[secure] Would send reply to %s: %+v\n", clientID, reply)
	return nil
}
