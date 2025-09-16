package messages

import (
	"context"
	"encoding/json"
)

const (
	// ErrorType is the message type identifier used for error messages.
	ErrorType = "error"
	AckType   = "ack"
)

// Envelope represents the standard message envelope format used for WebSocket communication.
// It wraps message data with metadata including type, version, routing information, and payload.
type Envelope struct {
	Type          string          `json:"type"`
	Version       string          `json:"version,omitempty"`
	To            string          `json:"to,omitempty"`
	From          string          `json:"from,omitempty"`
	ID            string          `json:"id,omitempty"`
	CorrelationID string          `json:"cid,omitempty"`
	AckRequested  bool            `json:"ackRequested,omitempty"`
	Data          json.RawMessage `json:"data"`
}

// MessageType is a type alias for any message payload that can be handled by the server.
type MessageType any

// Factory is a function type that creates new instances of message types.
type Factory func() MessageType

// Handler is a function type for processing messages with context.
type Handler func(ctx context.Context, msg MessageType) error

type Ack struct {
	// You can enrich later (latency, server timestamp, etc.)
}
