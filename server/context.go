package server

import (
	"context"
	"encoding/json"
	"github.com/sethfduke/link/messages"
	"time"

	"github.com/google/uuid"
)

// MessagingContext extends the standard context.Context with messaging capabilities.
// It provides methods for sending messages to specific clients, broadcasting to all clients,
// and managing correlation IDs for request-response patterns.
type MessagingContext interface {
	context.Context
	SendTo(to string, typeName string, v any, opts ...SendOpt) error
	Broadcast(typeName string, v any, opts ...SendOpt) int
	CorrelationID() string
	WithCorrelation(id string) MessagingContext
}

// SendOpt is a function type used to configure message sending options.
// It modifies the sendOpts structure to customize message envelope fields.
type SendOpt func(*sendOpts)

// sendOpts holds configuration options for sending messages through the messaging context.
// It contains metadata fields that will be included in the message envelope.
type sendOpts struct {
	from         string
	version      string
	cid          string
	ackRequested bool
}

// WithFrom sets the sender ID for the message envelope.
// This overrides the default sender ID from the messaging context.
func WithFrom(id string) SendOpt { return func(o *sendOpts) { o.from = id } }

// WithVersion sets the version field for the message envelope.
// This can be used for message versioning and compatibility handling.
func WithVersion(v string) SendOpt { return func(o *sendOpts) { o.version = v } }

// WithCorrelation sets a custom correlation ID for the message envelope.
// This overrides the default correlation ID from the messaging context.
func WithCorrelation(id string) SendOpt { return func(o *sendOpts) { o.cid = id } }

// WithAckRequested marks the message as requiring an acknowledgment from the recipient.
// The server will automatically send an acknowledgment message when the message is processed.
func WithAckRequested() SendOpt { return func(o *sendOpts) { o.ackRequested = true } }

// mctx is the concrete implementation of MessagingContext.
// It wraps a base context and adds messaging functionality with server access,
// client identification, and correlation ID management.
type mctx struct {
	base   context.Context
	s      *LinkServer
	fromID string
	cid    string
}

// newMctx creates a new messaging context with the specified base context, server reference,
// sender client ID, and correlation ID. It returns a fully initialized mctx instance.
func newMctx(base context.Context, s *LinkServer, fromID, cid string) *mctx {
	return &mctx{base: base, s: s, fromID: fromID, cid: cid}
}

// Deadline returns the deadline from the underlying base context.
// It implements the context.Context interface.
func (m *mctx) Deadline() (time.Time, bool) { return m.base.Deadline() }

// Done returns the done channel from the underlying base context.
// It implements the context.Context interface.
func (m *mctx) Done() <-chan struct{} { return m.base.Done() }

// Err returns any error from the underlying base context.
// It implements the context.Context interface.
func (m *mctx) Err() error { return m.base.Err() }

// Value returns a value from the underlying base context for the given key.
// It implements the context.Context interface.
func (m *mctx) Value(key any) any { return m.base.Value(key) }

// CorrelationID returns the current correlation ID associated with this messaging context.
// The correlation ID is used to track related messages in request-response patterns.
func (m *mctx) CorrelationID() string { return m.cid }

// WithCorrelation creates a new MessagingContext with the specified correlation ID.
// It preserves the base context, server reference, and sender ID while updating the correlation ID.
func (m *mctx) WithCorrelation(id string) MessagingContext {
	return &mctx{base: m.base, s: m.s, fromID: m.fromID, cid: id}
}

// SendTo sends a message to a specific client identified by the 'to' parameter.
// It marshals the payload 'v' to JSON and creates a message envelope with the specified type.
// The message options can be customized using the provided SendOpt functions.
// Returns an error if the client is not found or if JSON marshaling fails.
func (m *mctx) SendTo(to string, typeName string, v any, opts ...SendOpt) error {
	o := &sendOpts{from: m.fromID, cid: m.cid}
	for _, fn := range opts {
		fn(o)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	env := messages.Envelope{
		Type:          typeName,
		Version:       o.version,
		To:            to,
		From:          o.from,
		ID:            uuid.NewString(),
		CorrelationID: o.cid,
		AckRequested:  o.ackRequested,
		Data:          b,
	}
	return m.s.sendEnvelope(to, &env)
}

// Broadcast sends a message to all currently connected clients.
// It marshals the payload 'v' to JSON and creates individual message envelopes for each client.
// The message options can be customized using the provided SendOpt functions.
// Returns the number of clients that successfully received the message.
// If JSON marshaling fails, it logs an error and returns 0.
func (m *mctx) Broadcast(typeName string, v any, opts ...SendOpt) int {
	o := &sendOpts{from: m.fromID, cid: m.cid}
	for _, fn := range opts {
		fn(o)
	}
	b, err := json.Marshal(v)
	if err != nil {
		m.s.Log.Error("broadcast marshal error", "err", err)
		return 0
	}
	count := 0
	for id := range m.s.clients {
		env := messages.Envelope{
			Type:          typeName,
			Version:       o.version,
			To:            id,
			From:          o.from,
			ID:            uuid.NewString(),
			CorrelationID: o.cid,
			AckRequested:  o.ackRequested,
			Data:          b,
		}
		if err := m.s.sendEnvelope(id, &env); err == nil {
			count++
		}
	}
	return count
}
