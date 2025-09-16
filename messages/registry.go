package messages

import (
	"context"
	"link/auth"
)

// RegEntry holds the factory function and handler for a registered message type.
type RegEntry struct {
	New     Factory
	Handler Handler
	Auth    *auth.AuthSpec
}

// MessageSpec describes one message registration.
type MessageSpec struct {
	Type string
	Reg  RegEntry
}

// MessageOption is a function type used to configure message registration.
type MessageOption func(*RegEntry)

// WithAuth enables default authentication for the message type.
// This requires a JWT token using the server's default JWT validator.
func WithAuth() MessageOption {
	return func(entry *RegEntry) {
		entry.Auth = &auth.AuthSpec{Require: true}
	}
}

// WithCustomValidator enables authentication with a custom JWT validator.
// This requires a JWT token and uses the provided validator instead of the server's default.
func WithCustomValidator(validator auth.JWTValidator) MessageOption {
	return func(entry *RegEntry) {
		entry.Auth = &auth.AuthSpec{
			Require:   true,
			Validator: validator,
		}
	}
}

// Message registers a message type with its handler function and optional configuration.
// The typeName should match the message type used in the envelope.
func Message[T any](typeName string, h func(context.Context, *T) error, opts ...MessageOption) MessageSpec {
	entry := RegEntry{
		New: func() MessageType { return new(T) },
		Handler: func(ctx context.Context, msg MessageType) error {
			return h(ctx, msg.(*T))
		},
	}

	for _, opt := range opts {
		opt(&entry)
	}

	return MessageSpec{
		Type: typeName,
		Reg:  entry,
	}
}
