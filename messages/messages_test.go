package messages

import (
	"context"
	"encoding/json"
	"testing"

	"link/auth"
)

// Test message types for testing
type TestMsg struct {
	Text string `json:"text"`
	ID   int    `json:"id"`
}

type AnotherMsg struct {
	Value float64 `json:"value"`
	Name  string  `json:"name"`
}

func TestEnvelope(t *testing.T) {
	t.Run("basic envelope creation", func(t *testing.T) {
		data := json.RawMessage(`{"test": "data"}`)
		env := Envelope{
			Type:    "test",
			Version: "1.0",
			To:      "client-123",
			From:    "client-456",
			ID:      "msg-789",
			Data:    data,
		}

		if env.Type != "test" {
			t.Errorf("expected type 'test', got %q", env.Type)
		}
		if env.Version != "1.0" {
			t.Errorf("expected version '1.0', got %q", env.Version)
		}
		if env.To != "client-123" {
			t.Errorf("expected to 'client-123', got %q", env.To)
		}
		if env.From != "client-456" {
			t.Errorf("expected from 'client-456', got %q", env.From)
		}
		if env.ID != "msg-789" {
			t.Errorf("expected id 'msg-789', got %q", env.ID)
		}
	})

	t.Run("envelope with correlation ID and ack", func(t *testing.T) {
		env := Envelope{
			Type:          "test",
			CorrelationID: "corr-123",
			AckRequested:  true,
			Data:          json.RawMessage(`{}`),
		}

		if env.CorrelationID != "corr-123" {
			t.Errorf("expected correlation ID 'corr-123', got %q", env.CorrelationID)
		}
		if !env.AckRequested {
			t.Error("expected AckRequested to be true")
		}
	})

	t.Run("envelope JSON serialization", func(t *testing.T) {
		env := Envelope{
			Type:    "test",
			Version: "1.0",
			To:      "client-123",
			From:    "client-456",
			ID:      "msg-789",
			Data:    json.RawMessage(`{"hello": "world"}`),
		}

		data, err := json.Marshal(env)
		if err != nil {
			t.Fatalf("failed to marshal envelope: %v", err)
		}

		var unmarshaled Envelope
		if err := json.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("failed to unmarshal envelope: %v", err)
		}

		if unmarshaled.Type != env.Type {
			t.Errorf("expected type %q, got %q", env.Type, unmarshaled.Type)
		}
		if unmarshaled.Version != env.Version {
			t.Errorf("expected version %q, got %q", env.Version, unmarshaled.Version)
		}
		if unmarshaled.To != env.To {
			t.Errorf("expected to %q, got %q", env.To, unmarshaled.To)
		}
		if unmarshaled.From != env.From {
			t.Errorf("expected from %q, got %q", env.From, unmarshaled.From)
		}
		if unmarshaled.ID != env.ID {
			t.Errorf("expected id %q, got %q", env.ID, unmarshaled.ID)
		}
	})

	t.Run("envelope with minimal fields", func(t *testing.T) {
		env := Envelope{
			Type: "minimal",
			Data: json.RawMessage(`{}`),
		}

		data, err := json.Marshal(env)
		if err != nil {
			t.Fatalf("failed to marshal minimal envelope: %v", err)
		}

		var unmarshaled Envelope
		if err := json.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("failed to unmarshal minimal envelope: %v", err)
		}

		if unmarshaled.Type != "minimal" {
			t.Errorf("expected type 'minimal', got %q", unmarshaled.Type)
		}
	})

	t.Run("envelope omitempty behavior", func(t *testing.T) {
		env := Envelope{
			Type: "minimal",
			Data: json.RawMessage(`{}`),
		}

		data, err := json.Marshal(env)
		if err != nil {
			t.Fatalf("failed to marshal envelope: %v", err)
		}

		// Check that empty fields are omitted
		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("failed to unmarshal to map: %v", err)
		}

		if _, exists := raw["version"]; exists {
			t.Error("expected version to be omitted when empty")
		}
		if _, exists := raw["to"]; exists {
			t.Error("expected to to be omitted when empty")
		}
		if _, exists := raw["from"]; exists {
			t.Error("expected from to be omitted when empty")
		}
	})
}

func TestConstants(t *testing.T) {
	t.Run("error type constant", func(t *testing.T) {
		if ErrorType != "error" {
			t.Errorf("expected ErrorType to be 'error', got %q", ErrorType)
		}
	})

	t.Run("ack type constant", func(t *testing.T) {
		if AckType != "ack" {
			t.Errorf("expected AckType to be 'ack', got %q", AckType)
		}
	})
}

func TestMessage(t *testing.T) {
	t.Run("basic message registration", func(t *testing.T) {
		handlerCalled := false
		var receivedMessage *TestMsg

		handler := func(ctx context.Context, msg *TestMsg) error {
			handlerCalled = true
			receivedMessage = msg
			return nil
		}

		spec := Message("test", handler)

		if spec.Type != "test" {
			t.Errorf("expected type 'test', got %q", spec.Type)
		}

		// Test the factory function
		msg := spec.Reg.New()
		if _, ok := msg.(*TestMsg); !ok {
			t.Errorf("expected *TestMsg, got %T", msg)
		}

		// Test the handler function
		testMsg := &TestMsg{Text: "hello", ID: 123}
		ctx := context.Background()
		err := spec.Reg.Handler(ctx, testMsg)
		if err != nil {
			t.Fatalf("handler failed: %v", err)
		}

		if !handlerCalled {
			t.Error("expected handler to be called")
		}
		if receivedMessage == nil {
			t.Error("expected received message to be set")
		}
		if receivedMessage.Text != "hello" {
			t.Errorf("expected text 'hello', got %q", receivedMessage.Text)
		}
		if receivedMessage.ID != 123 {
			t.Errorf("expected ID 123, got %d", receivedMessage.ID)
		}
	})

	t.Run("message with auth option", func(t *testing.T) {
		handler := func(ctx context.Context, msg *TestMsg) error { return nil }
		spec := Message("secure-test", handler, WithAuth())

		if spec.Reg.Auth == nil {
			t.Error("expected auth to be configured")
		}
		if !spec.Reg.Auth.Require {
			t.Error("expected auth to be required")
		}
		if spec.Reg.Auth.Validator != nil {
			t.Error("expected validator to be nil (will be set by server)")
		}
	})

	t.Run("message with custom validator", func(t *testing.T) {
		handler := func(ctx context.Context, msg *TestMsg) error { return nil }
		customValidator := &auth.JwtHS256{Secret: []byte("test")}
		spec := Message("custom-test", handler, WithCustomValidator(customValidator))

		if spec.Reg.Auth == nil {
			t.Error("expected auth to be configured")
		}
		if !spec.Reg.Auth.Require {
			t.Error("expected auth to be required")
		}
		if spec.Reg.Auth.Validator != customValidator {
			t.Error("expected custom validator to be set")
		}
	})

	t.Run("message with multiple options", func(t *testing.T) {
		handler := func(ctx context.Context, msg *TestMsg) error { return nil }
		customValidator := &auth.JwtHS256{Secret: []byte("test")}
		spec := Message("multi-test", handler, WithAuth(), WithCustomValidator(customValidator))

		if spec.Reg.Auth == nil {
			t.Error("expected auth to be configured")
		}
		if !spec.Reg.Auth.Require {
			t.Error("expected auth to be required")
		}
		if spec.Reg.Auth.Validator != customValidator {
			t.Error("expected custom validator to be set (should override WithAuth)")
		}
	})
}

func TestWithAuth(t *testing.T) {
	t.Run("with auth option", func(t *testing.T) {
		entry := RegEntry{}
		option := WithAuth()
		option(&entry)

		if entry.Auth == nil {
			t.Error("expected auth to be set")
		}
		if !entry.Auth.Require {
			t.Error("expected auth to be required")
		}
		if entry.Auth.Validator != nil {
			t.Error("expected validator to be nil")
		}
	})
}

func TestWithCustomValidator(t *testing.T) {
	t.Run("with custom validator option", func(t *testing.T) {
		validator := &auth.JwtHS256{Secret: []byte("test-secret")}
		entry := RegEntry{}
		option := WithCustomValidator(validator)
		option(&entry)

		if entry.Auth == nil {
			t.Error("expected auth to be set")
		}
		if !entry.Auth.Require {
			t.Error("expected auth to be required")
		}
		if entry.Auth.Validator != validator {
			t.Error("expected custom validator to be set")
		}
	})
}

func TestRegEntry(t *testing.T) {
	t.Run("reg entry creation", func(t *testing.T) {
		factory := func() MessageType { return &TestMsg{} }
		handler := func(ctx context.Context, msg MessageType) error { return nil }

		entry := RegEntry{
			New:     factory,
			Handler: handler,
		}

		// Test factory
		msg := entry.New()
		if _, ok := msg.(*TestMsg); !ok {
			t.Errorf("expected *TestMsg, got %T", msg)
		}

		// Test handler
		err := entry.Handler(context.Background(), &TestMsg{})
		if err != nil {
			t.Errorf("unexpected error from handler: %v", err)
		}
	})

	t.Run("reg entry with auth", func(t *testing.T) {
		validator := &auth.JwtHS256{Secret: []byte("test")}
		authSpec := &auth.AuthSpec{
			Require:   true,
			Validator: validator,
		}

		entry := RegEntry{
			New:     func() MessageType { return &TestMsg{} },
			Handler: func(ctx context.Context, msg MessageType) error { return nil },
			Auth:    authSpec,
		}

		if entry.Auth != authSpec {
			t.Error("expected auth spec to match")
		}
		if !entry.Auth.Require {
			t.Error("expected auth to be required")
		}
		if entry.Auth.Validator != validator {
			t.Error("expected validator to match")
		}
	})
}

func TestMessageSpec(t *testing.T) {
	t.Run("message spec creation", func(t *testing.T) {
		entry := RegEntry{
			New:     func() MessageType { return &TestMsg{} },
			Handler: func(ctx context.Context, msg MessageType) error { return nil },
		}

		spec := MessageSpec{
			Type: "test-message",
			Reg:  entry,
		}

		if spec.Type != "test-message" {
			t.Errorf("expected type 'test-message', got %q", spec.Type)
		}
		if spec.Reg.New == nil {
			t.Error("expected New function to be set")
		}
		if spec.Reg.Handler == nil {
			t.Error("expected Handler function to be set")
		}
	})
}

func TestDifferentMessageTypes(t *testing.T) {
	t.Run("multiple message types", func(t *testing.T) {
		var receivedTest *TestMsg
		var receivedAnother *AnotherMsg

		testHandler := func(ctx context.Context, msg *TestMsg) error {
			receivedTest = msg
			return nil
		}

		anotherHandler := func(ctx context.Context, msg *AnotherMsg) error {
			receivedAnother = msg
			return nil
		}

		testSpec := Message("test", testHandler)
		anotherSpec := Message("another", anotherHandler)

		// Test first message type
		testMsg := &TestMsg{Text: "hello", ID: 42}
		err := testSpec.Reg.Handler(context.Background(), testMsg)
		if err != nil {
			t.Fatalf("test handler failed: %v", err)
		}

		if receivedTest == nil {
			t.Error("expected test message to be received")
		}
		if receivedTest.Text != "hello" {
			t.Errorf("expected text 'hello', got %q", receivedTest.Text)
		}

		// Test second message type
		anotherMsg := &AnotherMsg{Value: 3.14, Name: "test"}
		err = anotherSpec.Reg.Handler(context.Background(), anotherMsg)
		if err != nil {
			t.Fatalf("another handler failed: %v", err)
		}

		if receivedAnother == nil {
			t.Error("expected another message to be received")
		}
		if receivedAnother.Value != 3.14 {
			t.Errorf("expected value 3.14, got %f", receivedAnother.Value)
		}
		if receivedAnother.Name != "test" {
			t.Errorf("expected name 'test', got %q", receivedAnother.Name)
		}
	})
}

func TestErrorMessage(t *testing.T) {
	t.Run("error message creation", func(t *testing.T) {
		err := Error{
			Code: 500,
			Msg:  "internal server error",
		}

		if err.Code != 500 {
			t.Errorf("expected code 500, got %d", err.Code)
		}
		if err.Msg != "internal server error" {
			t.Errorf("expected msg 'internal server error', got %q", err.Msg)
		}
	})

	t.Run("error message JSON serialization", func(t *testing.T) {
		err := Error{
			Code: 400,
			Msg:  "bad request",
		}

		data, marshalErr := json.Marshal(err)
		if marshalErr != nil {
			t.Fatalf("failed to marshal error: %v", marshalErr)
		}

		var unmarshaled Error
		if unmarshalErr := json.Unmarshal(data, &unmarshaled); unmarshalErr != nil {
			t.Fatalf("failed to unmarshal error: %v", unmarshalErr)
		}

		if unmarshaled.Code != err.Code {
			t.Errorf("expected code %d, got %d", err.Code, unmarshaled.Code)
		}
		if unmarshaled.Msg != err.Msg {
			t.Errorf("expected msg %q, got %q", err.Msg, unmarshaled.Msg)
		}
	})
}

func TestJoinedMessage(t *testing.T) {
	t.Run("joined message creation", func(t *testing.T) {
		joined := Joined{
			ID: "client-123",
		}

		if joined.ID != "client-123" {
			t.Errorf("expected ID 'client-123', got %q", joined.ID)
		}
	})

	t.Run("joined message JSON serialization", func(t *testing.T) {
		joined := Joined{
			ID: "client-456",
		}

		data, err := json.Marshal(joined)
		if err != nil {
			t.Fatalf("failed to marshal joined: %v", err)
		}

		var unmarshaled Joined
		if err := json.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("failed to unmarshal joined: %v", err)
		}

		if unmarshaled.ID != joined.ID {
			t.Errorf("expected ID %q, got %q", joined.ID, unmarshaled.ID)
		}
	})
}

func TestAckMessage(t *testing.T) {
	t.Run("ack message creation and serialization", func(t *testing.T) {
		ack := Ack{}
		
		// Test that Ack can be marshaled/unmarshaled
		data, err := json.Marshal(ack)
		if err != nil {
			t.Fatalf("failed to marshal ack: %v", err)
		}

		var unmarshaled Ack
		if err := json.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("failed to unmarshal ack: %v", err)
		}
	})
}

func TestMessageOption(t *testing.T) {
	t.Run("message option function type", func(t *testing.T) {
		// Test that we can create and use message option functions
		testOption := func(entry *RegEntry) {
			entry.Auth = &auth.AuthSpec{Require: true}
		}

		entry := RegEntry{}
		testOption(&entry)

		if entry.Auth == nil {
			t.Error("expected auth to be set by option")
		}
		if !entry.Auth.Require {
			t.Error("expected auth to be required")
		}
	})
}