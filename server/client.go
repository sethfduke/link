package server

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/sethfduke/link/messages"

	"github.com/gorilla/websocket"
)

// ErrSendBufferFull is returned when a client's send buffer is at capacity.
var ErrSendBufferFull = errors.New("client send buffer full")

// Client represents a WebSocket client connection with message buffering capabilities.
// It manages the client's unique ID, WebSocket connection, and outbound message queue.
// Uses standard WebSocket control ping/pong functionality for connection keep-alive.
type Client struct {
	ID   string `json:"id"`
	Conn *websocket.Conn

	sendCh    chan []byte
	closeOnce sync.Once

	pingInterval time.Duration
	pingTimeout  time.Duration
}

// NewClient creates a new Client instance with the specified ID, WebSocket connection, and send buffer size.
// Uses default ping settings (30 second interval, 5 second timeout).
func NewClient(id string, conn *websocket.Conn, buf int) *Client {
	return NewClientWithPing(id, conn, buf, 30*time.Second, 5*time.Second)
}

// NewClientWithPing creates a new Client instance with custom ping/pong configuration.
// Uses standard WebSocket control ping/pong functionality for connection keep-alive.
func NewClientWithPing(id string, conn *websocket.Conn, buf int, pingInterval, pingTimeout time.Duration) *Client {
	return &Client{
		ID:           id,
		Conn:         conn,
		sendCh:       make(chan []byte, buf),
		pingInterval: pingInterval,
		pingTimeout:  pingTimeout,
	}
}

// Send queues a message to be sent to the client's WebSocket connection.
// Returns ErrSendBufferFull if the send buffer is at capacity.
func (c *Client) Send(msgType, version string, payload any) error {
	env := messages.Envelope{Type: msgType, Version: version, Data: mustJSON(payload)}
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	select {
	case c.sendCh <- b:
		return nil
	default:
		return ErrSendBufferFull
	}
}

// writePump handles sending messages from the send channel to the WebSocket connection.
// It uses Gorilla WebSocket's built-in ping/pong functionality for connection keep-alive.
func (c *Client) writePump() {
	if c.pingInterval > 0 {
		t := time.NewTicker(c.pingInterval)
		defer t.Stop()

		for {
			select {
			case msg, ok := <-c.sendCh:
				if !ok {
					_ = c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
					return
				}
				_ = c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := c.Conn.WriteMessage(websocket.TextMessage, msg); err != nil {
					return
				}
			case <-t.C:
				_ = c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	} else {
		for {
			msg, ok := <-c.sendCh
			if !ok {
				_ = c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			_ = c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.Conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		}
	}
}

// SendEnvelope queues a pre-constructed message envelope to be sent to the client.
// Returns ErrSendBufferFull if the send buffer is at capacity.
func (c *Client) SendEnvelope(e *messages.Envelope) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	select {
	case c.sendCh <- b:
		return nil
	default:
		return ErrSendBufferFull
	}
}

// Close safely closes the client's send channel and WebSocket connection.
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		close(c.sendCh)
		_ = c.Conn.Close()
	})
}
