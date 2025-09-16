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
type Client struct {
	ID   string `json:"id"`
	Conn *websocket.Conn

	sendCh    chan []byte
	closeOnce sync.Once

	pingInterval time.Duration
	pingTimeout  time.Duration
	pingHandler  func(appData string) error
	pongHandler  func(appData string) error
}

// NewClient creates a new Client instance with the specified ID, WebSocket connection, and send buffer size.
// Uses default ping settings (30 second interval, 5 second timeout).
func NewClient(id string, conn *websocket.Conn, buf int) *Client {
	return NewClientWithPing(id, conn, buf, 30*time.Second, 5*time.Second, nil, nil)
}

// NewClientWithPing creates a new Client instance with custom ping/pong configuration.
func NewClientWithPing(id string, conn *websocket.Conn, buf int, pingInterval, pingTimeout time.Duration, pingHandler, pongHandler func(string) error) *Client {
	return &Client{
		ID:           id,
		Conn:         conn,
		sendCh:       make(chan []byte, buf),
		pingInterval: pingInterval,
		pingTimeout:  pingTimeout,
		pingHandler:  pingHandler,
		pongHandler:  pongHandler,
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
// It also sends periodic ping messages to keep the connection alive using configured intervals.
func (c *Client) writePump() {
	if c.pingHandler != nil {
		c.Conn.SetPingHandler(c.pingHandler)
	}
	if c.pongHandler != nil {
		c.Conn.SetPongHandler(c.pongHandler)
	}

	if c.pingInterval > 0 {
		pingTimeout := c.pingTimeout
		if pingTimeout == 0 {
			pingTimeout = 5 * time.Second
		}

		t := time.NewTicker(c.pingInterval)
		defer t.Stop()

		for {
			select {
			case msg, ok := <-c.sendCh:
				if !ok {
					_ = c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
					return
				}
				if err := c.Conn.WriteMessage(websocket.TextMessage, msg); err != nil {
					return
				}
			case <-t.C:
				deadline := time.Now().Add(pingTimeout)
				_ = c.Conn.WriteControl(websocket.PingMessage, nil, deadline)
			}
		}
	} else {
		for {
			msg, ok := <-c.sendCh
			if !ok {
				_ = c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
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
