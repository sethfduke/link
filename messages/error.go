package messages

// Error represents an error message that can be sent to clients.
// It contains an error code and a human-readable message.
type Error struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}
