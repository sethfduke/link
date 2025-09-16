package messages

// Joined represents a message sent to clients when they successfully connect to the server.
// It contains the unique client ID that was assigned to them.
type Joined struct {
	ID string `json:"id"`
}