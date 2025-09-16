package server

import "log/slog"

// Logger defines the logging interface used by the LinkServer.
// It provides methods for different log levels and contextual logging.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	With(args ...any) Logger
}

// slogLogger is an implementation of Logger that wraps Go's standard slog.Logger.
type slogLogger struct{ l *slog.Logger }

// Debug logs a debug-level message with optional key-value pairs.
func (s *slogLogger) Debug(msg string, args ...any) { s.l.Debug(msg, args...) }

// Info logs an info-level message with optional key-value pairs.
func (s *slogLogger) Info(msg string, args ...any) { s.l.Info(msg, args...) }

// Warn logs a warning-level message with optional key-value pairs.
func (s *slogLogger) Warn(msg string, args ...any) { s.l.Warn(msg, args...) }

// Error logs an error-level message with optional key-value pairs.
func (s *slogLogger) Error(msg string, args ...any) { s.l.Error(msg, args...) }

// With returns a new Logger with the given key-value pairs added to all log messages.
func (s *slogLogger) With(args ...any) Logger { return &slogLogger{l: s.l.With(args...)} }
