package grpc_client

import (
	"context"
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

// ConnectionPool manages a pool of gRPC connections for performance optimization.
//
// The pool implements a round-robin connection selection strategy with automatic
// connection release. Connections are marked as "in use" temporarily to prevent
// concurrent access conflicts, then automatically released after a short delay.
//
// Thread Safety: All public methods are thread-safe using RWMutex protection.
// The pool supports concurrent access from multiple goroutines.
//
// Lifecycle: Connections are created during pool initialization and replaced
// when they become idle beyond the configured timeout.
type ConnectionPool struct {
	connections []connectionEntry // Pool of gRPC connections
	mu          sync.RWMutex      // Protects concurrent access to pool state
	cfg         *Config           // Configuration for connection management
	nextIndex   int               // Round-robin index for connection selection
	closed      bool              // Indicates if pool is closed
	ctx         context.Context   // Parent context for new connections
}

// connectionEntry represents a single gRPC connection in the pool with metadata
type connectionEntry struct {
	conn          *grpc.ClientConn // The actual gRPC connection
	lastUsed      time.Time        // Timestamp of last usage for idle cleanup
	createdAt     time.Time        // When this connection was created
	failureCount  int              // Number of consecutive failures
	lastFailure   time.Time        // Time of last failure
	healthChecked time.Time        // Last time health was checked
}

// getConnection gets an available connection from the pool with state validation
func (cp *ConnectionPool) getConnection() (*grpc.ClientConn, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if cp.closed {
		return nil, errors.New("connection pool is closed")
	}

	// First pass: Try to find a healthy connection in round-robin order
	for i := 0; i < len(cp.connections); i++ {
		idx := (cp.nextIndex + i) % len(cp.connections)
		entry := &cp.connections[idx]

		if !isConnectionExcessivelyFailing(entry, defaultMaxConnectionFailures, defaultFailureWindow) {
			// Validate connection health
			if !isConnectionHealthy(entry.conn) {
				recordConnectionFailure(entry)
				// Try to replace unhealthy connection
				if newConn, err := createConnection(cp.ctx, cp.cfg); err == nil {
					entry.conn.Close()
					now := time.Now()
					entry.conn = newConn
					entry.lastUsed = now
					entry.createdAt = now
					entry.failureCount = 0
					entry.lastFailure = time.Time{}
					entry.healthChecked = now
				} else {
					// Skip this connection and try next one
					continue
				}
			}

			entry.lastUsed = time.Now()
			entry.healthChecked = time.Now()
			cp.nextIndex = (idx + 1) % len(cp.connections)

			// Record successful connection usage
			recordConnectionSuccess(entry)

			return entry.conn, nil
		}
	}

	// Second pass: Find the best available connection (prioritize by failure rate)
	var bestEntry *connectionEntry
	var bestScore = -1

	for i, entry := range cp.connections {
		// Calculate connection score (lower is better)
		score := entry.failureCount

		// Boost score for recently failed connections (within last minute)
		if time.Since(entry.lastFailure) < time.Minute {
			score += 10
		}

		// Prefer connections that haven't been used recently (for load balancing)
		if time.Since(entry.lastUsed) > time.Minute {
			score -= 5
		}

		if bestEntry == nil || score < bestScore {
			bestEntry = &cp.connections[i]
			bestScore = score
		}
	}

	if bestEntry != nil {
		// Validate the best connection before returning it
		if !isConnectionHealthy(bestEntry.conn) {
			recordConnectionFailure(bestEntry)
			// Try to replace unhealthy connection
			if newConn, err := createConnection(cp.ctx, cp.cfg); err == nil {
				bestEntry.conn.Close()
				now := time.Now()
				bestEntry.conn = newConn
				bestEntry.lastUsed = now
				bestEntry.createdAt = now
				bestEntry.failureCount = 0
				bestEntry.lastFailure = time.Time{}
				bestEntry.healthChecked = now
			}
			// Continue using the connection even if replacement failed
		}

		bestEntry.lastUsed = time.Now()
		bestEntry.healthChecked = time.Now()

		// Record successful connection usage
		recordConnectionSuccess(bestEntry)

		return bestEntry.conn, nil
	}

	return nil, errors.New("no connections available in pool")
}

// cleanupIdle removes connections that have been idle for too long or are unhealthy
func (cp *ConnectionPool) cleanupIdle() {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if cp.closed {
		return
	}

	now := time.Now()

	for i := range cp.connections {
		entry := &cp.connections[i]
		shouldReplace := false

		// Check for idle timeout
		if now.Sub(entry.lastUsed) > cp.cfg.ConnectionIdleTimeout {
			shouldReplace = true
		}

		// Check for excessive failures
		if isConnectionExcessivelyFailing(entry, defaultMaxConnectionFailures, defaultFailureWindow) {
			shouldReplace = true
		}

		// Perform periodic health checks
		interval := cp.cfg.ConnectionHealthcheckInterval
		if interval <= 0 {
			interval = defaultHealthCheckInterval
		}
		if now.Sub(entry.healthChecked) > interval {
			if !isConnectionHealthy(entry.conn) {
				recordConnectionFailure(entry)
				shouldReplace = true
			} else {
				entry.healthChecked = now
				recordConnectionSuccess(entry)
			}
		}

		// Check for connections that are too old
		if cp.cfg.ConnectionMaxLifetime > 0 && now.Sub(entry.createdAt) > cp.cfg.ConnectionMaxLifetime {
			shouldReplace = true
		}

		if shouldReplace {
			if entry.conn != nil {
				entry.conn.Close()
			}

			if newConn, err := createConnection(cp.ctx, cp.cfg); err == nil {
				entry.conn = newConn
				entry.lastUsed = now
				entry.createdAt = now
				entry.failureCount = 0
				entry.lastFailure = time.Time{}
				entry.healthChecked = now
			} else if cp.cfg.Logger != nil {
				cp.cfg.Logger.With("address", cp.cfg.Address).Debugf("failed to refresh idle connection: %v", err)
			}
		}
	}
}

// closeAllConnections closes all connections in the pool
func (cp *ConnectionPool) closeAllConnections() {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	for _, entry := range cp.connections {
		if entry.conn != nil {
			entry.conn.Close()
		}
	}
	cp.connections = nil
	cp.closed = true
}

// isConnectionHealthy validates the connection state and health
func isConnectionHealthy(conn *grpc.ClientConn) bool {
	if conn == nil {
		return false
	}

	state := conn.GetState()
	switch state {
	case connectivity.Ready:
		return true
	case connectivity.Idle:
		return true
	case connectivity.Connecting:
		return true
	case connectivity.TransientFailure:
		return false
	case connectivity.Shutdown:
		return false
	default:
		return false
	}
}

// recordConnectionFailure records a failure for the connection entry with enhanced tracking
func recordConnectionFailure(entry *connectionEntry) {
	if entry == nil {
		return
	}

	now := time.Now()
	entry.failureCount++
	entry.lastFailure = now
}

// recordConnectionSuccess resets failure count for successful connections
func recordConnectionSuccess(entry *connectionEntry) {
	if entry == nil {
		return
	}

	if entry.failureCount > 0 {
		entry.failureCount = 0
		entry.lastFailure = time.Time{}
	}
}

// isConnectionExcessivelyFailing checks if a connection has failed too many times recently
func isConnectionExcessivelyFailing(entry *connectionEntry, maxFailures int, failureWindow time.Duration) bool {
	if entry == nil {
		return true
	}

	if entry.failureCount >= maxFailures {
		if time.Since(entry.lastFailure) <= failureWindow {
			return true
		}
		entry.failureCount = 0
		entry.lastFailure = time.Time{}
	}

	return false
}
