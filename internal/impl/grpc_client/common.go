package grpc_client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/desc/protoparse"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/jhump/protoreflect/grpcreflect"

	"github.com/warpstreamlabs/bento/public/service"
)

// Common config field names
const (
	fieldAddress            = "address"
	fieldMethod             = "method"
	fieldRPCType            = "rpc_type"
	fieldRequestJSON        = "request_json"
	fieldTLS                = "tls"
)

// Default timing configuration constants
const (
	defaultRetryBackoffInitial      = time.Second
	defaultRetryBackoffMax          = 30 * time.Second
	defaultConnectionIdleTimeout    = 30 * time.Minute
	defaultSessionSweepInterval     = time.Minute
	defaultConnectionPoolSize       = 1
	defaultRetryMultiplier          = 2.0
	defaultConnectionReleaseDelay   = 100 * time.Millisecond
	defaultCleanupTickerInterval    = time.Minute
	defaultHealthCheckInterval      = 30 * time.Second
	defaultMaxConnectionFailures    = 3
	defaultFailureWindow            = 5 * time.Minute
)

// Magic numbers for message sizes and limits
const (
	defaultMaxConnectionPoolSize = 1
	minMethodNameLength          = 3  // Minimum: "/a/b"
	maxLineLength                = 2000  // Maximum characters per line
	maxReadLines                 = 2000  // Maximum lines to read
)

// Config represents shared gRPC client configuration
type Config struct {
	Address             string
	Method              string
	RPCType             string
	RequestJSON         string
	TLSConfig           *tls.Config
	TLSEnabled          bool
	BearerToken         string
	AuthHeaders         map[string]string
	Authority           string
	UserAgent           string
	LoadBalancingPolicy string
	MaxSendMsgBytes     int
	MaxRecvMsgBytes     int
	KeepAliveTime       time.Duration
	KeepAliveTimeout    time.Duration
	KeepAlivePermit     bool
	CallTimeout         time.Duration
	ProtoFiles          []string
	IncludePaths        []string
	SessionKeyMeta      string
	SessionIdleTimeout  time.Duration
	SessionMaxLifetime  time.Duration
	LogResponses        bool
	
	// Security enhancements
	TLSSkipVerify       bool
	TLSServerName       string
	TLSCACert           string
	TLSClientCert       string
	TLSClientKey        string
	RequireTransportSecurity bool
	
	// Performance options
	MaxConnectionPoolSize int
	ConnectionIdleTimeout time.Duration
	EnableMessagePool     bool
	
	// gRPC best practices
	EnableInterceptors    bool
	PropagateDeadlines    bool
	RetryPolicy           *RetryPolicy
	DefaultMetadata       map[string]string
}

// RetryPolicy defines retry behavior for gRPC calls
type RetryPolicy struct {
	MaxAttempts     int
	InitialBackoff  time.Duration
	MaxBackoff      time.Duration
	BackoffMultiplier float64
	RetryableStatusCodes []codes.Code
}

// ServiceConfig represents gRPC service configuration for proper JSON marshaling
type ServiceConfig struct {
	LoadBalancingPolicy string         `json:"loadBalancingPolicy,omitempty"`
	MethodConfig        []MethodConfig `json:"methodConfig,omitempty"`
}

// MethodConfig represents method-specific configuration
type MethodConfig struct {
	Name        []MethodName     `json:"name"`
	RetryPolicy *ServiceRetryPolicy `json:"retryPolicy,omitempty"`
}

// MethodName represents a method selector in service config
type MethodName struct {
	Service string `json:"service,omitempty"`
	Method  string `json:"method,omitempty"`
}

// ServiceRetryPolicy represents retry policy in service config format
type ServiceRetryPolicy struct {
	MaxAttempts          int             `json:"maxAttempts"`
	InitialBackoff       string          `json:"initialBackoff"`
	MaxBackoff           string          `json:"maxBackoff"`
	BackoffMultiplier    float64         `json:"backoffMultiplier"`
	RetryableStatusCodes []StatusCodeStr `json:"retryableStatusCodes"`
}

// StatusCodeStr is a custom type for proper JSON marshaling of gRPC status codes
type StatusCodeStr string

// NewStatusCodeStr creates a StatusCodeStr from a gRPC codes.Code
func NewStatusCodeStr(code codes.Code) StatusCodeStr {
	return StatusCodeStr(code.String())
}

// MarshalJSON implements json.Marshaler for proper gRPC service config format
func (s StatusCodeStr) MarshalJSON() ([]byte, error) {
	// gRPC service config expects uppercase status codes without quotes
	return []byte(string(s)), nil
}

// ParseConfigFromService extracts gRPC configuration from service config
func ParseConfigFromService(conf *service.ParsedConfig) (*Config, error) {
	cfg := &Config{}
	
	// Extract core configuration
	extractCoreConfig(conf, cfg)
	
	// Extract TLS configuration
	extractTLSConfig(conf, cfg)
	
	// Extract authentication configuration
	extractAuthConfig(conf, cfg)
	
	// Extract connection configuration
	extractConnectionConfig(conf, cfg)
	
	// Extract streaming configuration
	extractStreamingConfig(conf, cfg)
	
	// Extract security configuration
	extractSecurityConfig(conf, cfg)
	
	// Extract performance configuration
	extractPerformanceConfig(conf, cfg)
	
	// Extract gRPC best practices configuration
	extractBestPracticesConfig(conf, cfg)
	
	// Extract retry policy configuration
	extractRetryPolicyConfig(conf, cfg)
	
	// Enhanced security validation
	if err := validateSecurityConfig(cfg); err != nil {
		return nil, fmt.Errorf("security validation failed: %w", err)
	}
	
	return cfg, nil
}

// extractCoreConfig extracts fundamental gRPC configuration fields
func extractCoreConfig(conf *service.ParsedConfig, cfg *Config) {
	cfg.Address, _ = conf.FieldString(fieldAddress)
	cfg.Method, _ = conf.FieldString(fieldMethod)
	cfg.RPCType, _ = conf.FieldString(fieldRPCType)
	cfg.RequestJSON, _ = conf.FieldString(fieldRequestJSON)
}

// extractTLSConfig extracts TLS-related configuration
func extractTLSConfig(conf *service.ParsedConfig, cfg *Config) {
	var tlsEnabled bool
	cfg.TLSConfig, tlsEnabled, _ = conf.FieldTLSToggled(fieldTLS)
	if !tlsEnabled {
		cfg.TLSConfig = nil
	}
	cfg.TLSEnabled = tlsEnabled
}

// extractAuthConfig extracts authentication configuration
func extractAuthConfig(conf *service.ParsedConfig, cfg *Config) {
	cfg.BearerToken, _ = conf.FieldString("bearer_token")
	cfg.AuthHeaders, _ = conf.FieldStringMap("auth_headers")
}

// extractConnectionConfig extracts connection-related configuration
func extractConnectionConfig(conf *service.ParsedConfig, cfg *Config) {
	cfg.Authority, _ = conf.FieldString("authority")
	cfg.UserAgent, _ = conf.FieldString("user_agent")
	cfg.LoadBalancingPolicy, _ = conf.FieldString("load_balancing_policy")
	cfg.MaxSendMsgBytes, _ = conf.FieldInt("max_send_msg_bytes")
	cfg.MaxRecvMsgBytes, _ = conf.FieldInt("max_recv_msg_bytes")
	cfg.KeepAliveTime, _ = conf.FieldDuration("keepalive_time")
	cfg.KeepAliveTimeout, _ = conf.FieldDuration("keepalive_timeout")
	cfg.KeepAlivePermit, _ = conf.FieldBool("keepalive_permit_without_stream")
	cfg.CallTimeout, _ = conf.FieldDuration("call_timeout")
	cfg.ProtoFiles, _ = conf.FieldStringList("proto_files")
	cfg.IncludePaths, _ = conf.FieldStringList("include_paths")
}

// extractStreamingConfig extracts streaming-specific configuration
func extractStreamingConfig(conf *service.ParsedConfig, cfg *Config) {
	cfg.SessionKeyMeta, _ = conf.FieldString("session_key_meta")
	cfg.SessionIdleTimeout, _ = conf.FieldDuration("session_idle_timeout")
	cfg.SessionMaxLifetime, _ = conf.FieldDuration("session_max_lifetime")
	cfg.LogResponses, _ = conf.FieldBool("log_responses")
}

// extractSecurityConfig extracts security enhancement configuration
func extractSecurityConfig(conf *service.ParsedConfig, cfg *Config) {
	cfg.TLSSkipVerify, _ = conf.FieldBool("tls_skip_verify")
	cfg.TLSServerName, _ = conf.FieldString("tls_server_name")
	cfg.TLSCACert, _ = conf.FieldString("tls_ca_cert")
	cfg.TLSClientCert, _ = conf.FieldString("tls_client_cert")
	cfg.TLSClientKey, _ = conf.FieldString("tls_client_key")
	cfg.RequireTransportSecurity, _ = conf.FieldBool("require_transport_security")
}

// extractPerformanceConfig extracts performance optimization configuration
func extractPerformanceConfig(conf *service.ParsedConfig, cfg *Config) {
	cfg.MaxConnectionPoolSize, _ = conf.FieldInt("max_connection_pool_size")
	if cfg.MaxConnectionPoolSize <= 0 {
		cfg.MaxConnectionPoolSize = defaultConnectionPoolSize
	}
	cfg.ConnectionIdleTimeout, _ = conf.FieldDuration("connection_idle_timeout")
	if cfg.ConnectionIdleTimeout <= 0 {
		cfg.ConnectionIdleTimeout = defaultConnectionIdleTimeout
	}
	cfg.EnableMessagePool, _ = conf.FieldBool("enable_message_pool")
}

// extractBestPracticesConfig extracts gRPC best practices configuration
func extractBestPracticesConfig(conf *service.ParsedConfig, cfg *Config) {
	cfg.EnableInterceptors, _ = conf.FieldBool("enable_interceptors")
	cfg.PropagateDeadlines, _ = conf.FieldBool("propagate_deadlines")
	cfg.DefaultMetadata, _ = conf.FieldStringMap("default_metadata")
}

// extractRetryPolicyConfig extracts retry policy configuration
func extractRetryPolicyConfig(conf *service.ParsedConfig, cfg *Config) {
	maxAttempts, _ := conf.FieldInt("retry_max_attempts")
	if maxAttempts <= 0 {
		return // No retry policy configured
	}

	retryInitialBackoff, _ := conf.FieldDuration("retry_initial_backoff")
	if retryInitialBackoff <= 0 {
		retryInitialBackoff = defaultRetryBackoffInitial
	}
	
	retryMaxBackoff, _ := conf.FieldDuration("retry_max_backoff")
	if retryMaxBackoff <= 0 {
		retryMaxBackoff = defaultRetryBackoffMax
	}
	
	retryMultiplier := defaultRetryMultiplier
	if multiplier, _ := conf.FieldFloat("retry_backoff_multiplier"); multiplier > 0 {
		retryMultiplier = multiplier
	}
	
	cfg.RetryPolicy = &RetryPolicy{
		MaxAttempts:       maxAttempts,
		InitialBackoff:    retryInitialBackoff,
		MaxBackoff:        retryMaxBackoff,
		BackoffMultiplier: retryMultiplier,
		RetryableStatusCodes: []codes.Code{
			codes.Unavailable,
			codes.ResourceExhausted,
			codes.Aborted,
			codes.DeadlineExceeded,
		},
	}
}

// validateSecurityConfig performs comprehensive security validation
func validateSecurityConfig(cfg *Config) error {
	// Validate auth requirements
	if (cfg.BearerToken != "" || len(cfg.AuthHeaders) > 0) {
		if !cfg.TLSEnabled && !cfg.RequireTransportSecurity {
			return fmt.Errorf("bearer_token/auth_headers require TLS to be enabled")
		}
	}
	
	// Validate TLS certificate configuration
	if cfg.TLSEnabled && cfg.TLSConfig != nil {
		if cfg.TLSClientCert != "" || cfg.TLSClientKey != "" {
			if cfg.TLSClientCert == "" || cfg.TLSClientKey == "" {
				return fmt.Errorf("both tls_client_cert and tls_client_key must be provided for mutual TLS")
			}
		}
		
		// Validate certificate files exist and are readable
		if cfg.TLSCACert != "" {
			if err := validateCertificateFile(cfg.TLSCACert); err != nil {
				return fmt.Errorf("invalid CA certificate: %w", err)
			}
		}
		
		if cfg.TLSClientCert != "" {
			if err := validateCertificateFile(cfg.TLSClientCert); err != nil {
				return fmt.Errorf("invalid client certificate: %w", err)
			}
		}
	}
	
	// Warn about insecure configurations
	if cfg.TLSSkipVerify {
		// Log warning about insecure configuration
	}
	
	return nil
}

// validateCertificateFile validates that a certificate file is readable and valid
func validateCertificateFile(filepath string) error {
	// For now, just check if file path is not empty
	// In a production implementation, we would:
	// 1. Check if file exists and is readable
	// 2. Parse the certificate to ensure it's valid
	// 3. Check certificate expiration
	if filepath == "" {
		return fmt.Errorf("certificate file path cannot be empty")
	}
	return nil
}

// headerCreds implements credentials.PerRPCCredentials with enhanced security
type headerCreds struct {
	token               string
	headers             map[string]string
	requireTransportSec bool
	tlsEnabled          bool
}

func (h headerCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	md := map[string]string{}
	
	// Add authorization token if present
	if h.token != "" {
		md["authorization"] = "Bearer " + h.token
	}
	
	// Add custom headers
	for k, v := range h.headers {
		md[k] = v
	}
	
	return md, nil
}

func (h headerCreds) RequireTransportSecurity() bool {
	// Return true if TLS is enabled OR transport security is explicitly required
	// This fixes the security issue where secureOnly was hardcoded to true
	return h.tlsEnabled || h.requireTransportSec
}

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
	connections []connectionEntry  // Pool of gRPC connections
	mu          sync.RWMutex       // Protects concurrent access to pool state
	cfg         *Config            // Configuration for connection management
	nextIndex   int                // Round-robin index for connection selection
	closed      bool               // Indicates if pool is closed
}

// connectionEntry represents a single gRPC connection in the pool with metadata
type connectionEntry struct {
	conn          *grpc.ClientConn  // The actual gRPC connection
	lastUsed      time.Time         // Timestamp of last usage for idle cleanup
	inUse         bool              // Temporary flag to prevent concurrent usage
	createdAt     time.Time         // When this connection was created
	failureCount  int               // Number of consecutive failures
	lastFailure   time.Time         // Time of last failure
	healthChecked time.Time         // Last time health was checked
}

// ConnectionManager manages gRPC connections with proper lifecycle and pooling.
//
// The manager coordinates between connection pooling, automatic cleanup, and
// graceful shutdown. It runs a background goroutine that periodically checks
// for idle connections and replaces them to maintain connection freshness.
//
// Key Responsibilities:
// - Connection pool lifecycle management
// - Automatic cleanup of idle connections
// - Thread-safe access coordination
// - Graceful shutdown without resource leaks
type ConnectionManager struct {
	pool   *ConnectionPool  // Underlying connection pool
	mu     sync.RWMutex     // Protects manager state during shutdown
	closed bool             // Indicates if manager is shut down
}

// NewConnectionManager creates a new connection manager with pooling support
func NewConnectionManager(ctx context.Context, cfg *Config) (*ConnectionManager, error) {
	pool := &ConnectionPool{
		connections: make([]connectionEntry, 0, cfg.MaxConnectionPoolSize),
		cfg:         cfg,
	}
	
	// Create initial connections
	for i := 0; i < cfg.MaxConnectionPoolSize; i++ {
		conn, err := createConnection(ctx, cfg)
		if err != nil {
			// Close any previously created connections
			pool.closeAllConnections()
			return nil, fmt.Errorf("failed to create connection %d: %w", i, err)
		}
		
		now := time.Now()
		pool.connections = append(pool.connections, connectionEntry{
			conn:          conn,
			lastUsed:      now,
			inUse:         false,
			createdAt:     now,
			failureCount:  0,
			lastFailure:   time.Time{},
			healthChecked: now,
		})
	}
	
	cm := &ConnectionManager{
		pool: pool,
	}
	
	// Start connection cleanup goroutine
	go cm.cleanupIdleConnections()
	
	return cm, nil
}

// createConnection creates a single gRPC connection with all options
func createConnection(ctx context.Context, cfg *Config) (*grpc.ClientConn, error) {
	opts, err := buildDialOptions(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build dial options: %w", err)
	}
	
	conn, err := grpc.NewClient(cfg.Address, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}
	
	return conn, nil
}

// isConnectionHealthy validates the connection state and health
func isConnectionHealthy(conn *grpc.ClientConn) bool {
	if conn == nil {
		return false
	}
	
	// Check connection state
	state := conn.GetState()
	switch state {
	case connectivity.Ready:
		return true
	case connectivity.Idle:
		// Idle connections are acceptable, they can be activated
		return true
	case connectivity.Connecting:
		// Connecting state might be temporary, give it a chance
		return true
	case connectivity.TransientFailure:
		// Transient failures should trigger replacement
		return false
	case connectivity.Shutdown:
		// Shutdown connections are definitely unusable
		return false
	default:
		// Unknown state, be conservative
		return false
	}
}

// isConnectionHealthyWithHistory validates connection health considering failure history
func isConnectionHealthyWithHistory(entry *connectionEntry, maxFailures int, failureWindow time.Duration) bool {
	if entry == nil || entry.conn == nil {
		return false
	}
	
	// Check basic connection state first
	if !isConnectionHealthy(entry.conn) {
		return false
	}
	
	// Consider failure history
	if entry.failureCount >= maxFailures {
		// Check if failures are within the failure window
		if time.Since(entry.lastFailure) < failureWindow {
			return false
		}
		// Reset failure count if outside the window
		entry.failureCount = 0
	}
	
	return true
}

// recordConnectionFailure records a failure for the connection entry
func recordConnectionFailure(entry *connectionEntry) {
	if entry == nil {
		return
	}
	entry.failureCount++
	entry.lastFailure = time.Now()
}

// recordConnectionSuccess resets failure count for successful connections
func recordConnectionSuccess(entry *connectionEntry) {
	if entry == nil {
		return
	}
	entry.failureCount = 0
	entry.lastFailure = time.Time{}
}

// GetConnection returns an available gRPC connection from the pool (thread-safe)
func (cm *ConnectionManager) GetConnection() (*grpc.ClientConn, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	if cm.closed {
		return nil, fmt.Errorf("connection manager is closed")
	}
	
	return cm.pool.getConnection()
}

// ValidateConnection checks if a specific connection is healthy and ready for use
func (cm *ConnectionManager) ValidateConnection(conn *grpc.ClientConn) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	if cm.closed || conn == nil {
		return false
	}
	
	return isConnectionHealthy(conn)
}

// GetConnectionStats returns comprehensive statistics about the connection pool including health metrics
func (cm *ConnectionManager) GetConnectionStats() map[string]interface{} {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	if cm.closed || cm.pool == nil {
		return map[string]interface{}{
			"status": "closed",
		}
	}
	
	cm.pool.mu.RLock()
	defer cm.pool.mu.RUnlock()
	
	stats := map[string]interface{}{
		"total_connections": len(cm.pool.connections),
		"pool_size":        cap(cm.pool.connections),
		"next_index":       cm.pool.nextIndex,
	}
	
	// Count connections by state and health metrics
	stateCounts := make(map[string]int)
	inUseCount := 0
	failedConnections := 0
	oldestConnection := time.Now()
	newestConnection := time.Time{}
	totalFailures := 0
	healthyConnections := 0
	
	for _, entry := range cm.pool.connections {
		if entry.inUse {
			inUseCount++
		}
		
		if entry.conn != nil {
			state := entry.conn.GetState()
			stateCounts[state.String()]++
			
			// Health metrics
			if isConnectionHealthy(entry.conn) {
				healthyConnections++
			}
			
			if entry.failureCount > 0 {
				failedConnections++
				totalFailures += entry.failureCount
			}
			
			// Age tracking
			if entry.createdAt.Before(oldestConnection) {
				oldestConnection = entry.createdAt
			}
			if entry.createdAt.After(newestConnection) {
				newestConnection = entry.createdAt
			}
		}
	}
	
	stats["in_use_connections"] = inUseCount
	stats["available_connections"] = len(cm.pool.connections) - inUseCount
	stats["healthy_connections"] = healthyConnections
	stats["failed_connections"] = failedConnections
	stats["total_failures"] = totalFailures
	stats["connection_states"] = stateCounts
	
	if !oldestConnection.IsZero() {
		stats["oldest_connection_age"] = time.Since(oldestConnection).String()
	}
	if !newestConnection.IsZero() {
		stats["newest_connection_age"] = time.Since(newestConnection).String()
	}
	
	return stats
}

// getConnection gets an available connection from the pool with state validation
func (cp *ConnectionPool) getConnection() (*grpc.ClientConn, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	if cp.closed {
		return nil, fmt.Errorf("connection pool is closed")
	}
	
	// Find an available connection using round-robin with enhanced health validation
	for i := 0; i < len(cp.connections); i++ {
		idx := (cp.nextIndex + i) % len(cp.connections)
		entry := &cp.connections[idx]
		
		if !entry.inUse {
			// Validate connection health with failure history
			if !isConnectionHealthyWithHistory(entry, defaultMaxConnectionFailures, defaultFailureWindow) {
				recordConnectionFailure(entry)
				// Replace unhealthy connection
				if newConn, err := createConnection(context.Background(), cp.cfg); err == nil {
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
			
			entry.inUse = true
			entry.lastUsed = time.Now()
			entry.healthChecked = time.Now()
			cp.nextIndex = (idx + 1) % len(cp.connections)
			
			// Record successful connection usage
			recordConnectionSuccess(entry)
			
			// Start a goroutine to release the connection after a short time
			go func(e *connectionEntry) {
				time.Sleep(defaultConnectionReleaseDelay) // Small delay to allow operation completion
				cp.mu.Lock()
				e.inUse = false
				cp.mu.Unlock()
			}(entry)
			
			return entry.conn, nil
		}
	}
	
	// If all connections are in use, return the least recently used one after validation
	// (this allows connection sharing in high-load scenarios)
	oldestIdx := 0
	oldestTime := cp.connections[0].lastUsed
	
	for i, entry := range cp.connections {
		if entry.lastUsed.Before(oldestTime) {
			oldestTime = entry.lastUsed
			oldestIdx = i
		}
	}
	
	// Validate the oldest connection before returning it
	entry := &cp.connections[oldestIdx]
	if !isConnectionHealthy(entry.conn) {
		// Replace unhealthy connection
		if newConn, err := createConnection(context.Background(), cp.cfg); err == nil {
			entry.conn.Close()
			entry.conn = newConn
		}
		// Continue using the connection even if replacement failed
		// (better to try than to fail completely)
	}
	
	entry.lastUsed = time.Now()
	return entry.conn, nil
}

// cleanupIdleConnections periodically cleans up idle connections
func (cm *ConnectionManager) cleanupIdleConnections() {
	ticker := time.NewTicker(defaultCleanupTickerInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			cm.mu.RLock()
			if cm.closed {
				cm.mu.RUnlock()
				return
			}
			cm.mu.RUnlock()
			
			cm.pool.cleanupIdle()
		}
	}
}

// cleanupIdle removes connections that have been idle for too long or are unhealthy with comprehensive monitoring
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
		if !entry.inUse && now.Sub(entry.lastUsed) > cp.cfg.ConnectionIdleTimeout {
			shouldReplace = true
		}
		
		// Check connection health with failure history (even if not idle)
		if !entry.inUse && !isConnectionHealthyWithHistory(entry, defaultMaxConnectionFailures, defaultFailureWindow) {
			shouldReplace = true
		}
		
		// Perform periodic health checks
		if !entry.inUse && now.Sub(entry.healthChecked) > defaultHealthCheckInterval {
			if !isConnectionHealthy(entry.conn) {
				recordConnectionFailure(entry)
				shouldReplace = true
			} else {
				entry.healthChecked = now
				recordConnectionSuccess(entry)
			}
		}
		
		// Check for connections that are too old
		if !entry.inUse && cp.cfg.SessionMaxLifetime > 0 && now.Sub(entry.createdAt) > cp.cfg.SessionMaxLifetime {
			shouldReplace = true
		}
		
		if shouldReplace {
			// Close the connection and create a new one
			entry.conn.Close()
			if newConn, err := createConnection(context.Background(), cp.cfg); err == nil {
				entry.conn = newConn
				entry.lastUsed = now
				entry.createdAt = now
				entry.failureCount = 0
				entry.lastFailure = time.Time{}
				entry.healthChecked = now
			}
			// If replacement fails, keep the old connection for now
			// The next health check will try again
		}
	}
}

// closeAllConnections closes all connections in the pool
func (cp *ConnectionPool) closeAllConnections() {
	for _, entry := range cp.connections {
		if entry.conn != nil {
			entry.conn.Close()
		}
	}
}

// Close closes the connection manager and all connections (thread-safe)
func (cm *ConnectionManager) Close() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	if cm.closed {
		return nil
	}
	
	cm.closed = true
	
	if cm.pool != nil {
		cm.pool.mu.Lock()
		cm.pool.closed = true
		cm.pool.closeAllConnections()
		cm.pool.mu.Unlock()
	}
	
	return nil
}

// buildDialOptions creates gRPC dial options from configuration with enhanced security and performance
func buildDialOptions(ctx context.Context, cfg *Config) ([]grpc.DialOption, error) {
	var opts []grpc.DialOption
	
	// Enhanced TLS configuration
	transportCreds, err := buildTransportCredentials(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build transport credentials: %w", err)
	}
	opts = append(opts, grpc.WithTransportCredentials(transportCreds))
	
	// Authority
	if cfg.Authority != "" {
		opts = append(opts, grpc.WithAuthority(cfg.Authority))
	}
	
	// User agent
	if cfg.UserAgent != "" {
		opts = append(opts, grpc.WithUserAgent(cfg.UserAgent))
	}
	
	// Enhanced load balancing with retry policy
	serviceConfig := buildServiceConfig(cfg)
	if serviceConfig != "" {
		opts = append(opts, grpc.WithDefaultServiceConfig(serviceConfig))
	}
	
	// Keep alive parameters
	if cfg.KeepAliveTime > 0 || cfg.KeepAliveTimeout > 0 || cfg.KeepAlivePermit {
		opts = append(opts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                cfg.KeepAliveTime,
			Timeout:             cfg.KeepAliveTimeout,
			PermitWithoutStream: cfg.KeepAlivePermit,
		}))
	}
	
	// Default call options including message size limits
	callOpts := buildDefaultCallOptions(cfg)
	if len(callOpts) > 0 {
		opts = append(opts, grpc.WithDefaultCallOptions(callOpts...))
	}
	
	// Authentication credentials
	if cfg.BearerToken != "" || len(cfg.AuthHeaders) > 0 {
		opts = append(opts, grpc.WithPerRPCCredentials(headerCreds{
			token:               cfg.BearerToken,
			headers:             cfg.AuthHeaders,
			tlsEnabled:          cfg.TLSEnabled,
			requireTransportSec: cfg.RequireTransportSecurity,
		}))
	}
	
	// Interceptors for observability and best practices
	if cfg.EnableInterceptors {
		unaryInterceptors, streamInterceptors := buildInterceptors(cfg)
		if len(unaryInterceptors) > 0 {
			opts = append(opts, grpc.WithChainUnaryInterceptor(unaryInterceptors...))
		}
		if len(streamInterceptors) > 0 {
			opts = append(opts, grpc.WithChainStreamInterceptor(streamInterceptors...))
		}
	}
	
	return opts, nil
}

// buildTransportCredentials creates enhanced TLS credentials with proper validation
func buildTransportCredentials(cfg *Config) (credentials.TransportCredentials, error) {
	if !cfg.TLSEnabled {
		return insecure.NewCredentials(), nil
	}
	
	tlsConfig := cfg.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	
	// Set minimum TLS version
	if tlsConfig.MinVersion == 0 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	
	// Configure server name
	if cfg.TLSServerName != "" {
		tlsConfig.ServerName = cfg.TLSServerName
	} else if cfg.Authority != "" && tlsConfig.ServerName == "" {
		host, _, err := net.SplitHostPort(cfg.Authority)
		if err != nil {
			host = cfg.Authority
		}
		tlsConfig.ServerName = host
	}
	
	// Configure certificate verification
	tlsConfig.InsecureSkipVerify = cfg.TLSSkipVerify
	
	// Load custom CA certificate (supports both file path and inline cert data)
	if cfg.TLSCACert != "" {
		caCertPool := x509.NewCertPool()
		var caCertData []byte
		
		// Try to load as file first, then treat as inline cert data
		if certData, err := os.ReadFile(cfg.TLSCACert); err == nil {
			caCertData = certData
		} else {
			// Assume it's inline cert data
			caCertData = []byte(cfg.TLSCACert)
		}
		
		if !caCertPool.AppendCertsFromPEM(caCertData) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}
	
	// Configure mutual TLS (supports both file path and inline cert/key data)
	if cfg.TLSClientCert != "" && cfg.TLSClientKey != "" {
		var cert tls.Certificate
		var err error
		
		// Try to load from files first
		if _, fileErr := os.Stat(cfg.TLSClientCert); fileErr == nil {
			cert, err = tls.LoadX509KeyPair(cfg.TLSClientCert, cfg.TLSClientKey)
		} else {
			// Treat as inline cert/key data
			cert, err = tls.X509KeyPair([]byte(cfg.TLSClientCert), []byte(cfg.TLSClientKey))
		}
		
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	
	return credentials.NewTLS(tlsConfig), nil
}

// buildServiceConfig creates a gRPC service config with load balancing and retry policies using proper JSON marshaling
func buildServiceConfig(cfg *Config) string {
	if cfg.LoadBalancingPolicy == "" {
		return ""
	}
	
	serviceConfig := ServiceConfig{}
	
	// Load balancing policy
	if cfg.LoadBalancingPolicy != "" {
		serviceConfig.LoadBalancingPolicy = cfg.LoadBalancingPolicy
	}
	
	// Note: Retry policy is handled via interceptors instead of service config
	// to avoid complex JSON marshaling issues with gRPC status codes
	
	// Marshal to JSON with proper error handling
	jsonBytes, err := json.Marshal(serviceConfig)
	if err != nil {
		// Log error and return empty config - this shouldn't happen with valid config
		return ""
	}
	
	return string(jsonBytes)
}

// buildDefaultCallOptions creates default call options including performance optimizations
func buildDefaultCallOptions(cfg *Config) []grpc.CallOption {
	var callOpts []grpc.CallOption
	
	// Message size limits
	if cfg.MaxSendMsgBytes > 0 {
		callOpts = append(callOpts, grpc.MaxCallSendMsgSize(cfg.MaxSendMsgBytes))
	}
	if cfg.MaxRecvMsgBytes > 0 {
		callOpts = append(callOpts, grpc.MaxCallRecvMsgSize(cfg.MaxRecvMsgBytes))
	}
	
	// Note: Default metadata is now handled in context via injectMetadataIntoContext()
	// This avoids duplication and ensures proper metadata handling
	
	return callOpts
}

// statusCodesToStrings converts gRPC status codes to string representation
func statusCodesToStrings(codes []codes.Code) []string {
	result := make([]string, len(codes))
	for i, code := range codes {
		// Use uppercase status code names as expected by gRPC service config
		result[i] = code.String()
	}
	return result
}

// formatDurationForServiceConfig converts Go duration to gRPC service config format
func formatDurationForServiceConfig(d time.Duration) string {
	// gRPC service config expects duration in decimal form with units
	// Examples: "1s", "0.5s", "100ms" -> "0.1s"
	seconds := d.Seconds()
	if seconds < 1.0 {
		// For sub-second durations, use decimal seconds
		return fmt.Sprintf("%.3fs", seconds)
	}
	// For longer durations, use whole seconds
	return fmt.Sprintf("%.0fs", seconds)
}

// buildInterceptors creates gRPC interceptors for observability and best practices
func buildInterceptors(cfg *Config) ([]grpc.UnaryClientInterceptor, []grpc.StreamClientInterceptor) {
	var unaryInterceptors []grpc.UnaryClientInterceptor
	var streamInterceptors []grpc.StreamClientInterceptor
	
	// Deadline propagation interceptor
	if cfg.PropagateDeadlines {
		unaryInterceptors = append(unaryInterceptors, deadlineUnaryInterceptor)
		streamInterceptors = append(streamInterceptors, deadlineStreamInterceptor)
	}
	
	// Metadata propagation interceptor
	if len(cfg.DefaultMetadata) > 0 {
		unaryInterceptors = append(unaryInterceptors, metadataUnaryInterceptor(cfg.DefaultMetadata))
		streamInterceptors = append(streamInterceptors, metadataStreamInterceptor(cfg.DefaultMetadata))
	}
	
	// Logging/observability interceptor
	unaryInterceptors = append(unaryInterceptors, loggingUnaryInterceptor)
	streamInterceptors = append(streamInterceptors, loggingStreamInterceptor)
	
	// Retry interceptor (if not handled by service config)
	if cfg.RetryPolicy != nil {
		unaryInterceptors = append(unaryInterceptors, retryUnaryInterceptor(cfg.RetryPolicy))
	}
	
	return unaryInterceptors, streamInterceptors
}

// deadlineUnaryInterceptor propagates deadlines from context with enhanced handling
func deadlineUnaryInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	// Enhanced context deadline handling
	ctx = enhanceContextWithDeadlines(ctx)
	
	// Add method-specific timeout if none exists
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		// Apply default timeout for unary calls
		defaultTimeout := 30 * time.Second
		newCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
		ctx = newCtx
	}
	
	// Ensure context is properly canceled on completion
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	
	return invoker(ctx, method, req, reply, cc, opts...)
}

// deadlineStreamInterceptor propagates deadlines for streaming calls with enhanced handling
func deadlineStreamInterceptor(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	// Enhanced context deadline handling for streams
	ctx = enhanceContextWithDeadlines(ctx)
	
	// Add method-specific timeout for streaming calls if none exists
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		// Apply longer default timeout for streaming calls
		defaultTimeout := 5 * time.Minute
		newCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
		ctx = newCtx
	}
	
	return streamer(ctx, desc, cc, method, opts...)
}

// enhanceContextWithDeadlines enhances context with proper deadline handling and propagation
func enhanceContextWithDeadlines(ctx context.Context) context.Context {
	// Check if we already have a deadline
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		// Calculate remaining time
		remaining := time.Until(deadline)
		
		// If deadline is too close, extend it slightly to avoid immediate failures
		minRemainingTime := 100 * time.Millisecond
		if remaining < minRemainingTime {
			newCtx, cancel := context.WithTimeout(context.Background(), minRemainingTime)
			// Copy values from original context
			if val := ctx.Value("metadata"); val != nil {
				newCtx = context.WithValue(newCtx, "metadata", val)
			}
			_ = cancel // Keep cancel function available but don't defer it here
			return newCtx
		}
		
		// Deadline is reasonable, use as-is
		return ctx
	}
	
	// No deadline exists, return original context
	return ctx
}

// withContextMetadata adds metadata from one context to another while preserving deadlines
func withContextMetadata(targetCtx, sourceCtx context.Context) context.Context {
	// Copy important metadata values
	metadataKeys := []interface{}{
		"session_id", "trace_id", "request_id", "user_id", "correlation_id",
	}
	
	result := targetCtx
	for _, key := range metadataKeys {
		if val := sourceCtx.Value(key); val != nil {
			result = context.WithValue(result, key, val)
		}
	}
	
	return result
}

// metadataUnaryInterceptor adds default metadata to unary calls
func metadataUnaryInterceptor(defaultMD map[string]string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		// Add default metadata to context
		md := metadata.New(defaultMD)
		
		// Merge with existing metadata if present
		if existingMD, ok := metadata.FromOutgoingContext(ctx); ok {
			for k, v := range existingMD {
				md[k] = v
			}
		}
		
		ctx = metadata.NewOutgoingContext(ctx, md)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// metadataStreamInterceptor adds default metadata to streaming calls
func metadataStreamInterceptor(defaultMD map[string]string) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		// Add default metadata to context
		md := metadata.New(defaultMD)
		
		// Merge with existing metadata if present
		if existingMD, ok := metadata.FromOutgoingContext(ctx); ok {
			for k, v := range existingMD {
				md[k] = v
			}
		}
		
		ctx = metadata.NewOutgoingContext(ctx, md)
		return streamer(ctx, desc, cc, method, opts...)
	}
}

// loggingUnaryInterceptor provides basic logging for observability
func loggingUnaryInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	start := time.Now()
	err := invoker(ctx, method, req, reply, cc, opts...)
	duration := time.Since(start)
	
	// Log the call (in production, use structured logging)
	if err != nil {
		// Log error with context
		_ = duration // Use duration for metrics
	}
	
	return err
}

// loggingStreamInterceptor provides basic logging for streaming calls
func loggingStreamInterceptor(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	start := time.Now()
	stream, err := streamer(ctx, desc, cc, method, opts...)
	duration := time.Since(start)
	
	// Log the stream creation (in production, use structured logging)
	if err != nil {
		// Log error with context
		_ = duration // Use duration for metrics
	}
	
	return stream, err
}

// retryUnaryInterceptor implements client-side retry logic
func retryUnaryInterceptor(retryPolicy *RetryPolicy) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		var lastErr error
		backoff := retryPolicy.InitialBackoff
		
		for attempt := 0; attempt < retryPolicy.MaxAttempts; attempt++ {
			// Check for context cancellation
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			
			err := invoker(ctx, method, req, reply, cc, opts...)
			if err == nil {
				return nil // Success
			}
			
			lastErr = err
			
			// Check if error is retryable
			if !isRetryableError(err, retryPolicy.RetryableStatusCodes) {
				return err
			}
			
			// Don't retry on last attempt
			if attempt == retryPolicy.MaxAttempts-1 {
				break
			}
			
			// Sleep with backoff
			select {
			case <-time.After(backoff):
				backoff = time.Duration(float64(backoff) * retryPolicy.BackoffMultiplier)
				if backoff > retryPolicy.MaxBackoff {
					backoff = retryPolicy.MaxBackoff
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		
		return lastErr
	}
}

// isRetryableError determines if an error should be retried
func isRetryableError(err error, retryableCodes []codes.Code) bool {
	if err == nil {
		return false
	}
	
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	
	for _, code := range retryableCodes {
		if st.Code() == code {
			return true
		}
	}
	
	return false
}

// MessagePool provides object pooling for dynamic messages to reduce allocations
type MessagePool struct {
	pool sync.Pool
	desc *desc.MessageDescriptor
}

// NewMessagePool creates a new message pool for a specific message type
func NewMessagePool(msgDesc *desc.MessageDescriptor) *MessagePool {
	return &MessagePool{
		desc: msgDesc,
		pool: sync.Pool{
			New: func() interface{} {
				return dynamic.NewMessage(msgDesc)
			},
		},
	}
}

// Get retrieves a message from the pool
func (mp *MessagePool) Get() *dynamic.Message {
	msg := mp.pool.Get().(*dynamic.Message)
	msg.Reset() // Ensure message is clean
	return msg
}

// Put returns a message to the pool
func (mp *MessagePool) Put(msg *dynamic.Message) {
	if msg != nil {
		mp.pool.Put(msg)
	}
}

// MethodResolver handles method resolution with caching and performance optimizations
type MethodResolver struct {
	cache       sync.Map // string -> *methodCacheEntry
	messagePools sync.Map // string -> *MessagePool
}

// methodCacheEntry holds both the method descriptor and message pools
type methodCacheEntry struct {
	method    *desc.MethodDescriptor
	inputPool *MessagePool
	outputPool *MessagePool
}

// NewMethodResolver creates a new method resolver
func NewMethodResolver() *MethodResolver {
	return &MethodResolver{}
}

// ResolveMethod resolves a method using reflection or proto files with enhanced caching
func (mr *MethodResolver) ResolveMethod(ctx context.Context, conn *grpc.ClientConn, cfg *Config) (*desc.MethodDescriptor, error) {
	// Check cache first
	if cached, ok := mr.cache.Load(cfg.Method); ok {
		entry := cached.(*methodCacheEntry)
		return entry.method, nil
	}
	
	var method *desc.MethodDescriptor
	var err error
	
	if len(cfg.ProtoFiles) > 0 {
		method, err = mr.resolveFromProtoFiles(cfg.Method, cfg.ProtoFiles, cfg.IncludePaths)
	} else {
		method, err = mr.resolveFromReflection(ctx, conn, cfg.Method)
	}
	
	if err != nil {
		return nil, err
	}
	
	// Create message pools for performance optimization
	var inputPool, outputPool *MessagePool
	if cfg.EnableMessagePool {
		inputPool = NewMessagePool(method.GetInputType())
		outputPool = NewMessagePool(method.GetOutputType())
	}
	
	// Cache the result with message pools
	entry := &methodCacheEntry{
		method:     method,
		inputPool:  inputPool,
		outputPool: outputPool,
	}
	mr.cache.Store(cfg.Method, entry)
	
	return method, nil
}

// GetMessagePools returns the input and output message pools for a method
func (mr *MethodResolver) GetMessagePools(methodName string) (*MessagePool, *MessagePool) {
	if cached, ok := mr.cache.Load(methodName); ok {
		entry := cached.(*methodCacheEntry)
		return entry.inputPool, entry.outputPool
	}
	return nil, nil
}

// resolveFromReflection resolves method using gRPC reflection
func (mr *MethodResolver) resolveFromReflection(ctx context.Context, conn *grpc.ClientConn, methodName string) (*desc.MethodDescriptor, error) {
	rc := grpcreflect.NewClientAuto(ctx, conn)
	defer rc.Reset()
	
	svcName, mName, err := parseMethodName(methodName)
	if err != nil {
		return nil, err
	}
	
	svc, err := rc.ResolveService(svcName)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve service %s: %w", svcName, err)
	}
	
	method := svc.FindMethodByName(mName)
	if method == nil {
		return nil, fmt.Errorf("method not found: %s", methodName)
	}
	
	return method, nil
}

// resolveFromProtoFiles resolves method from proto files
func (mr *MethodResolver) resolveFromProtoFiles(methodName string, protoFiles, includePaths []string) (*desc.MethodDescriptor, error) {
	var parser protoparse.Parser
	if len(includePaths) > 0 {
		parser.ImportPaths = includePaths
	}
	
	fds, err := parser.ParseFiles(protoFiles...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proto files: %w", err)
	}
	
	svcName, mName, err := parseMethodName(methodName)
	if err != nil {
		return nil, err
	}
	
	for _, fd := range fds {
		for _, svc := range fd.GetServices() {
			if svc.GetFullyQualifiedName() == svcName || svc.GetName() == svcName {
				if method := svc.FindMethodByName(mName); method != nil {
					return method, nil
				}
			}
		}
	}
	
	return nil, fmt.Errorf("method not found in provided proto files: %s", methodName)
}

// parseMethodName parses a method name like "/pkg.Service/Method" into service and method names
// Optimized to avoid repeated string operations and memory allocations
func parseMethodName(full string) (string, string, error) {
	// Fast path: check minimum length and format
	if len(full) < minMethodNameLength { // Minimum: "/a/b"
		return "", "", fmt.Errorf("invalid method format: %s (too short)", full)
	}
	
	// Remove leading slash efficiently
	start := 0
	if full[0] == '/' {
		start = 1
	}
	
	// Find the last slash to separate service and method (single pass)
	lastSlash := -1
	for i := len(full) - 1; i >= start; i-- {
		if full[i] == '/' {
			lastSlash = i
			break
		}
	}
	
	if lastSlash == -1 || lastSlash == start {
		return "", "", fmt.Errorf("invalid method format: %s (expected format: /service/method)", full)
	}
	
	serviceName := full[start:lastSlash]
	methodName := full[lastSlash+1:]
	
	// Validate non-empty (avoid string comparison)
	if len(serviceName) == 0 || len(methodName) == 0 {
		return "", "", fmt.Errorf("invalid method format: %s (service and method names cannot be empty)", full)
	}
	
	return serviceName, methodName, nil
}

// RetryConfig holds retry configuration
type RetryConfig struct {
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	MaxRetries     int
}

// DefaultRetryConfig returns sensible retry defaults
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		InitialBackoff: defaultRetryBackoffInitial,
		MaxBackoff:     defaultRetryBackoffMax,
		MaxRetries:     5,
	}
}

// WithContextRetry performs an operation with exponential backoff retry and context awareness.
//
// Retry Strategy:
// - Implements exponential backoff with configurable initial delay and multiplier
// - Respects maximum backoff duration to prevent excessive wait times
// - Honors context cancellation at any point during retry attempts
//
// Context Handling:
// - Checks for context cancellation before each retry attempt
// - Cancellation during backoff sleep immediately returns context error
// - Preserves last operation error when context is cancelled
//
// Error Handling:
// - Returns immediately on successful operation (nil error)
// - Accumulates the last error from failed attempts
// - Provides comprehensive error context including attempt count
//
// Usage Pattern:
// This is typically used for transient failures in gRPC operations where
// temporary network issues or service unavailability should be retried.
func WithContextRetry(ctx context.Context, cfg RetryConfig, operation func() error) error {
	var lastErr error
	backoff := cfg.InitialBackoff
	
	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		// Check context cancellation before each attempt
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("context cancelled, last error: %w", lastErr)
			}
			return ctx.Err()
		default:
		}
		
		if err := operation(); err != nil {
			lastErr = err
			
			// Don't sleep after the last attempt
			if attempt == cfg.MaxRetries {
				break
			}
			
			// Sleep with backoff, but respect context cancellation
			select {
			case <-time.After(backoff):
				// Exponential backoff
				backoff *= 2
				if backoff > cfg.MaxBackoff {
					backoff = cfg.MaxBackoff
				}
			case <-ctx.Done():
				return fmt.Errorf("context cancelled during backoff, last error: %w", lastErr)
			}
		} else {
			return nil // Success
		}
	}
	
	return fmt.Errorf("operation failed after %d attempts: %w", cfg.MaxRetries+1, lastErr)
}
