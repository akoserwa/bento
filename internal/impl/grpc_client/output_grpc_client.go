package grpc_client

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/jhump/protoreflect/dynamic/grpcdynamic"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	structpb "google.golang.org/protobuf/types/known/structpb"

	"github.com/warpstreamlabs/bento/public/service"
)

func genericOutputSpec() *service.ConfigSpec {
	return service.NewConfigSpec().
		Version("1.11.0").
		Categories("Services").
		Summary("Call an arbitrary gRPC method (unary, client_stream, or bidi) using reflection to resolve types with enhanced security and performance").
		Field(service.NewStringField(fieldAddress).Default("127.0.0.1:50051")).
		Field(service.NewStringField(fieldMethod).Description("Full method name, e.g. /pkg.Service/Method")).
		Field(service.NewStringField(fieldRPCType).Default("unary").Description("One of: unary, client_stream, bidi")).
		Field(service.NewTLSToggledField(fieldTLS)).
		Field(service.NewStringField("bearer_token").Secret().Optional()).
		Field(service.NewStringMapField("auth_headers").Optional()).
		Field(service.NewStringField("authority").Optional()).
		Field(service.NewStringField("user_agent").Optional()).
		Field(service.NewStringField("load_balancing_policy").Default("pick_first")).
		Field(service.NewIntField("max_send_msg_bytes").Default(0)).
		Field(service.NewIntField("max_recv_msg_bytes").Default(0)).
		Field(service.NewDurationField("keepalive_time").Default("0s")).
		Field(service.NewDurationField("keepalive_timeout").Default("0s")).
		Field(service.NewBoolField("keepalive_permit_without_stream").Default(false)).
		Field(service.NewDurationField("call_timeout").Default("0s")).
		Field(service.NewStringListField("proto_files").Optional()).
		Field(service.NewStringListField("include_paths").Optional()).
		Field(service.NewStringField("session_key_meta").Default("session_id").Description("Bidi: message metadata key used to route messages to a specific stream session")).
		Field(service.NewDurationField("session_idle_timeout").Default("60s").Description("Bidi: closes an idle session stream after this duration")).
		Field(service.NewDurationField("session_max_lifetime").Default("10m").Description("Bidi: closes a session stream after this lifetime to rotate connections")).
		Field(service.NewBoolField("log_responses").Default(false).Description("Bidi: if enabled, receives server messages and logs them as debug entries")).
		// Security enhancements
		Field(service.NewBoolField("tls_skip_verify").Default(false).Description("Skip TLS certificate verification (insecure)")).
		Field(service.NewStringField("tls_server_name").Optional().Description("Override TLS server name for verification")).
		Field(service.NewStringField("tls_ca_cert").Optional().Description("Custom CA certificate for TLS")).
		Field(service.NewStringField("tls_client_cert").Optional().Description("Client certificate for mutual TLS")).
		Field(service.NewStringField("tls_client_key").Secret().Optional().Description("Client private key for mutual TLS")).
		Field(service.NewBoolField("require_transport_security").Default(false).Description("Force transport security even without TLS")).
		// Performance options
		Field(service.NewIntField("max_connection_pool_size").Default(1).Description("Maximum number of connections in pool")).
		Field(service.NewDurationField("connection_idle_timeout").Default("30m").Description("Connection idle timeout")).
		Field(service.NewBoolField("enable_message_pool").Default(false).Description("Enable message object pooling for performance")).
		// gRPC best practices
		Field(service.NewBoolField("enable_interceptors").Default(true).Description("Enable gRPC interceptors for observability")).
		Field(service.NewBoolField("propagate_deadlines").Default(true).Description("Propagate context deadlines to gRPC calls")).
		Field(service.NewStringMapField("default_metadata").Optional().Description("Default metadata to include in all calls")).
		// Retry policy
		Field(service.NewIntField("retry_max_attempts").Default(0).Description("Maximum retry attempts (0 disables retries)")).
		Field(service.NewDurationField("retry_initial_backoff").Default("1s").Description("Initial backoff for retries")).
		Field(service.NewDurationField("retry_max_backoff").Default("30s").Description("Maximum backoff for retries")).
		Field(service.NewFloatField("retry_backoff_multiplier").Default(2.0).Description("Backoff multiplier for retries")).
		Field(service.NewOutputMaxInFlightField())
}

// StreamSession represents a streaming gRPC session with comprehensive lifecycle management.
//
// StreamSession handles both client-streaming and bidirectional streaming patterns.
// It provides thread-safe access to stream state and automatic resource cleanup.
//
// Lifecycle Management:
// - Tracks session creation time and last usage for timeout enforcement
// - Maintains context cancellation for graceful stream termination
// - Provides thread-safe state management for concurrent access
//
// Stream Types Supported:
// - *grpcdynamic.ClientStream for client-streaming RPCs
// - *grpcdynamic.BidiStream for bidirectional streaming RPCs
//
// Thread Safety: All methods are thread-safe using RWMutex protection.
type StreamSession struct {
	stream   interface{}        // Can be *grpcdynamic.ClientStream or *grpcdynamic.BidiStream
	lastUse  time.Time          // Last time this session was used for idle timeout
	openedAt time.Time          // When this session was created for max lifetime
	cancel   context.CancelFunc // Cancels the stream context for graceful shutdown
	closed   bool               // Indicates if session has been closed
	mu       sync.RWMutex       // Protects concurrent access to session state
}

// NewStreamSession creates a new stream session
func NewStreamSession(stream interface{}, cancel context.CancelFunc) *StreamSession {
	now := time.Now()
	return &StreamSession{
		stream:   stream,
		lastUse:  now,
		openedAt: now,
		cancel:   cancel,
	}
}

// UpdateLastUse updates the last use time (thread-safe)
func (s *StreamSession) UpdateLastUse() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastUse = time.Now()
}

// GetLastUse returns the last use time (thread-safe)
func (s *StreamSession) GetLastUse() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastUse
}

// GetOpenedAt returns when the session was opened (thread-safe)
func (s *StreamSession) GetOpenedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.openedAt
}

// Close closes the session (thread-safe)
func (s *StreamSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}

	s.closed = true

	// Close the appropriate stream type
	switch stream := s.stream.(type) {
	case *grpcdynamic.ClientStream:
		_, _ = stream.CloseAndReceive()
	case *grpcdynamic.BidiStream:
		_ = stream.CloseSend()
	}

	if s.cancel != nil {
		s.cancel()
	}
}

// IsClosed returns whether the session is closed (thread-safe)
func (s *StreamSession) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// GetStream returns the underlying stream (thread-safe)
func (s *StreamSession) GetStream() interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stream
}

// SessionManager manages streaming sessions with automatic cleanup and lifecycle enforcement.
//
// The SessionManager coordinates multiple concurrent streaming sessions, applying
// configurable timeout policies and providing centralized session lifecycle management.
//
// Cleanup Strategy:
// - Runs a background goroutine that periodically sweeps for expired sessions
// - Enforces both idle timeout (time since last use) and max lifetime policies
// - Performs graceful session shutdown with proper resource cleanup
//
// Concurrency Model:
// - Thread-safe session storage using RWMutex protection
// - Supports concurrent session creation, access, and cleanup
// - Prevents resource leaks through systematic session tracking
//
// Session Routing:
// - Sessions are identified by string keys (typically from message metadata)
// - Enables message routing to appropriate streaming contexts
// - Supports session-based stateful streaming patterns
type SessionManager struct {
	sessions    map[string]*StreamSession // Active sessions indexed by session key
	mu          sync.RWMutex              // Protects concurrent access to sessions map
	stopCh      chan struct{}             // Signals cleanup goroutine to stop
	stopped     bool                      // Indicates if manager is shut down
	idleTimeout time.Duration             // Time after which idle sessions are closed
	maxLifetime time.Duration             // Maximum time a session can remain open
	log         *service.Logger           // Logger for session lifecycle events
}

// NewSessionManager creates a new session manager
func NewSessionManager(idleTimeout, maxLifetime time.Duration, log *service.Logger) *SessionManager {
	sm := &SessionManager{
		sessions:    make(map[string]*StreamSession),
		stopCh:      make(chan struct{}),
		idleTimeout: idleTimeout,
		maxLifetime: maxLifetime,
		log:         log,
	}

	// Start cleanup goroutine
	go sm.cleanup()

	return sm
}

// GetSession returns an existing session or nil
func (sm *SessionManager) GetSession(key string) *StreamSession {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[key]
	if !exists || session.IsClosed() {
		return nil
	}

	return session
}

// SetSession stores a session
func (sm *SessionManager) SetSession(key string, session *StreamSession) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Close existing session if any
	if existing, exists := sm.sessions[key]; exists {
		existing.Close()
	}

	sm.sessions[key] = session
}

// RemoveSession removes and closes a session
func (sm *SessionManager) RemoveSession(key string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if session, exists := sm.sessions[key]; exists {
		session.Close()
		delete(sm.sessions, key)
	}
}

// Close closes all sessions and stops the manager
func (sm *SessionManager) Close() {
	sm.mu.Lock()
	if sm.stopped {
		sm.mu.Unlock()
		return
	}
	sm.stopped = true

	// Close all sessions
	for key, session := range sm.sessions {
		session.Close()
		delete(sm.sessions, key)
	}
	sm.mu.Unlock()

	// Stop cleanup goroutine
	close(sm.stopCh)
}

// cleanup runs in a goroutine to clean up expired sessions
func (sm *SessionManager) cleanup() {
	ticker := time.NewTicker(defaultSessionSweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.sweepExpiredSessions()
		case <-sm.stopCh:
			return
		}
	}
}

// sweepExpiredSessions removes expired sessions based on idle timeout and max lifetime.
//
// This method implements the core cleanup logic for session management:
//
// 1. Idle Timeout Enforcement:
//   - Checks if sessions haven't been used within the configured idle timeout
//   - Removes sessions that have been inactive too long to free resources
//
// 2. Max Lifetime Enforcement:
//   - Ensures sessions don't exceed their maximum allowed lifetime
//   - Prevents indefinitely long-running sessions that could cause resource leaks
//
// 3. Graceful Cleanup:
//   - Properly closes each expired session before removal
//   - Calls session.Close() to trigger context cancellation and stream cleanup
//   - Removes session from the active sessions map
//
// Thread Safety: Acquires write lock for the duration of the sweep operation.
func (sm *SessionManager) sweepExpiredSessions() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.stopped {
		return
	}

	now := time.Now()
	for key, session := range sm.sessions {
		shouldRemove := false

		if sm.idleTimeout > 0 && now.Sub(session.GetLastUse()) > sm.idleTimeout {
			shouldRemove = true
			if sm.log != nil {
				sm.log.Debugf("Removing idle session %s", key)
			}
		} else if sm.maxLifetime > 0 && now.Sub(session.GetOpenedAt()) > sm.maxLifetime {
			shouldRemove = true
			if sm.log != nil {
				sm.log.Debugf("Removing expired session %s", key)
			}
		}

		if shouldRemove {
			session.Close()
			delete(sm.sessions, key)
		}
	}
}

// UnifiedOutput handles all gRPC output types with shared implementation
type UnifiedOutput struct {
	cfg            *Config
	connMgr        *ConnectionManager
	methodResolver *MethodResolver
	method         *desc.MethodDescriptor
	sessionMgr     *SessionManager
	retryConfig    RetryConfig

	// Streaming state
	mu       sync.Mutex
	shutdown bool
}

func newUnifiedOutput(conf *service.ParsedConfig, res *service.Resources) (service.Output, int, error) {
	cfg, err := ParseConfigFromService(conf)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse config: %w", err)
	}

	maxInFlight, _ := conf.FieldMaxInFlight()

	connMgr, err := NewConnectionManager(context.Background(), cfg)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create connection manager: %w", err)
	}

	methodResolver := NewMethodResolver()

	conn, err := connMgr.GetConnection()
	if err != nil {
		connMgr.Close()
		return nil, 0, fmt.Errorf("failed to get connection: %w", err)
	}

	method, err := methodResolver.ResolveMethod(context.Background(), conn, cfg)
	if err != nil {
		connMgr.Close()
		return nil, 0, fmt.Errorf("failed to resolve method: %w", err)
	}

	// Validate method type based on RPC type
	if err := validateMethodType(method, cfg.RPCType); err != nil {
		connMgr.Close()
		return nil, 0, err
	}

	// Create session manager for streaming types
	var sessionMgr *SessionManager
	if isStreamingType(cfg.RPCType) {
		sessionMgr = NewSessionManager(cfg.SessionIdleTimeout, cfg.SessionMaxLifetime, res.Logger())
	}

	return &UnifiedOutput{
		cfg:            cfg,
		connMgr:        connMgr,
		methodResolver: methodResolver,
		method:         method,
		sessionMgr:     sessionMgr,
		retryConfig:    DefaultRetryConfig(),
	}, maxInFlight, nil
}

// validateMethodType validates that the method matches the expected RPC type
func validateMethodType(method *desc.MethodDescriptor, rpcType string) error {
	switch rpcType {
	case "", "unary":
		if method.IsServerStreaming() || method.IsClientStreaming() {
			return fmt.Errorf("method %s is not unary", method.GetFullyQualifiedName())
		}
	case "client_stream":
		if !method.IsClientStreaming() || method.IsServerStreaming() {
			return fmt.Errorf("method %s is not client-streaming", method.GetFullyQualifiedName())
		}
	case "bidi":
		if !method.IsClientStreaming() || !method.IsServerStreaming() {
			return fmt.Errorf("method %s is not bidirectional", method.GetFullyQualifiedName())
		}
	default:
		return fmt.Errorf("unsupported rpc_type: %s", rpcType)
	}
	return nil
}

// isStreamingType returns true if the RPC type requires streaming
func isStreamingType(rpcType string) bool {
	return rpcType == "client_stream" || rpcType == "bidi"
}

func (u *UnifiedOutput) Connect(ctx context.Context) error {
	return nil
}

func (u *UnifiedOutput) Write(ctx context.Context, msg *service.Message) error {
	u.mu.Lock()
	if u.shutdown {
		u.mu.Unlock()
		return service.ErrNotConnected
	}
	u.mu.Unlock()

	if u.method == nil {
		return service.ErrNotConnected
	}

	// Build request message from the incoming message with optional pooling
	var requestMsg *dynamic.Message
	var shouldReturnToPool bool
	
	// Use message pool if enabled for better performance
	if inputPool, _ := u.methodResolver.GetMessagePools(u.method.GetFullyQualifiedName()); inputPool != nil {
		requestMsg = inputPool.Get()
		shouldReturnToPool = true
	} else {
		requestMsg = dynamic.NewMessage(u.method.GetInputType())
	}
	
	// Ensure message is returned to pool when done
	if shouldReturnToPool {
		defer func() {
			if inputPool, _ := u.methodResolver.GetMessagePools(u.method.GetFullyQualifiedName()); inputPool != nil {
				inputPool.Put(requestMsg)
			}
		}()
	}
	
	msgBytes, err := msg.AsBytes()
	if err != nil {
		return fmt.Errorf("failed to get message bytes: %w", err)
	}
	if len(msgBytes) == 0 {
		msgBytes = []byte("{}")
	}
	if err := requestMsg.UnmarshalJSON(msgBytes); err != nil {
		return fmt.Errorf("failed to unmarshal message JSON: %w", err)
	}

	switch u.cfg.RPCType {
	case "", "unary":
		return u.handleUnaryWrite(ctx, requestMsg)
	case "client_stream":
		return u.handleClientStreamWrite(ctx, requestMsg, msg)
	case "bidi":
		return u.handleBidiWrite(ctx, requestMsg, msg)
	default:
		return fmt.Errorf("unsupported rpc_type: %s", u.cfg.RPCType)
	}
}

func (u *UnifiedOutput) handleUnaryWrite(ctx context.Context, requestMsg *dynamic.Message) error {
	conn, err := u.connMgr.GetConnection()
	if err != nil {
		return fmt.Errorf("failed to get connection: %w", err)
	}

	stub := grpcdynamic.NewStub(conn)

	// Enhanced context handling with proper deadline propagation
	callCtx := u.enhanceCallContext(ctx)
	var cancel context.CancelFunc

	if u.cfg.CallTimeout > 0 {
		callCtx, cancel = context.WithTimeout(callCtx, u.cfg.CallTimeout)
		defer cancel()
	} else if _, hasDeadline := callCtx.Deadline(); !hasDeadline {
		// Apply default timeout if none specified
		callCtx, cancel = context.WithTimeout(callCtx, 30*time.Second)
		defer cancel()
	}

	_, err = stub.InvokeRpc(callCtx, u.method, requestMsg)
	if err != nil {
		return fmt.Errorf("unary RPC call failed: %w", err)
	}

	return nil
}

// enhanceCallContext enhances the context for gRPC calls with proper deadline and metadata handling
func (u *UnifiedOutput) enhanceCallContext(ctx context.Context) context.Context {
	// Preserve existing context values while enhancing for gRPC
	enhancedCtx := ctx

	// Ensure proper deadline propagation
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		remaining := time.Until(deadline)
		// Reserve some time for connection establishment and cleanup
		if remaining > 500*time.Millisecond {
			adjustedTimeout := remaining - 100*time.Millisecond
			newCtx, cancel := context.WithTimeout(context.Background(), adjustedTimeout)
			_ = cancel // Don't defer here, caller will handle
			// Copy important context values
			for _, key := range []interface{}{"session_id", "trace_id", "request_id"} {
				if val := ctx.Value(key); val != nil {
					newCtx = context.WithValue(newCtx, key, val)
				}
			}
			enhancedCtx = newCtx
		}
	}

	// Apply default metadata and auth headers to context
	enhancedCtx = u.injectMetadataIntoContext(enhancedCtx)
	
	return enhancedCtx
}

// injectMetadataIntoContext adds default_metadata and auth_headers to the gRPC context
func (u *UnifiedOutput) injectMetadataIntoContext(ctx context.Context) context.Context {
	// Collect all metadata to inject
	md := make(map[string]string)
	
	// Add default metadata from config
	if len(u.cfg.DefaultMetadata) > 0 {
		for k, v := range u.cfg.DefaultMetadata {
			md[k] = v
		}
	}
	
	// Add auth headers from config
	if len(u.cfg.AuthHeaders) > 0 {
		for k, v := range u.cfg.AuthHeaders {
			md[k] = v
		}
	}
	
	// Add bearer token if configured
	if u.cfg.BearerToken != "" {
		md["authorization"] = "Bearer " + u.cfg.BearerToken
	}
	
	// If we have metadata to inject, add it to the context
	if len(md) > 0 {
		// Get existing metadata if any
		existingMD, ok := metadata.FromOutgoingContext(ctx)
		if ok {
			// Merge with existing metadata
			for k, v := range existingMD {
				if _, exists := md[k]; !exists {
					if len(v) > 0 {
						md[k] = v[0] // Take first value
					}
				}
			}
		}
		
		// Create new metadata and attach to context
		newMD := metadata.New(md)
		ctx = metadata.NewOutgoingContext(ctx, newMD)
	}
	
	return ctx
}

func (u *UnifiedOutput) handleClientStreamWrite(ctx context.Context, requestMsg *dynamic.Message, msg *service.Message) error {
	sessionKey := "default" // Client streams don't use session keys

	session := u.sessionMgr.GetSession(sessionKey)
	if session == nil {
		if err := u.createClientStreamSession(ctx, sessionKey); err != nil {
			return fmt.Errorf("failed to create client stream session: %w", err)
		}
		session = u.sessionMgr.GetSession(sessionKey)
	}

	if session == nil {
		return errors.New("failed to get client stream session")
	}

	return WithContextRetry(ctx, u.retryConfig, func() error {
		session.UpdateLastUse()

		clientStream, ok := session.GetStream().(*grpcdynamic.ClientStream)
		if !ok {
			return errors.New("invalid client stream type")
		}

		if err := clientStream.SendMsg(requestMsg); err != nil {
			// Remove failed session and retry will recreate it
			u.sessionMgr.RemoveSession(sessionKey)
			if recreateErr := u.createClientStreamSession(ctx, sessionKey); recreateErr != nil {
				return fmt.Errorf("failed to recreate client stream: %w", recreateErr)
			}

			newSession := u.sessionMgr.GetSession(sessionKey)
			if newSession == nil {
				return errors.New("failed to get recreated client stream session")
			}

			newClientStream, ok := newSession.GetStream().(*grpcdynamic.ClientStream)
			if !ok {
				return errors.New("invalid recreated client stream type")
			}

			return newClientStream.SendMsg(requestMsg)
		}

		return nil
	})
}

func (u *UnifiedOutput) handleBidiWrite(ctx context.Context, requestMsg *dynamic.Message, msg *service.Message) error {
	sessionKey, _ := msg.MetaGet(u.cfg.SessionKeyMeta)
	if sessionKey == "" {
		sessionKey = "default"
	}

	session := u.sessionMgr.GetSession(sessionKey)
	if session == nil {
		if err := u.createBidiStreamSession(ctx, sessionKey); err != nil {
			return fmt.Errorf("failed to create bidi stream session: %w", err)
		}
		session = u.sessionMgr.GetSession(sessionKey)
	}

	if session == nil {
		return errors.New("failed to get bidi stream session")
	}

	return WithContextRetry(ctx, u.retryConfig, func() error {
		session.UpdateLastUse()

		bidiStream, ok := session.GetStream().(*grpcdynamic.BidiStream)
		if !ok {
			return errors.New("invalid bidi stream type")
		}

		if err := bidiStream.SendMsg(requestMsg); err != nil {
			// Remove failed session and retry will recreate it
			u.sessionMgr.RemoveSession(sessionKey)
			if recreateErr := u.createBidiStreamSession(ctx, sessionKey); recreateErr != nil {
				return fmt.Errorf("failed to recreate bidi stream: %w", recreateErr)
			}

			newSession := u.sessionMgr.GetSession(sessionKey)
			if newSession == nil {
				return errors.New("failed to get recreated bidi stream session")
			}

			newBidiStream, ok := newSession.GetStream().(*grpcdynamic.BidiStream)
			if !ok {
				return errors.New("invalid recreated bidi stream type")
			}

			return newBidiStream.SendMsg(requestMsg)
		}

		return nil
	})
}

func (u *UnifiedOutput) createClientStreamSession(ctx context.Context, sessionKey string) error {
	conn, err := u.connMgr.GetConnection()
	if err != nil {
		return fmt.Errorf("failed to get connection: %w", err)
	}

	stub := grpcdynamic.NewStub(conn)

	// Enhanced context handling for streaming
	streamCtx := u.enhanceCallContext(ctx)
	var cancel context.CancelFunc

	if u.cfg.CallTimeout > 0 {
		streamCtx, cancel = context.WithTimeout(streamCtx, u.cfg.CallTimeout)
	} else {
		// Apply default timeout for streaming operations
		defaultStreamTimeout := 10 * time.Minute
		streamCtx, cancel = context.WithTimeout(streamCtx, defaultStreamTimeout)
	}

	clientStream, err := stub.InvokeRpcClientStream(streamCtx, u.method)
	if err != nil {
		cancel()
		return fmt.Errorf("failed to create client stream: %w", err)
	}

	session := NewStreamSession(clientStream, cancel)
	u.sessionMgr.SetSession(sessionKey, session)

	return nil
}

func (u *UnifiedOutput) createBidiStreamSession(ctx context.Context, sessionKey string) error {
	conn, err := u.connMgr.GetConnection()
	if err != nil {
		return fmt.Errorf("failed to get connection: %w", err)
	}

	stub := grpcdynamic.NewStub(conn)

	// Enhanced context handling for bidirectional streaming
	streamCtx := u.enhanceCallContext(ctx)
	var cancel context.CancelFunc

	if u.cfg.CallTimeout > 0 {
		streamCtx, cancel = context.WithTimeout(streamCtx, u.cfg.CallTimeout)
	} else {
		// Apply longer default timeout for bidirectional streaming
		defaultBidiTimeout := 30 * time.Minute
		streamCtx, cancel = context.WithTimeout(streamCtx, defaultBidiTimeout)
	}

	bidiStream, err := stub.InvokeRpcBidiStream(streamCtx, u.method)
	if err != nil {
		cancel()
		return fmt.Errorf("failed to create bidi stream: %w", err)
	}

	session := NewStreamSession(bidiStream, cancel)
	u.sessionMgr.SetSession(sessionKey, session)

	// Start response handler if configured
	if u.cfg.LogResponses {
		go u.handleBidiResponses(bidiStream, sessionKey)
	}

	return nil
}

func (u *UnifiedOutput) handleBidiResponses(bidiStream *grpcdynamic.BidiStream, sessionKey string) {
	for {
		resp, err := bidiStream.RecvMsg()
		if err != nil {
			// Log the error and exit
			if u.sessionMgr != nil && u.sessionMgr.log != nil {
				u.sessionMgr.log.With("session", sessionKey, "error", err).Debug("bidi response handler ended")
			}
			return
		}

		// Handle different response types for logging
		var respBytes []byte
		var marshalErr error

		switch v := resp.(type) {
		case *dynamic.Message:
			respBytes, marshalErr = v.MarshalJSON()
		case *structpb.Struct:
			respBytes, marshalErr = protojson.Marshal(v)
		default:
			// Skip logging for unknown types
			continue
		}

		if marshalErr == nil && u.sessionMgr != nil && u.sessionMgr.log != nil {
			u.sessionMgr.log.With("session", sessionKey).Debug(string(respBytes))
		}
	}
}

func (u *UnifiedOutput) Close(ctx context.Context) error {
	u.mu.Lock()
	u.shutdown = true
	u.mu.Unlock()

	// Close session manager (this stops background goroutines)
	if u.sessionMgr != nil {
		u.sessionMgr.Close()
	}

	// Close connection manager
	if u.connMgr != nil {
		return u.connMgr.Close()
	}

	return nil
}

func init() {
	_ = service.RegisterOutput("grpc_client", genericOutputSpec(), func(conf *service.ParsedConfig, res *service.Resources) (service.Output, int, error) {
		return newUnifiedOutput(conf, res)
	})
}
