package grpc_client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/jhump/protoreflect/dynamic/grpcdynamic"
	"google.golang.org/grpc/metadata"
	structpb "google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/warpstreamlabs/bento/public/service"
)

func genericInputSpec() *service.ConfigSpec {
	return service.NewConfigSpec().
		Version("1.11.0").
		Categories("Services").
		Summary("Call an arbitrary gRPC method (unary or server-stream) using reflection to resolve types with enhanced security and performance").
		Field(service.NewStringField(fieldAddress).Default("127.0.0.1:50051")).
		Field(service.NewStringField(fieldMethod).Description("Full method name, e.g. /pkg.Service/Method")).
		Field(service.NewStringField(fieldRPCType).Default("server_stream")).
		Field(service.NewStringField(fieldRequestJSON).Default("{}").Description("JSON request body used for unary or initial server-stream request")).
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
		Field(service.NewFloatField("retry_backoff_multiplier").Default(2.0).Description("Backoff multiplier for retries"))
}

// genericInput handles both unary and server-streaming gRPC input
type genericInput struct {
	cfg            *Config
	connMgr        *ConnectionManager
	methodResolver *MethodResolver
	reqIS          *service.InterpolatedString
	method         *desc.MethodDescriptor

	// Server streaming state with proper cleanup
	mu             sync.Mutex
	streamCtx      context.Context
	streamCancel   context.CancelFunc
	stream         *grpcdynamic.ServerStream
	streamOpen     bool
	shutdown       bool
	retryConfig    RetryConfig
}

func newGenericInput(conf *service.ParsedConfig, res *service.Resources) (service.Input, error) {
	cfg, err := ParseConfigFromService(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	reqIS, err := service.NewInterpolatedString(cfg.RequestJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to create interpolated string: %w", err)
	}

	connMgr, err := NewConnectionManager(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	methodResolver := NewMethodResolver()
	
	conn, err := connMgr.GetConnection()
	if err != nil {
		connMgr.Close()
		return nil, fmt.Errorf("failed to get connection: %w", err)
	}

	method, err := methodResolver.ResolveMethod(context.Background(), conn, cfg)
	if err != nil {
		connMgr.Close()
		return nil, fmt.Errorf("failed to resolve method: %w", err)
	}

	return &genericInput{
		cfg:            cfg,
		connMgr:        connMgr,
		methodResolver: methodResolver,
		reqIS:          reqIS,
		method:         method,
		retryConfig:    DefaultRetryConfig(),
	}, nil
}

func (g *genericInput) Connect(_ context.Context) error { 
	return nil 
}

func (g *genericInput) Read(ctx context.Context) (*service.Message, service.AckFunc, error) {
	g.mu.Lock()
	if g.shutdown {
		g.mu.Unlock()
		return nil, nil, service.ErrNotConnected
	}
	g.mu.Unlock()

	if g.method == nil {
		return nil, nil, service.ErrNotConnected
	}

	// Build request message from JSON with optional pooling
	var requestMsg *dynamic.Message
	var shouldReturnToPool bool
	
	// Use message pool if enabled for better performance
	if inputPool, _ := g.methodResolver.GetMessagePools(g.method.GetFullyQualifiedName()); inputPool != nil {
		requestMsg = inputPool.Get()
		shouldReturnToPool = true
	} else {
		requestMsg = dynamic.NewMessage(g.method.GetInputType())
	}
	
	// Ensure message is returned to pool when done
	if shouldReturnToPool {
		defer func() {
			if inputPool, _ := g.methodResolver.GetMessagePools(g.method.GetFullyQualifiedName()); inputPool != nil {
				inputPool.Put(requestMsg)
			}
		}()
	}
	
	reqJSON := g.reqIS.String(service.NewMessage(nil))
	if reqJSON == "" {
		reqJSON = "{}"
	}
	if err := requestMsg.UnmarshalJSON([]byte(reqJSON)); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal request JSON: %w", err)
	}

	switch g.cfg.RPCType {
	case "unary":
		return g.handleUnaryCall(ctx, requestMsg)
	case "server_stream":
		return g.handleServerStreamCall(ctx, requestMsg, reqJSON)
	default:
		return nil, nil, fmt.Errorf("unsupported rpc_type for input: %s", g.cfg.RPCType)
	}
}

func (g *genericInput) handleUnaryCall(ctx context.Context, requestMsg *dynamic.Message) (*service.Message, service.AckFunc, error) {
	// Validate method type
	if g.method.IsServerStreaming() || g.method.IsClientStreaming() {
		return nil, nil, fmt.Errorf("method %s is not unary", g.method.GetFullyQualifiedName())
	}

	conn, err := g.connMgr.GetConnection()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get connection: %w", err)
	}

	stub := grpcdynamic.NewStub(conn)
	
	// Enhanced context handling with proper deadline propagation
	callCtx := g.enhanceCallContext(ctx)
	var cancel context.CancelFunc
	
	if g.cfg.CallTimeout > 0 {
		callCtx, cancel = context.WithTimeout(callCtx, g.cfg.CallTimeout)
		defer cancel()
	} else if _, hasDeadline := callCtx.Deadline(); !hasDeadline {
		// Apply default timeout for unary input calls
		callCtx, cancel = context.WithTimeout(callCtx, 30*time.Second)
		defer cancel()
	}

	resp, err := stub.InvokeRpc(callCtx, g.method, requestMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("unary RPC call failed: %w", err)
	}

	// Handle different response types
	var respBytes []byte
	switch v := resp.(type) {
	case *dynamic.Message:
		respBytes, err = v.MarshalJSON()
	case *structpb.Struct:
		respBytes, err = protojson.Marshal(v)
	default:
		return nil, nil, fmt.Errorf("unexpected response type from unary call: %T", resp)
	}
	
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	msg := service.NewMessage(respBytes)
	return msg, func(context.Context, error) error { return nil }, nil
}

func (g *genericInput) handleServerStreamCall(ctx context.Context, requestMsg *dynamic.Message, reqJSON string) (*service.Message, service.AckFunc, error) {
	// Validate method type
	if !g.method.IsServerStreaming() || g.method.IsClientStreaming() {
		return nil, nil, fmt.Errorf("method %s is not server-streaming", g.method.GetFullyQualifiedName())
	}

	// Ensure stream is open
	if err := g.ensureStreamOpen(ctx, requestMsg); err != nil {
		return nil, nil, fmt.Errorf("failed to open stream: %w", err)
	}

	for {
		g.mu.Lock()
		if g.shutdown || g.stream == nil {
			g.mu.Unlock()
			return nil, nil, service.ErrNotConnected
		}
		stream := g.stream
		g.mu.Unlock()

		resp, err := stream.RecvMsg()
		if err == nil {
			// Handle different response types
			var respBytes []byte
			var marshalErr error
			
			switch v := resp.(type) {
			case *dynamic.Message:
				// Direct dynamic message
				respBytes, marshalErr = v.MarshalJSON()
			case *structpb.Struct:
				// google.protobuf.Struct
				respBytes, marshalErr = protojson.Marshal(v)
			default:
				return nil, nil, fmt.Errorf("unexpected stream response type: %T", resp)
			}
			
			if marshalErr != nil {
				return nil, nil, fmt.Errorf("failed to marshal stream response: %w", marshalErr)
			}

			msg := service.NewMessage(respBytes)
			return msg, func(context.Context, error) error { return nil }, nil
		}

		if errors.Is(err, io.EOF) {
			return nil, nil, service.ErrEndOfInput
		}

		// Stream failed, attempt to reopen with retry
		if reopenErr := g.reopenStreamWithRetry(ctx, reqJSON); reopenErr != nil {
			return nil, nil, fmt.Errorf("failed to reopen stream: %w", reopenErr)
		}
	}
}

func (g *genericInput) ensureStreamOpen(ctx context.Context, requestMsg *dynamic.Message) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.streamOpen && g.stream != nil {
		return nil
	}

	return g.openStreamLocked(ctx, requestMsg)
}

func (g *genericInput) openStreamLocked(ctx context.Context, requestMsg *dynamic.Message) error {
	// Close existing stream if any
	g.closeStreamLocked()

	conn, err := g.connMgr.GetConnection()
	if err != nil {
		return fmt.Errorf("failed to get connection: %w", err)
	}

	stub := grpcdynamic.NewStub(conn)

	// Enhanced context handling for server streaming
	streamCtx := g.enhanceCallContext(ctx)
	var cancel context.CancelFunc
	
	if g.cfg.CallTimeout > 0 {
		streamCtx, cancel = context.WithTimeout(streamCtx, g.cfg.CallTimeout)
	} else {
		// Apply default timeout for server streaming
		defaultStreamTimeout := 15 * time.Minute
		streamCtx, cancel = context.WithTimeout(streamCtx, defaultStreamTimeout)
	}

	stream, err := stub.InvokeRpcServerStream(streamCtx, g.method, requestMsg)
	if err != nil {
		cancel()
		return fmt.Errorf("failed to invoke server stream: %w", err)
	}

	g.streamCtx = streamCtx
	g.streamCancel = cancel
	g.stream = stream
	g.streamOpen = true

	return nil
}

// enhanceCallContext enhances the context for gRPC calls with proper deadline and metadata handling
func (g *genericInput) enhanceCallContext(ctx context.Context) context.Context {
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
	enhancedCtx = g.injectMetadataIntoContext(enhancedCtx)
	
	return enhancedCtx
}

// injectMetadataIntoContext adds default_metadata and auth_headers to the gRPC context
func (g *genericInput) injectMetadataIntoContext(ctx context.Context) context.Context {
	// Collect all metadata to inject
	md := make(map[string]string)
	
	// Add default metadata from config
	if len(g.cfg.DefaultMetadata) > 0 {
		for k, v := range g.cfg.DefaultMetadata {
			md[k] = v
		}
	}
	
	// Add auth headers from config
	if len(g.cfg.AuthHeaders) > 0 {
		for k, v := range g.cfg.AuthHeaders {
			md[k] = v
		}
	}
	
	// Add bearer token if configured
	if g.cfg.BearerToken != "" {
		md["authorization"] = "Bearer " + g.cfg.BearerToken
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

func (g *genericInput) reopenStreamWithRetry(ctx context.Context, reqJSON string) error {
	// Use message pool if enabled for better performance
	var requestMsg *dynamic.Message
	var shouldReturnToPool bool
	
	if inputPool, _ := g.methodResolver.GetMessagePools(g.method.GetFullyQualifiedName()); inputPool != nil {
		requestMsg = inputPool.Get()
		shouldReturnToPool = true
	} else {
		requestMsg = dynamic.NewMessage(g.method.GetInputType())
	}
	
	// Ensure message is returned to pool when done
	if shouldReturnToPool {
		defer func() {
			if inputPool, _ := g.methodResolver.GetMessagePools(g.method.GetFullyQualifiedName()); inputPool != nil {
				inputPool.Put(requestMsg)
			}
		}()
	}
	
	if err := requestMsg.UnmarshalJSON([]byte(reqJSON)); err != nil {
		return fmt.Errorf("failed to unmarshal request for retry: %w", err)
	}

	return WithContextRetry(ctx, g.retryConfig, func() error {
		g.mu.Lock()
		defer g.mu.Unlock()
		
		if g.shutdown {
			return fmt.Errorf("input is shutting down")
		}
		
		return g.openStreamLocked(ctx, requestMsg)
	})
}

func (g *genericInput) closeStreamLocked() {
	if g.streamCancel != nil {
		g.streamCancel()
		g.streamCancel = nil
	}
	g.stream = nil
	g.streamOpen = false
}

func (g *genericInput) Close(ctx context.Context) error {
	g.mu.Lock()
	g.shutdown = true
	g.closeStreamLocked()
	g.mu.Unlock()

	if g.connMgr != nil {
		return g.connMgr.Close()
	}
	return nil
}

func init() {
	_ = service.RegisterInput("grpc_client", genericInputSpec(), func(conf *service.ParsedConfig, res *service.Resources) (service.Input, error) {
		return newGenericInput(conf, res)
	})
}
