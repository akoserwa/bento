package grpc_client

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jhump/protoreflect/dynamic"
	"github.com/jhump/protoreflect/dynamic/grpcdynamic"
	"google.golang.org/grpc/codes"
)

func startTestServer(t *testing.T) func() {
	t.Helper()
	cmd := exec.Command("go", "run", "./cmd/tools/grpc_test_server")
	cmd.Dir = repoRoot(t)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	// wait briefly for server to listen
	time.Sleep(1 * time.Second)
	return func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}

func repoRoot(t *testing.T) string {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	// internal/impl/grpc_client → repo root is ../../..
	return filepath.Clean(filepath.Join(dir, "../../../"))
}

func TestIntegration_ServerStream_OK(t *testing.T) {
	stop := startTestServer(t)
	defer stop()

	cfg := &Config{
		Address:                   "127.0.0.1:50051",
		Method:                    "/echo.Echo/Stream",
		RPCType:                   "server_stream",
		LoadBalancingPolicy:       "pick_first",
		ProtoFiles:                []string{"echo.proto", "google/protobuf/struct.proto"},
		IncludePaths:              []string{filepath.Join(repoRoot(t), "cmd/tools/grpc_test_server/pb")},
		RetryPolicy:               &RetryPolicy{MaxAttempts: 2, InitialBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond, BackoffMultiplier: 2, RetryableStatusCodes: []codes.Code{codes.Unavailable}},
		MaxConnectionPoolSize:     1,
		ConnectTimeout:            2 * time.Second,
		ConnectionIdleTimeout:     30 * time.Second,
		ConnectionCleanupInterval: 1 * time.Minute,
	}

	cm, err := NewConnectionManager(context.Background(), cfg)
	if err != nil {
		t.Fatalf("cm: %v", err)
	}
	defer cm.Close()

	conn, err := cm.GetConnection()
	if err != nil {
		t.Fatalf("conn: %v", err)
	}

	mr := NewMethodResolver()
	m, err := mr.ResolveMethod(context.Background(), conn, cfg)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	stub := grpcdynamic.NewStub(conn)

	in := dynamic.NewMessage(m.GetInputType())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = stub.InvokeRpcServerStream(ctx, m, in)
	if err != nil {
		t.Fatalf("invoke stream: %v", err)
	}
}

func TestIntegration_ClientStream_OK(t *testing.T) {
	stop := startTestServer(t)
	defer stop()

	cfg := &Config{
		Address:                   "127.0.0.1:50051",
		Method:                    "/ingest.Ingest/Stream",
		RPCType:                   "client_stream",
		LoadBalancingPolicy:       "pick_first",
		ProtoFiles:                []string{"ingest.proto", "google/protobuf/struct.proto"},
		IncludePaths:              []string{filepath.Join(repoRoot(t), "cmd/tools/grpc_test_server/pb")},
		RetryPolicy:               &RetryPolicy{MaxAttempts: 2, InitialBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond, BackoffMultiplier: 2, RetryableStatusCodes: []codes.Code{codes.Unavailable}},
		MaxConnectionPoolSize:     1,
		ConnectTimeout:            2 * time.Second,
		ConnectionIdleTimeout:     30 * time.Second,
		ConnectionCleanupInterval: 1 * time.Minute,
	}

	cm, err := NewConnectionManager(context.Background(), cfg)
	if err != nil {
		t.Fatalf("cm: %v", err)
	}
	defer cm.Close()

	conn, err := cm.GetConnection()
	if err != nil {
		t.Fatalf("conn: %v", err)
	}

	mr := NewMethodResolver()
	m, err := mr.ResolveMethod(context.Background(), conn, cfg)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	stub := grpcdynamic.NewStub(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cs, err := stub.InvokeRpcClientStream(ctx, m)
	if err != nil {
		t.Fatalf("open client stream: %v", err)
	}
	// send a few empty structs
	for i := 0; i < 3; i++ {
		if err := cs.SendMsg(dynamic.NewMessage(m.GetInputType())); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	// close and receive final response
	if _, err := cs.CloseAndReceive(); err != nil {
		t.Fatalf("close/recv: %v", err)
	}
}
