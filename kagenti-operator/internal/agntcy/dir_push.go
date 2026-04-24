package agntcy

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/go-logr/logr"
	corev1 "github.com/agntcy/dir/api/core/v1"
	storev1 "github.com/agntcy/dir/api/store/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// DirPusher uses agntcy/dir StoreService/Push over gRPC. This PoC only
// supports plaintext ("insecure"/"none"); production should use the full
// auth stack from agntcy/dir (SPIFFE/jwt, etc.) via a dedicated client or
// the official dir client when its dependency tree is compatible.
type DirPusher struct {
	conn   *grpc.ClientConn
	client storev1.StoreServiceClient
}

// NewDirPusher dials the catalog StoreService.
func NewDirPusher(ctx context.Context, log logr.Logger, address, authMode string) (*DirPusher, error) {
	_ = ctx
	if address == "" {
		return nil, fmt.Errorf("directory address is required")
	}
	if authMode == "" {
		authMode = "insecure"
	}
	// gRPC: allow passing host:port; no scheme.
	target := address
	if !strings.HasPrefix(target, "dns:") && !strings.HasPrefix(target, "unix:") {
		target = address
	}
	if authMode != "insecure" && authMode != "none" {
		return nil, fmt.Errorf("dir PoC: authMode %q is not supported — use \"insecure\" (local) or wire SPIFFE in a follow-up", authMode)
	}
	log.V(1).Info("AGNTCY PoC: dialing directory", "target", target, "authMode", authMode)
	conn, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("dir grpc dial: %w", err)
	}
	return &DirPusher{conn: conn, client: storev1.NewStoreServiceClient(conn)}, nil
}

func (d *DirPusher) Close() error {
	if d == nil || d.conn == nil {
		return nil
	}
	return d.conn.Close() //nolint:wrapcheck
}

// PushRecord sends a single record and returns the content CID.
func (d *DirPusher) PushRecord(ctx context.Context, rec *corev1.Record) (cid string, err error) {
	if d == nil || d.client == nil {
		return "", fmt.Errorf("dir pusher is nil")
	}
	stream, err := d.client.Push(ctx)
	if err != nil {
		return "", fmt.Errorf("dir push: %w", err)
	}
	if err := stream.Send(rec); err != nil {
		_ = stream.CloseSend() //nolint:errcheck
		return "", fmt.Errorf("dir push send: %w", err)
	}
	if err := stream.CloseSend(); err != nil {
		return "", fmt.Errorf("dir push close send: %w", err)
	}
	ref, err := stream.Recv()
	if err != nil {
		if err == io.EOF {
			return "", fmt.Errorf("dir push: no record ref after send")
		}
		return "", fmt.Errorf("dir push recv: %w", err)
	}
	if ref == nil {
		return "", fmt.Errorf("dir push: nil record ref")
	}
	return ref.GetCid(), nil
}
