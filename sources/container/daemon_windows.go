package container

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
)

func dialDaemonPipe(ctx context.Context, path string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, path)
}
