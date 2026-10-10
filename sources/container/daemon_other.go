//go:build !windows

package container

import (
	"context"
	"errors"
	"net"
)

func dialDaemonPipe(_ context.Context, _ string) (net.Conn, error) {
	return nil, errors.New("engine named pipes require Windows; set --daemon-host to a supported endpoint")
}
