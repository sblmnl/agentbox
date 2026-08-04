package netpol

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// The in-guest half of the vm tier's egress path.
//
// HTTP_PROXY takes a host:port, so something in the guest has to speak TCP
// even though the transport off the box is vsock. This forwarder is that
// shim: it accepts on loopback and splices each connection to the host
// daemon, announcing the box with its token first. It carries no policy —
// every allow/deny decision stays on the host, where a guest (which may have
// root, under this tier) cannot reach it.
//
// It binds loopback only. Binding the box's bridge address instead would
// re-expose the proxy to the guest's network and, on a box sharing a
// network, to a neighbour.

// GuestForwarderSpec configures the in-guest listener.
type GuestForwarderSpec struct {
	Listen string // loopback address, e.g. 127.0.0.1:3128
	Token  string // per-box token announced to the host daemon
	Port   uint32 // host vsock port
}

// RunGuestForwarder serves until ctx is cancelled.
func RunGuestForwarder(ctx context.Context, spec *GuestForwarderSpec, logw io.Writer) error {
	if spec.Token == "" {
		return fmt.Errorf("vsockfwd: token is required")
	}
	port := spec.Port
	if port == 0 {
		port = VsockPort
	}
	ln, err := net.Listen("tcp", spec.Listen)
	if err != nil {
		return fmt.Errorf("vsockfwd: listening on %s: %w", spec.Listen, err)
	}
	defer ln.Close()
	logf := func(format string, a ...any) {
		if logw != nil {
			fmt.Fprintf(logw, time.Now().UTC().Format(time.RFC3339)+" "+format+"\n", a...)
		}
	}
	logf("vsockfwd listening on %s -> host cid %d port %d", spec.Listen, CIDHost, port)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			return fmt.Errorf("vsockfwd: accept: %w", err)
		}
		go func() {
			defer conn.Close()
			up, err := DialVsock(CIDHost, port)
			if err != nil {
				// The host daemon is gone or the channel is unavailable.
				// Closing is the honest answer: failing the request beats
				// letting the guest believe it has unproxied egress.
				logf("vsockfwd: %v", err)
				return
			}
			defer up.Close()
			if err := WritePreamble(up, spec.Token); err != nil {
				logf("vsockfwd: preamble: %v", err)
				return
			}
			splice(conn, up)
		}()
	}
}

// splice copies both directions until either side is done, half-closing so
// the peer sees EOF rather than waiting out an idle timeout.
func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
