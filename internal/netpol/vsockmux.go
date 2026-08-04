package netpol

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// One host vsock listener serves every box, because a vsock port is a
// host-global resource — there is no per-box address to bind, the way each
// bridge gave its own gateway IP. Boxes are told apart by a preamble
// carrying the per-box token minted at create time.
//
// Sharing the listener MUST NOT share policy: the token selects one box's
// boxListener, and everything after that — allow/deny evaluation, audit
// destination — is that box's alone, exactly as with a private listener. A
// connection whose token matches nothing is closed without being served, so
// a box that has been stopped cannot keep egressing on a stale token.
const (
	preambleMagic   = "agentbox-vsock/1 "
	preambleMaxLen  = 128
	preambleTimeout = 10 * time.Second
)

// WritePreamble announces which box a guest connection belongs to. Called by
// the in-guest forwarder before any proxy bytes flow.
func WritePreamble(c net.Conn, token string) error {
	_, err := fmt.Fprintf(c, "%s%s\n", preambleMagic, token)
	return err
}

// readPreamble reads the token line. It is deadline-bound and length-capped:
// the listener is reachable by any guest on the host, so a peer that connects
// and says nothing must not hold a goroutine or buffer indefinitely.
func readPreamble(c net.Conn, r *bufio.Reader) (string, error) {
	if err := c.SetReadDeadline(time.Now().Add(preambleTimeout)); err != nil {
		return "", err
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > preambleMaxLen {
		return "", fmt.Errorf("preamble too long")
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, preambleMagic) {
		return "", fmt.Errorf("bad preamble")
	}
	token := strings.TrimPrefix(line, preambleMagic)
	if token == "" {
		return "", fmt.Errorf("empty token")
	}
	return token, nil
}

// VsockReadyPath marks that the shared vsock listener is bound. The backend
// cannot probe the listener the way it dialed a TCP gateway — a host process
// cannot connect to its own CID_ANY socket without vsock_loopback — so
// readiness is published as a file instead.
func VsockReadyPath(stateRoot string) string {
	return filepath.Join(ProxydDir(stateRoot), "vsock.ready")
}

// WaitVsockReady blocks until the daemon publishes the listener, so a box is
// never started before its egress path exists.
func WaitVsockReady(stateRoot string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	path := VsockReadyPath(stateRoot)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("proxyd vsock listener did not come up within %s", timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// stateRoot recovers the agentbox state root from the spool directory,
// which is <root>/proxyd/listeners — two levels down, not one.
func (p *Proxyd) stateRoot() string {
	return filepath.Dir(filepath.Dir(p.SpoolDir))
}

// ensureVsock binds the shared listener on first token-bearing box.
// p.mu must be held.
func (p *Proxyd) ensureVsock() error {
	if p.vsockLn != nil {
		return nil
	}
	ln, err := ListenVsock(VsockPort)
	if err != nil {
		return err
	}
	p.vsockLn = ln
	if p.SpoolDir != "" {
		ready := VsockReadyPath(p.stateRoot())
		if err := os.MkdirAll(filepath.Dir(ready), 0o700); err == nil {
			_ = os.WriteFile(ready, []byte(fmt.Sprintf("%d\n", VsockPort)), 0o600)
		}
	}
	p.Logf("vsock listener up on port %d", VsockPort)
	go p.acceptVsock(ln)
	return nil
}

// closeVsock retracts the shared listener once no box is using it, so a host
// with no running boxes holds no guest-reachable socket. p.mu must be held.
func (p *Proxyd) closeVsock() {
	if p.vsockLn == nil || len(p.byToken) > 0 {
		return
	}
	p.vsockLn.Close()
	p.vsockLn = nil
	if p.SpoolDir != "" {
		_ = os.Remove(VsockReadyPath(p.stateRoot()))
	}
	p.Logf("vsock listener down")
}

func (p *Proxyd) acceptVsock(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			p.mu.Lock()
			current := p.vsockLn
			p.mu.Unlock()
			if current != ln {
				return // retracted by closeVsock
			}
			p.Logf("vsock accept: %v", err)
			return
		}
		go p.serveVsock(conn)
	}
}

// serveVsock attributes one guest connection to a box and hands it to that
// box's handler.
func (p *Proxyd) serveVsock(conn net.Conn) {
	peer := conn.RemoteAddr().String()
	br := bufio.NewReader(conn)
	token, err := readPreamble(conn, br)
	if err != nil {
		p.Logf("vsock %s: %v", peer, err)
		conn.Close()
		return
	}
	p.mu.Lock()
	bl := p.byToken[token]
	p.mu.Unlock()
	if bl == nil {
		// No live box owns this token: a stopped box's forwarder, or a
		// guest guessing. Serving it would mean egress under no policy.
		p.Logf("vsock %s: no listener for token", peer)
		conn.Close()
		return
	}
	bl.handleBuffered(conn, br)
}
