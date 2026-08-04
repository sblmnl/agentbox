package netpol

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// muxWithBox returns a Proxyd holding one token-attached box, without
// binding a real vsock socket: the routing under test is the token lookup,
// and serveVsock takes any net.Conn.
func muxWithBox(t *testing.T, token string, pol *Policy) *Proxyd {
	t.Helper()
	p := &Proxyd{Logf: func(string, ...any) {}}
	p.active = map[string]*boxListener{}
	p.byToken = map[string]*boxListener{}
	p.byToken[token] = &boxListener{
		spec:   ListenerSpec{Resource: "agentbox-box", Token: token},
		pol:    pol,
		closed: make(chan struct{}),
	}
	return p
}

// The daemon publishes readiness and the backend polls for it; they derive
// the path from different ends (spool directory vs state root) and must
// agree. They did not once — the daemon wrote a directory too deep, the
// listener was up, and every box start failed waiting for a file nobody
// would ever create.
func TestVsockReadyPathAgreesWithSpoolDerivation(t *testing.T) {
	root := t.TempDir()
	p := &Proxyd{SpoolDir: SpoolDir(root)}
	if got := p.stateRoot(); got != root {
		t.Fatalf("daemon derived state root %q from its spool, want %q", got, root)
	}
	if got := VsockReadyPath(p.stateRoot()); got != VsockReadyPath(root) {
		t.Fatalf("daemon would publish readiness at %q, backend waits at %q", got, VsockReadyPath(root))
	}
}

func TestVsockPreambleRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { _ = WritePreamble(a, "cafebabe") }()
	tok, err := readPreamble(b, bufio.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if tok != "cafebabe" {
		t.Fatalf("token round trip: got %q", tok)
	}
}

// A connection whose token matches no live box must be closed, not served.
// Serving it would be egress under no policy at all — the exact silent
// weakening the tier is not allowed to have.
func TestVsockUnknownTokenIsRefused(t *testing.T) {
	p := muxWithBox(t, "goodtoken", &Policy{Mode: ModeProxy, Allow: []string{"example.com"}})
	client, server := net.Pipe()
	defer client.Close()
	go p.serveVsock(server)

	if err := WritePreamble(client, "wrongtoken"); err != nil {
		t.Fatal(err)
	}
	// The peer never gets to speak: the connection is closed outright, so
	// the read ends in EOF with nothing served.
	buf := make([]byte, 1)
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := client.Read(buf); n > 0 || err == nil {
		t.Fatalf("unknown token was served (read %d bytes, err %v)", n, err)
	}
}

// A malformed preamble is refused the same way, and must not leave the
// handler waiting on a peer that never identifies itself.
func TestVsockBadPreambleIsRefused(t *testing.T) {
	p := muxWithBox(t, "goodtoken", &Policy{Mode: ModeProxy})
	client, server := net.Pipe()
	defer client.Close()
	go p.serveVsock(server)

	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := client.Read(buf); n > 0 || err == nil {
		t.Fatalf("bad preamble was served (read %d bytes, err %v)", n, err)
	}
}

// The token selects that box's policy: a denial must come back under the
// allowlist of the box the token names.
func TestVsockTokenSelectsBoxPolicy(t *testing.T) {
	p := muxWithBox(t, "goodtoken", &Policy{Mode: ModeProxy, Allow: []string{"allowed.example"}})
	client, server := net.Pipe()
	defer client.Close()
	go p.serveVsock(server)

	if err := WritePreamble(client, "goodtoken"); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = io.WriteString(client, "CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\n\r\n")
	}()
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("no response after a valid preamble: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("host outside the box's allowlist got %d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "allowlist") {
		t.Fatalf("denial body does not name the allowlist: %q", body)
	}
}
