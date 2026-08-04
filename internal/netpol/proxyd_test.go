package netpol

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startProxyd runs a daemon over a temp spool and returns the state root.
func startProxyd(t *testing.T) (string, context.CancelFunc) {
	t.Helper()
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	p := &Proxyd{SpoolDir: SpoolDir(root), Logf: t.Logf, IdleExit: time.Hour}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = p.Run(ctx)
	}()
	t.Cleanup(func() { cancel(); <-done })
	return root, cancel
}

func declareListener(t *testing.T, root string, ls *ListenerSpec) string {
	t.Helper()
	// Grab a free port deterministically: bind, close, reuse.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	ls.Addr = addr
	if err := WriteListenerSpec(root, ls); err != nil {
		t.Fatal(err)
	}
	if err := WaitListener(addr, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	return addr
}

// origin starts a plain HTTP origin server the proxy can forward to.
func origin(t *testing.T) (host string, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Via") != "" {
			w.WriteHeader(500)
			return
		}
		fmt.Fprint(w, "origin-ok")
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	return h, p
}

func proxyGet(t *testing.T, proxyAddr, rawurl string) (*http.Response, string) {
	t.Helper()
	u, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true}}
	resp, err := client.Get(rawurl)
	if err != nil {
		t.Fatalf("GET %s via %s: %v", rawurl, proxyAddr, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestProxydForwardAllowedAndDenied(t *testing.T) {
	root, _ := startProxyd(t)
	oh, op := origin(t)
	audit := filepath.Join(root, "audit.log")

	// 127.0.0.1 is an IP literal, which Resolve refuses; the policy engine
	// matches hosts textually, so allow the literal host string directly.
	addr := declareListener(t, root, &ListenerSpec{
		BoxID: "b1", Resource: "agentbox-t1", Mode: ModeProxy,
		Allow: []string{oh}, Deny: nil, Audit: true, AuditPath: audit,
		ReadTimeout: "1h", RequestTimeout: "5m",
	})

	resp, body := proxyGet(t, addr, "http://"+net.JoinHostPort(oh, op)+"/hello")
	if resp.StatusCode != 200 || body != "origin-ok" {
		t.Fatalf("allowed forward: got %d %q", resp.StatusCode, body)
	}

	resp, body = proxyGet(t, addr, "http://not-allowed.example/")
	if resp.StatusCode != 403 {
		t.Fatalf("denied forward: got %d %q", resp.StatusCode, body)
	}
	if !strings.Contains(body, "not in this box's allowlist") {
		t.Fatalf("denial body should name the cause, got %q", body)
	}

	blob, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	log := string(blob)
	if !strings.Contains(log, "TCP_MISS/200 GET") {
		t.Fatalf("audit missing allowed line:\n%s", log)
	}
	if !strings.Contains(log, "TCP_DENIED/403 GET http://not-allowed.example/") {
		t.Fatalf("audit missing denial line:\n%s", log)
	}
}

func TestProxydConnectPolicy(t *testing.T) {
	root, _ := startProxyd(t)
	audit := filepath.Join(root, "audit.log")
	addr := declareListener(t, root, &ListenerSpec{
		BoxID: "b1", Resource: "agentbox-t2", Mode: ModeProxy,
		Allow: []string{"allowed.example"}, Audit: true, AuditPath: audit,
	})

	connect := func(target string) string {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			t.Fatalf("CONNECT %s: %v", target, err)
		}
		return strings.TrimSpace(line)
	}

	// Denied host: refused before any dial happens.
	if got := connect("evil.example:443"); !strings.Contains(got, "403") {
		t.Fatalf("CONNECT to non-allowlisted host: %q", got)
	}
	// Allowed host but non-TLS port: CONNECT is for TLS only.
	if got := connect("allowed.example:25"); !strings.Contains(got, "403") {
		t.Fatalf("CONNECT to port 25 should be refused: %q", got)
	}
}

// TestTunnelDataPath exercises the byte-copy loop directly: a full CONNECT
// tunnel needs an origin on port 443, which a test cannot bind.
func TestTunnelDataPath(t *testing.T) {
	pair := func() (net.Conn, net.Conn) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		ch := make(chan net.Conn, 1)
		go func() { c, _ := ln.Accept(); ch <- c }()
		client, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return client, <-ch
	}
	clientA, proxyA := pair() // guest <-> proxy
	proxyB, echoSrv := pair() // proxy <-> upstream
	go func() { defer echoSrv.Close(); io.Copy(echoSrv, echoSrv) }()
	done := make(chan struct{})
	go func() { defer close(done); tunnel(proxyA, proxyB, time.Minute) }()

	if _, err := clientA.Write([]byte("through-the-tunnel")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 18)
	if _, err := io.ReadFull(clientA, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "through-the-tunnel" {
		t.Fatalf("echoed %q", buf)
	}
	clientA.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("tunnel did not shut down after client close")
	}
}

func TestProxydReconcileAddRemove(t *testing.T) {
	root, _ := startProxyd(t)
	addr := declareListener(t, root, &ListenerSpec{
		BoxID: "b1", Resource: "agentbox-t4", Mode: ModeProxy,
	})

	if err := RemoveListenerSpec(root, "agentbox-t4"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			break // listener gone
		}
		c.Close()
		if time.Now().After(deadline) {
			t.Fatal("listener still accepting after spec removal")
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Retraction is idempotent.
	if err := RemoveListenerSpec(root, "agentbox-t4"); err != nil {
		t.Fatal(err)
	}
}

func TestProxydPerListenerPolicyIsolation(t *testing.T) {
	root, _ := startProxyd(t)
	oh, op := origin(t)
	target := "http://" + net.JoinHostPort(oh, op) + "/"

	allowed := declareListener(t, root, &ListenerSpec{
		BoxID: "b1", Resource: "agentbox-a", Mode: ModeProxy, Allow: []string{oh},
	})
	denied := declareListener(t, root, &ListenerSpec{
		BoxID: "b2", Resource: "agentbox-b", Mode: ModeProxy, Allow: []string{"other.example"},
	})

	if resp, _ := proxyGet(t, allowed, target); resp.StatusCode != 200 {
		t.Fatalf("box a should reach its allowed origin, got %d", resp.StatusCode)
	}
	if resp, _ := proxyGet(t, denied, target); resp.StatusCode != 403 {
		t.Fatalf("box b must not reach box a's origin, got %d", resp.StatusCode)
	}
}
