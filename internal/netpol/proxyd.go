// Host proxy daemon for the vm backend: one daemon per state root,
// one listener per box. A private kernel per box is already the dominant
// cost of the vm tier, so the policy engine is shared — but sharing MUST NOT
// weaken per-box policy: each listener evaluates only its own box's
// effective set, and audit lines land in that box's own log.
//
// The daemon is the same agentbox binary running the hidden `proxyd`
// subcommand. Listeners are declared as spec files in a spool directory;
// the daemon reconciles the spool once a second, so the backend adds or
// removes a listener by writing or deleting a file — no daemon protocol.
package netpol

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ListenerSpec is one box's proxy listener, serialized into the spool as
// <resource>.json. It carries the box's evaluated policy rather than a
// reference to configuration: the policy was frozen when the box was
// created, and the daemon must not re-resolve it.
type ListenerSpec struct {
	BoxID    string `json:"box_id"`
	Resource string `json:"resource"`
	// Addr is a TCP address to bind (container-style bridge gateway).
	// Empty when the box reaches the daemon over vsock instead.
	Addr string `json:"addr,omitempty"`
	// Token attributes an incoming vsock connection to this box. Set for
	// vm-tier boxes, which have no per-box address to bind. It is a
	// capability: whoever holds it egresses under this box's policy, so it
	// is minted per box at create time and never reused.
	Token          string   `json:"token,omitempty"`
	Mode           string   `json:"mode"`
	Allow          []string `json:"allow"`
	Deny           []string `json:"deny"`
	Audit          bool     `json:"audit"`
	AuditPath      string   `json:"audit_path"`
	ReadTimeout    string   `json:"read_timeout"`    // idle budget for an established tunnel
	RequestTimeout string   `json:"request_timeout"` // budget for reading the request
}

func (ls *ListenerSpec) policy() *Policy {
	return &Policy{Mode: ls.Mode, Allow: ls.Allow, Deny: ls.Deny, Audit: ls.Audit}
}

func parseTimeout(s string, fallback time.Duration) time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(s)); err == nil && d > 0 {
		return d
	}
	return fallback
}

// Spool and pidfile layout under the agentbox state root.
func ProxydDir(stateRoot string) string   { return filepath.Join(stateRoot, "proxyd") }
func SpoolDir(stateRoot string) string    { return filepath.Join(ProxydDir(stateRoot), "listeners") }
func PidfilePath(stateRoot string) string { return filepath.Join(ProxydDir(stateRoot), "proxyd.pid") }
func LogPath(stateRoot string) string     { return filepath.Join(ProxydDir(stateRoot), "proxyd.log") }

// WriteListenerSpec atomically declares (or replaces) a box's listener.
func WriteListenerSpec(stateRoot string, ls *ListenerSpec) error {
	dir := SpoolDir(stateRoot)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	blob, err := json.MarshalIndent(ls, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, ls.Resource+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(blob, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RemoveListenerSpec retracts a box's listener; the daemon closes it on the
// next reconcile pass. Missing is not an error: retraction is idempotent.
func RemoveListenerSpec(stateRoot, resource string) error {
	err := os.Remove(filepath.Join(SpoolDir(stateRoot), resource+".json"))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// ReadListenerSpec loads a declared listener, for `logs --proxy` and status.
func ReadListenerSpec(stateRoot, resource string) (*ListenerSpec, error) {
	blob, err := os.ReadFile(filepath.Join(SpoolDir(stateRoot), resource+".json"))
	if err != nil {
		return nil, err
	}
	var ls ListenerSpec
	if err := json.Unmarshal(blob, &ls); err != nil {
		return nil, err
	}
	return &ls, nil
}

// pidAlive reports whether pid exists and is signalable.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

func readPidfile(path string) int {
	blob, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(blob)))
	return pid
}

// EnsureDaemon makes sure a proxyd serves this state root, spawning the
// current executable detached if none is alive. Racing spawns are resolved
// by the pidfile: the loser exits quietly.
func EnsureDaemon(stateRoot, selfExe string) error {
	if pidAlive(readPidfile(PidfilePath(stateRoot))) {
		return nil
	}
	if err := os.MkdirAll(ProxydDir(stateRoot), 0o700); err != nil {
		return err
	}
	logf, err := os.OpenFile(LogPath(stateRoot), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	cmd := exec.Command(selfExe, "proxyd", "--state-root", stateRoot)
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawning proxyd: %w", err)
	}
	return cmd.Process.Release()
}

// WaitListener blocks until the listener accepts connections: the
// guest is not ready before its proxy is.
func WaitListener(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("proxy listener %s did not come up within %s: %w", addr, timeout, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// RunDaemon is the `agentbox proxyd` entry point: acquire the pidfile,
// reconcile the spool until told to stop or left idle.
func RunDaemon(ctx context.Context, stateRoot string, logw io.Writer) error {
	pidPath := PidfilePath(stateRoot)
	if err := os.MkdirAll(ProxydDir(stateRoot), 0o700); err != nil {
		return err
	}
	if pid := readPidfile(pidPath); pidAlive(pid) && pid != os.Getpid() {
		return nil // another daemon already serves this state root
	}
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		return err
	}
	defer os.Remove(pidPath)

	p := &Proxyd{SpoolDir: SpoolDir(stateRoot), Logf: func(format string, a ...any) {
		fmt.Fprintf(logw, time.Now().UTC().Format(time.RFC3339)+" "+format+"\n", a...)
	}}
	p.Logf("proxyd started, spool %s", p.SpoolDir)
	return p.Run(ctx)
}

// Proxyd reconciles the spool with a set of live listeners.
type Proxyd struct {
	SpoolDir string
	Logf     func(format string, a ...any)
	// IdleExit ends Run after the spool has been empty this long; zero
	// means run forever (tests use a short value).
	IdleExit time.Duration

	mu     sync.Mutex
	active map[string]*boxListener
	// byToken routes vsock connections to a box; vsockLn is the single
	// shared listener serving all of them (see vsockmux.go).
	byToken map[string]*boxListener
	vsockLn net.Listener
}

type boxListener struct {
	raw    string // marshaled spec, for change detection
	spec   ListenerSpec
	pol    *Policy
	ln     net.Listener
	audit  *auditLog
	closed chan struct{}
}

const defaultIdleExit = 2 * time.Minute

// Run polls the spool once a second. File-granular reconciliation keeps the
// daemon protocol-free: `Start` writes a spec, `Stop`/`Remove` delete it.
func (p *Proxyd) Run(ctx context.Context) error {
	p.active = map[string]*boxListener{}
	p.byToken = map[string]*boxListener{}
	idleExit := p.IdleExit
	if idleExit == 0 {
		idleExit = defaultIdleExit
	}
	var idleSince time.Time
	defer func() {
		for name := range p.active {
			p.stopListener(name)
		}
	}()
	for {
		p.reconcile()
		if len(p.active) == 0 {
			if idleSince.IsZero() {
				idleSince = time.Now()
			} else if time.Since(idleSince) > idleExit {
				p.Logf("no listeners for %s; exiting", idleExit)
				return nil
			}
		} else {
			idleSince = time.Time{}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
	}
}

func (p *Proxyd) reconcile() {
	ents, err := os.ReadDir(p.SpoolDir)
	if err != nil && !os.IsNotExist(err) {
		p.Logf("reading spool: %v", err)
		return
	}
	seen := map[string]bool{}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		blob, err := os.ReadFile(filepath.Join(p.SpoolDir, e.Name()))
		if err != nil {
			continue
		}
		var spec ListenerSpec
		if err := json.Unmarshal(blob, &spec); err != nil {
			p.Logf("spec %s: %v", e.Name(), err)
			continue
		}
		seen[e.Name()] = true
		cur, ok := p.active[e.Name()]
		if ok && cur.raw == string(blob) {
			continue // unchanged
		}
		if ok {
			p.stopListener(e.Name())
		}
		if err := p.startListener(e.Name(), string(blob), spec); err != nil {
			p.Logf("listener %s (%s): %v", spec.Resource, spec.Addr, err)
		}
	}
	for name := range p.active {
		if !seen[name] {
			p.stopListener(name)
		}
	}
}

func (p *Proxyd) startListener(name, raw string, spec ListenerSpec) error {
	bl := &boxListener{raw: raw, spec: spec, pol: spec.policy(), closed: make(chan struct{})}
	if spec.Audit && spec.AuditPath != "" {
		bl.audit = &auditLog{path: spec.AuditPath}
	}
	// A vsock-attached box binds nothing of its own: it is registered
	// against the shared listener by token.
	if spec.Token != "" {
		p.mu.Lock()
		defer p.mu.Unlock()
		if err := p.ensureVsock(); err != nil {
			return err
		}
		p.active[name] = bl
		p.byToken[spec.Token] = bl
		p.Logf("listener up: %s on vsock:%d (%d allow, %d deny)",
			spec.Resource, VsockPort, len(spec.Allow), len(spec.Deny))
		return nil
	}
	ln, err := net.Listen("tcp", spec.Addr)
	if err != nil {
		return err
	}
	bl.ln = ln
	p.mu.Lock()
	p.active[name] = bl
	p.mu.Unlock()
	p.Logf("listener up: %s on %s (%d allow, %d deny)", spec.Resource, spec.Addr, len(spec.Allow), len(spec.Deny))
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-bl.closed:
				default:
					p.Logf("accept on %s: %v", spec.Addr, err)
				}
				return
			}
			go bl.handle(conn)
		}
	}()
	return nil
}

func (p *Proxyd) stopListener(name string) {
	p.mu.Lock()
	bl, ok := p.active[name]
	if ok {
		delete(p.active, name)
		if bl.spec.Token != "" {
			// Retract the token first: a stopped box must stop egressing
			// even if its forwarder is still connected and retrying.
			delete(p.byToken, bl.spec.Token)
			p.closeVsock()
		}
	}
	p.mu.Unlock()
	if !ok {
		return
	}
	close(bl.closed)
	if bl.ln != nil {
		bl.ln.Close()
	}
	bl.audit.Close()
	where := bl.spec.Addr
	if bl.spec.Token != "" {
		where = fmt.Sprintf("vsock:%d", VsockPort)
	}
	p.Logf("listener down: %s (%s)", bl.spec.Resource, where)
}

// handle serves one client connection: a CONNECT tunnel or one plain
// absolute-form HTTP request. TLS is never intercepted: the match is
// on the CONNECT target, certificate validation stays end-to-end.
func (bl *boxListener) handle(conn net.Conn) {
	bl.handleBuffered(conn, bufio.NewReader(conn))
}

// handleBuffered is handle over a reader that may already hold bytes — the
// vsock path consumes its token preamble through one, and the first request
// can arrive in the same segment.
func (bl *boxListener) handleBuffered(conn net.Conn, br *bufio.Reader) {
	defer conn.Close()
	reqTimeout := parseTimeout(bl.spec.RequestTimeout, 5*time.Minute)
	idleTimeout := parseTimeout(bl.spec.ReadTimeout, time.Hour)
	client := conn.RemoteAddr().String()
	if h, _, err := net.SplitHostPort(client); err == nil {
		client = h
	}

	_ = conn.SetReadDeadline(time.Now().Add(reqTimeout))
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		bl.handleConnect(conn, req, client, idleTimeout)
		return
	}
	bl.handleForward(conn, req, client)
}

func (bl *boxListener) deny(conn net.Conn, client, method, target string) {
	bl.audit.line(client, "TCP_DENIED/403", method, target)
	body := fmt.Sprintf("agentbox: egress to %s is not in this box's allowlist\n", target)
	fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

func (bl *boxListener) handleConnect(conn net.Conn, req *http.Request, client string, idle time.Duration) {
	host, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		host, port = req.Host, "443"
	}
	// Mirror the sidecar's SSL_ports restriction: CONNECT is for TLS only.
	if port != "443" || !bl.pol.Allowed(host) {
		bl.deny(conn, client, req.Method, req.Host)
		return
	}
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 30*time.Second)
	if err != nil {
		bl.audit.line(client, "TCP_TUNNEL/502", req.Method, req.Host)
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
		return
	}
	defer upstream.Close()
	bl.audit.line(client, "TCP_TUNNEL/200", req.Method, req.Host)
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	tunnel(conn, upstream, idle)
}

// tunnel copies both directions until either side closes or the idle budget
// elapses — read_timeout exists so a streamed model response is not severed
// mid-flight, not to keep dead tunnels forever.
func tunnel(a, b net.Conn, idle time.Duration) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			_ = src.SetReadDeadline(time.Now().Add(idle))
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		// Half-close so the peer's copy loop sees EOF instead of idling.
		// Matched by interface, not type: the vm tier's client side is a
		// vsock conn, which half-closes the same way.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

// hop-by-hop headers stripped from forwarded plain-HTTP requests, plus the
// client-identifying set that must be removed.
var strippedHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	"X-Forwarded-For", "Via", "Forwarded",
}

func (bl *boxListener) handleForward(conn net.Conn, req *http.Request, client string) {
	if req.URL == nil || req.URL.Host == "" {
		bl.deny(conn, client, req.Method, req.RequestURI)
		return
	}
	host := req.URL.Hostname()
	target := req.URL.String()
	if !bl.pol.Allowed(host) {
		bl.deny(conn, client, req.Method, target)
		return
	}
	out := req.Clone(req.Context())
	out.RequestURI = ""
	for _, h := range strippedHeaders {
		out.Header.Del(h)
	}
	tr := &http.Transport{DisableKeepAlives: true, Proxy: nil}
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(out)
	if err != nil {
		bl.audit.line(client, "TCP_MISS/502", req.Method, target)
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
		return
	}
	defer resp.Body.Close()
	bl.audit.line(client, fmt.Sprintf("TCP_MISS/%03d", resp.StatusCode), req.Method, target)
	resp.Header.Del("Connection")
	resp.Close = true
	_ = resp.Write(conn)
}

// auditLog appends squid-shaped lines (one line per request, denials
// distinguishable) so `logs --denied` filters identically under both tiers.
type auditLog struct {
	path string
	mu   sync.Mutex
	f    *os.File
}

func (a *auditLog) line(client, action, method, target string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
			return
		}
		f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return
		}
		a.f = f
	}
	now := time.Now()
	fmt.Fprintf(a.f, "%d.%03d %s %s %s %s\n", now.Unix(), now.Nanosecond()/1e6, client, action, method, target)
}

func (a *auditLog) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f != nil {
		a.f.Close()
		a.f = nil
	}
}
