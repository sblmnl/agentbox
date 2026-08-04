// AF_VSOCK transport for the vm tier's egress proxy.
//
// The bridge is not a dependable path from a VM guest to a host process.
// It is subject to the host's INPUT policy and, more awkwardly, to VPN
// kill-switches that install their own nftables table and accept only
// RFC 1918 as "local network" — such a ruleset drops guest->host traffic in
// both directions, before iptables sees it, leaving no counter and no log.
// vsock is a hypervisor channel: it carries no IP, traverses no bridge, and
// is invisible to netfilter, so the guest's path to its proxy cannot be
// severed by host firewall or VPN state.
//
// The kernel ABI needed here is four constants and a 16-byte sockaddr,
// which is less code than a socket library would cost — agentbox keeps its
// single dependency.
package netpol

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	afVsock = 40
	// VMADDR_CID_HOST: the host, addressed from inside a guest.
	CIDHost = 2
	// VMADDR_CID_ANY: bind on the host to accept from any guest.
	cidAny = uint32(0xFFFFFFFF)
)

// VsockPort is the port the host proxy accepts guest connections on. It is
// fixed: unlike the bridge scheme there is no per-box address to allocate,
// because connections are attributed by the token preamble (and audited by
// the kernel-supplied peer CID, which a guest cannot forge).
const VsockPort = 3128

// sockaddrVM lays out struct sockaddr_vm: family u16, reserved u16,
// port u32, cid u32, zero[4].
func sockaddrVM(cid, port uint32) []byte {
	b := make([]byte, 16)
	*(*uint16)(unsafe.Pointer(&b[0])) = afVsock
	*(*uint32)(unsafe.Pointer(&b[4])) = port
	*(*uint32)(unsafe.Pointer(&b[8])) = cid
	return b
}

// VsockAddr is a (context id, port) pair. String is deliberately shaped so
// net.SplitHostPort parses it, which lets the audit log carry "cid<n>" as
// the client identity exactly where a bridge listener carried an IP.
type VsockAddr struct {
	CID  uint32
	Port uint32
}

func (a *VsockAddr) Network() string { return "vsock" }
func (a *VsockAddr) String() string  { return fmt.Sprintf("cid%d:%d", a.CID, a.Port) }

// vsockConn adapts a vsock socket to net.Conn. The fd is nonblocking so the
// runtime poller owns it, which is what makes the deadlines the proxy
// depends on work.
type vsockConn struct {
	f             *os.File
	local, remote *VsockAddr
}

func (c *vsockConn) Read(b []byte) (int, error)         { return c.f.Read(b) }
func (c *vsockConn) Write(b []byte) (int, error)        { return c.f.Write(b) }
func (c *vsockConn) Close() error                       { return c.f.Close() }
func (c *vsockConn) LocalAddr() net.Addr                { return c.local }
func (c *vsockConn) RemoteAddr() net.Addr               { return c.remote }
func (c *vsockConn) SetDeadline(t time.Time) error      { return c.f.SetDeadline(t) }
func (c *vsockConn) SetReadDeadline(t time.Time) error  { return c.f.SetReadDeadline(t) }
func (c *vsockConn) SetWriteDeadline(t time.Time) error { return c.f.SetWriteDeadline(t) }

// CloseWrite half-closes, so the peer's copy loop sees EOF rather than
// idling until the tunnel budget expires. tunnel() looks for this method.
func (c *vsockConn) CloseWrite() error {
	rc, err := c.f.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = syscall.Shutdown(int(fd), syscall.SHUT_WR) }); err != nil {
		return err
	}
	return serr
}

// rawAccept4 is accept4(2) spelled out. syscall.Accept4 cannot be used: it
// runs the result through anyToSockaddr, which rejects AF_VSOCK and closes
// the freshly accepted fd on the way out.
func rawAccept4(fd uintptr) (nfd int, cid, port uint32, err error) {
	var rsa [16]byte
	l := uint32(len(rsa))
	n, _, e := syscall.Syscall6(syscall.SYS_ACCEPT4, fd,
		uintptr(unsafe.Pointer(&rsa[0])), uintptr(unsafe.Pointer(&l)),
		uintptr(syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC), 0, 0)
	if e != 0 {
		return 0, 0, 0, e
	}
	port = *(*uint32)(unsafe.Pointer(&rsa[4]))
	cid = *(*uint32)(unsafe.Pointer(&rsa[8]))
	return int(n), cid, port, nil
}

type vsockListener struct {
	f    *os.File
	addr *VsockAddr
}

func (l *vsockListener) Addr() net.Addr { return l.addr }
func (l *vsockListener) Close() error   { return l.f.Close() }

func (l *vsockListener) Accept() (net.Conn, error) {
	rc, err := l.f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var (
		nfd       int
		cid, port uint32
		serr      error
	)
	// Returning false parks the goroutine in the poller until the listener
	// is readable again, so Accept blocks without a busy loop.
	ctlErr := rc.Read(func(fd uintptr) bool {
		nfd, cid, port, serr = rawAccept4(fd)
		return serr != syscall.EAGAIN
	})
	if ctlErr != nil {
		return nil, ctlErr
	}
	if serr != nil {
		return nil, &net.OpError{Op: "accept", Net: "vsock", Err: serr}
	}
	return &vsockConn{
		f:      os.NewFile(uintptr(nfd), "vsock"),
		local:  l.addr,
		remote: &VsockAddr{CID: cid, Port: port},
	}, nil
}

// ListenVsock accepts guest connections on port, from any guest.
func ListenVsock(port uint32) (net.Listener, error) {
	fd, err := syscall.Socket(afVsock, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w (is the vhost_vsock module loaded?)", err)
	}
	sa := sockaddrVM(cidAny, port)
	if _, _, e := syscall.Syscall(syscall.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(&sa[0])), 16); e != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("vsock bind port %d: %w", port, syscall.Errno(e))
	}
	if err := syscall.Listen(fd, 128); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("vsock listen: %w", err)
	}
	return &vsockListener{
		f:    os.NewFile(uintptr(fd), "vsock-listener"),
		addr: &VsockAddr{CID: cidAny, Port: port},
	}, nil
}

// DialVsock opens a connection to (cid, port). This runs in the guest, where
// the only peer that matters is CIDHost.
//
// The socket connects blocking — a nonblocking connect would mean handling
// EINPROGRESS for no benefit on a channel with no routing — and is switched
// to nonblocking before being wrapped, so the runtime poller owns it. That
// is what keeps a forwarder serving many tunnels from pinning an OS thread
// per direction.
func DialVsock(cid, port uint32) (net.Conn, error) {
	fd, err := syscall.Socket(afVsock, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	sa := sockaddrVM(cid, port)
	if _, _, e := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sa[0])), 16); e != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("vsock connect to cid %d port %d: %w", cid, port, syscall.Errno(e))
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("vsock set nonblocking: %w", err)
	}
	return &vsockConn{
		f:      os.NewFile(uintptr(fd), "vsock"),
		local:  &VsockAddr{CID: cidAny, Port: 0},
		remote: &VsockAddr{CID: cid, Port: port},
	}, nil
}
