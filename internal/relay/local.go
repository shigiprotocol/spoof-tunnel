package relay

import (
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/ParsaKSH/spoof-tunnel/internal/transport"
)

// LocalConfig configures the local (client) relay.
type LocalConfig struct {
	ListenAddr      string
	RemoteIP        net.IP
	RemotePort      uint16
	RecvPort        uint16
	SpoofIP         net.IP
	SpoofIPs        []net.IP
	SpoofIPFile     string // pool file for hot-reload of forged sources (empty = none)
	SpoofPort       uint16
	PeerSpoofIP     net.IP   // single pinned peer source (back-compat)
	PeerSpoofIPs    []net.IP // set of accepted peer sources (multi-IP); empty = use PeerSpoofIP
	PeerSpoofIPFile string   // pool file for hot-reload of the accept set (empty = none)
	SendTransport   string   // "tcp", "udp", "icmp", "icmpv6"
	RecvTransport   string   // "tcp", "udp", "icmp", "icmpv6"
	XDPInterface    string   // network interface for XDP (empty = disabled)
}

type Local struct {
	cfg     LocalConfig
	udpConn *net.UDPConn
	sender  *swapSender
	accept  acceptSet
	stop    chan struct{}
	recver  transport.Receiver

	lastAppAddr atomic.Pointer[net.UDPAddr]

	up       atomic.Uint64
	down     atomic.Uint64
	upPkts   atomic.Uint64
	downPkts atomic.Uint64

	icmpSuppressed bool
}

func NewLocal(cfg LocalConfig) (*Local, error) {
	if cfg.SendTransport == "" {
		cfg.SendTransport = transport.TransportTCP
	}
	if cfg.RecvTransport == "" {
		cfg.RecvTransport = transport.TransportUDP
	}

	icmpSuppressed := false
	if cfg.RecvTransport == transport.TransportICMP || cfg.RecvTransport == transport.TransportICMPv6 {
		if suppressICMPEchoReply() {
			icmpSuppressed = true
		}
	}

	addr, err := net.ResolveUDPAddr("udp4", cfg.ListenAddr)
	if err != nil {
		if icmpSuppressed {
			restoreICMPEchoReply()
		}
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		if icmpSuppressed {
			restoreICMPEchoReply()
		}
		return nil, err
	}

	senderIPs := cfg.SpoofIPs
	if len(senderIPs) == 0 {
		senderIPs = []net.IP{cfg.SpoofIP}
	}
	sender, err := newSwapSender(cfg.SendTransport, cfg.SpoofPort, 1400, senderIPs)
	if err != nil {
		udpConn.Close()
		if icmpSuppressed {
			restoreICMPEchoReply()
		}
		return nil, err
	}

	// With a set of accepted peer sources, let the receiver accept any source
	// (pass nil) and filter the set here in Go, so the peer can rotate a pool of
	// forged sources without the receiver dropping all but one. A single pinned
	// peer IP keeps the original kernel/Rust-side filtering.
	recvPeer := cfg.PeerSpoofIP
	if len(cfg.PeerSpoofIPs) > 0 {
		recvPeer = nil
	}
	recver, err := transport.NewReceiver(cfg.RecvTransport, transport.ReceiverConfig{
		ListenPort:   cfg.RecvPort,
		PeerSpoofIP:  recvPeer,
		BufferSize:   4 * 1024 * 1024,
		UseXDP:       cfg.XDPInterface != "",
		XDPInterface: cfg.XDPInterface,
	})
	if err != nil {
		udpConn.Close()
		sender.Close()
		if icmpSuppressed {
			restoreICMPEchoReply()
		}
		return nil, err
	}

	l := &Local{
		cfg:            cfg,
		udpConn:        udpConn,
		sender:         sender,
		recver:         recver,
		stop:           make(chan struct{}),
		icmpSuppressed: icmpSuppressed,
	}
	l.accept.set(cfg.PeerSpoofIPs)
	return l, nil
}

func (l *Local) Run() {
	go l.uplinkLoop()
	go l.statsLoop()
	go poolReloader(l.stop, defaultReloadInterval,
		l.cfg.SpoofIPFile, func(ips []net.IP) {
			if err := l.sender.setIPs(ips); err != nil {
				log.Printf("[reload] applying forged sources: %v", err)
			}
		},
		l.cfg.PeerSpoofIPFile, l.accept.set)
	l.downlinkLoop()
}

func (l *Local) uplinkLoop() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := l.udpConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if n == 0 {
			continue
		}
		l.lastAppAddr.Store(addr)
		if err := l.sender.Send(buf[:n], l.cfg.RemoteIP, l.cfg.RemotePort); err != nil {
			continue
		}
		l.up.Add(uint64(n))
		l.upPkts.Add(1)
	}
}

func (l *Local) downlinkLoop() {
	for {
		data, srcIP, _, err := l.recver.Receive()
		if err != nil {
			return
		}
		if len(data) == 0 {
			continue
		}
		// Drop packets whose forged source is not in the accepted peer set
		// (no-op when no set is configured).
		if !l.accept.allow(srcIP) {
			continue
		}
		appAddr := l.lastAppAddr.Load()
		if appAddr == nil {
			continue
		}
		if _, err := l.udpConn.WriteToUDP(data, appAddr); err != nil {
			continue
		}
		l.down.Add(uint64(len(data)))
		l.downPkts.Add(1)
	}
}

func (l *Local) statsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		log.Printf("[local] stats: up=%d pkts (%s) | down=%d pkts (%s)",
			l.upPkts.Load(), formatBytes(l.up.Load()),
			l.downPkts.Load(), formatBytes(l.down.Load()))
	}
}

func (l *Local) Close() {
	select {
	case <-l.stop:
	default:
		close(l.stop)
	}
	l.udpConn.Close()
	l.sender.Close()
	l.recver.Close()
	if l.icmpSuppressed {
		restoreICMPEchoReply()
	}
}

func (l *Local) Stats() (up, down uint64) {
	return l.up.Load(), l.down.Load()
}
