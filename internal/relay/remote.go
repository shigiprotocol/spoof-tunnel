package relay

import (
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/ParsaKSH/spoof-tunnel/internal/transport"
)

// RemoteConfig configures the remote (server) relay.
type RemoteConfig struct {
	ListenPort      uint16
	ForwardAddr     string
	ClientIP        net.IP
	ClientPort      uint16
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

type Remote struct {
	cfg     RemoteConfig
	recver  transport.Receiver
	sender  *swapSender
	accept  acceptSet
	stop    chan struct{}
	udpConn *net.UDPConn
	fwdAddr *net.UDPAddr

	up       atomic.Uint64
	down     atomic.Uint64
	upPkts   atomic.Uint64
	downPkts atomic.Uint64

	icmpSuppressed bool
}

func NewRemote(cfg RemoteConfig) (*Remote, error) {
	if cfg.SendTransport == "" {
		cfg.SendTransport = transport.TransportUDP
	}
	if cfg.RecvTransport == "" {
		cfg.RecvTransport = transport.TransportTCP
	}

	icmpSuppressed := false
	if cfg.RecvTransport == transport.TransportICMP || cfg.RecvTransport == transport.TransportICMPv6 {
		if suppressICMPEchoReply() {
			icmpSuppressed = true
		}
	}

	// A set of accepted peer sources means accept-any at the receiver (nil) and
	// filter the set here in Go; a single pinned peer keeps kernel/Rust filtering.
	recvPeer := cfg.PeerSpoofIP
	if len(cfg.PeerSpoofIPs) > 0 {
		recvPeer = nil
	}
	recver, err := transport.NewReceiver(cfg.RecvTransport, transport.ReceiverConfig{
		ListenPort:   cfg.ListenPort,
		PeerSpoofIP:  recvPeer,
		BufferSize:   4 * 1024 * 1024,
		UseXDP:       cfg.XDPInterface != "",
		XDPInterface: cfg.XDPInterface,
	})
	if err != nil {
		if icmpSuppressed {
			restoreICMPEchoReply()
		}
		return nil, err
	}

	fwdAddr, err := net.ResolveUDPAddr("udp4", cfg.ForwardAddr)
	if err != nil {
		recver.Close()
		if icmpSuppressed {
			restoreICMPEchoReply()
		}
		return nil, err
	}

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		recver.Close()
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
		recver.Close()
		udpConn.Close()
		if icmpSuppressed {
			restoreICMPEchoReply()
		}
		return nil, err
	}

	r := &Remote{
		cfg:            cfg,
		recver:         recver,
		sender:         sender,
		udpConn:        udpConn,
		fwdAddr:        fwdAddr,
		stop:           make(chan struct{}),
		icmpSuppressed: icmpSuppressed,
	}
	r.accept.set(cfg.PeerSpoofIPs)
	return r, nil
}

func (r *Remote) Run() {
	go r.uplinkLoop()
	go r.statsLoop()
	go poolReloader(r.stop, defaultReloadInterval,
		r.cfg.SpoofIPFile, func(ips []net.IP) {
			if err := r.sender.setIPs(ips); err != nil {
				log.Printf("[reload] applying forged sources: %v", err)
			}
		},
		r.cfg.PeerSpoofIPFile, r.accept.set)
	r.downlinkLoop()
}

func (r *Remote) uplinkLoop() {
	for {
		data, srcIP, _, err := r.recver.Receive()
		if err != nil {
			return
		}
		if len(data) == 0 {
			continue
		}
		if !r.accept.allow(srcIP) {
			continue
		}
		if _, err := r.udpConn.WriteToUDP(data, r.fwdAddr); err != nil {
			continue
		}
		r.up.Add(uint64(len(data)))
		r.upPkts.Add(1)
	}
}

func (r *Remote) downlinkLoop() {
	buf := make([]byte, 65536)
	for {
		n, _, err := r.udpConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if n == 0 {
			continue
		}
		if err := r.sender.Send(buf[:n], r.cfg.ClientIP, r.cfg.ClientPort); err != nil {
			continue
		}
		r.down.Add(uint64(n))
		r.downPkts.Add(1)
	}
}

func (r *Remote) statsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		log.Printf("[remote] stats: up=%d pkts (%s) | down=%d pkts (%s)",
			r.upPkts.Load(), formatBytes(r.up.Load()),
			r.downPkts.Load(), formatBytes(r.down.Load()))
	}
}

func (r *Remote) Close() {
	select {
	case <-r.stop:
	default:
		close(r.stop)
	}
	r.recver.Close()
	r.sender.Close()
	r.udpConn.Close()
	if r.icmpSuppressed {
		restoreICMPEchoReply()
	}
}

func (r *Remote) Stats() (up, down uint64) {
	return r.up.Load(), r.down.Load()
}
