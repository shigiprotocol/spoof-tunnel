package relay

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/ParsaKSH/spoof-tunnel/internal/config"
	"github.com/ParsaKSH/spoof-tunnel/internal/transport"
)

// defaultReloadInterval is how often the spoof-IP pool file(s) are re-read.
const defaultReloadInterval = 30 * time.Second

// swapSender wraps a transport.Sender so the set of forged source IPs can be
// hot-swapped at runtime without stopping the tunnel: on a pool change a new
// sender is built with the new IPs and swapped in atomically, and the old one
// is closed after a short grace period so in-flight sends finish. The hot send
// path stays lock-free — one atomic load per packet — so the fast Rust data
// plane is untouched.
type swapSender struct {
	cur       atomic.Pointer[senderBox]
	transport string
	port      uint16
	mtu       int
}

type senderBox struct{ s transport.Sender }

func newSwapSender(tr string, port uint16, mtu int, ips []net.IP) (*swapSender, error) {
	ss := &swapSender{transport: tr, port: port, mtu: mtu}
	s, err := ss.make(ips)
	if err != nil {
		return nil, err
	}
	ss.cur.Store(&senderBox{s})
	return ss, nil
}

func (ss *swapSender) make(ips []net.IP) (transport.Sender, error) {
	return transport.NewSender(ss.transport, transport.SenderConfig{
		SourceIPs:  ips,
		SourcePort: ss.port,
		MTU:        ss.mtu,
	})
}

// Send forwards to the current underlying sender, lock-free.
func (ss *swapSender) Send(payload []byte, dstIP net.IP, dstPort uint16) error {
	return ss.cur.Load().s.Send(payload, dstIP, dstPort)
}

// setIPs rebuilds the sender with a new forged-source pool and swaps it in.
func (ss *swapSender) setIPs(ips []net.IP) error {
	if len(ips) == 0 {
		return nil
	}
	s, err := ss.make(ips)
	if err != nil {
		return err
	}
	old := ss.cur.Swap(&senderBox{s})
	if old != nil {
		go func(b *senderBox) {
			time.Sleep(2 * time.Second) // let in-flight sends on the old socket drain
			b.s.Close()
		}(old)
	}
	return nil
}

func (ss *swapSender) Close() error {
	if b := ss.cur.Load(); b != nil {
		return b.s.Close()
	}
	return nil
}

// acceptSet is the set of peer forged source IPs accepted on receive. It is
// swapped atomically on a hot reload. A nil set means "accept any source",
// which is the original behaviour and the path used when a single peer IP is
// pinned at the receiver (and the kernel/Rust side filters instead).
type acceptSet struct {
	m atomic.Pointer[map[[4]byte]struct{}]
}

func buildAcceptSet(ips []net.IP) *map[[4]byte]struct{} {
	if len(ips) == 0 {
		return nil
	}
	m := make(map[[4]byte]struct{}, len(ips))
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		var k [4]byte
		copy(k[:], v4)
		m[k] = struct{}{}
	}
	return &m
}

func (a *acceptSet) set(ips []net.IP) { a.m.Store(buildAcceptSet(ips)) }

// allow reports whether a received packet's forged source is accepted.
func (a *acceptSet) allow(src net.IP) bool {
	mp := a.m.Load()
	if mp == nil {
		return true // no set configured: accept any (receiver did the filtering)
	}
	if src == nil {
		return false
	}
	v4 := src.To4()
	if v4 == nil {
		return false
	}
	var k [4]byte
	copy(k[:], v4)
	_, ok := (*mp)[k]
	return ok
}

// fileSig is a cheap change detector for a pool file: size and mtime.
func fileSig(path string) string {
	if path == "" {
		return ""
	}
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d:%d", fi.Size(), fi.ModTime().UnixNano())
}

// poolReloader re-reads the forged-source pool file and the peer-source pool
// file every reloadEvery and applies any change, so an external updater (this
// project's own tester, or your scanner) can refresh the live IP set with no
// restart. apply receives the sender's new source pool; applyPeer receives the
// new accept set. Either file path may be empty.
func poolReloader(stop <-chan struct{}, reloadEvery time.Duration,
	srcFile string, apply func([]net.IP),
	peerFile string, applyPeer func([]net.IP)) {

	if srcFile == "" && peerFile == "" {
		return
	}
	if reloadEvery <= 0 {
		reloadEvery = defaultReloadInterval
	}
	lastSrc := fileSig(srcFile)
	lastPeer := fileSig(peerFile)
	t := time.NewTicker(reloadEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if srcFile != "" {
				if sig := fileSig(srcFile); sig != "" && sig != lastSrc {
					if ips, err := config.LoadIPListFile(srcFile); err == nil {
						apply(ips)
						lastSrc = sig
						log.Printf("[reload] forged-source pool: %d IP(s) from %s", len(ips), srcFile)
					} else {
						log.Printf("[reload] %s: %v", srcFile, err)
					}
				}
			}
			if peerFile != "" {
				if sig := fileSig(peerFile); sig != "" && sig != lastPeer {
					if ips, err := config.LoadIPListFile(peerFile); err == nil {
						applyPeer(ips)
						lastPeer = sig
						log.Printf("[reload] peer-source accept set: %d IP(s) from %s", len(ips), peerFile)
					} else {
						log.Printf("[reload] %s: %v", peerFile, err)
					}
				}
			}
		}
	}
}
