package relay

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func ip(s string) net.IP { return net.ParseIP(s) }

func TestAcceptSetMembership(t *testing.T) {
	var a acceptSet
	// No set configured: accept any.
	if !a.allow(ip("8.8.8.8")) {
		t.Fatal("empty accept set should accept any source")
	}
	a.set([]net.IP{ip("185.10.10.5"), ip("104.16.0.2")})
	if !a.allow(ip("185.10.10.5")) || !a.allow(ip("104.16.0.2")) {
		t.Fatal("configured sources must be accepted")
	}
	if a.allow(ip("8.8.8.8")) {
		t.Fatal("a source not in the set must be rejected")
	}
	if a.allow(nil) {
		t.Fatal("a nil source must be rejected when a set is configured")
	}
}

func TestAcceptSetHotSwap(t *testing.T) {
	var a acceptSet
	a.set([]net.IP{ip("1.1.1.1")})
	if !a.allow(ip("1.1.1.1")) || a.allow(ip("2.2.2.2")) {
		t.Fatal("initial set wrong")
	}
	// Swap to a new set; the old member is gone, the new one is in.
	a.set([]net.IP{ip("2.2.2.2"), ip("3.3.3.3")})
	if a.allow(ip("1.1.1.1")) {
		t.Fatal("after swap, the old-only source must be rejected")
	}
	if !a.allow(ip("2.2.2.2")) || !a.allow(ip("3.3.3.3")) {
		t.Fatal("after swap, the new sources must be accepted")
	}
	// Swapping to empty returns to accept-any.
	a.set(nil)
	if !a.allow(ip("9.9.9.9")) {
		t.Fatal("swapping to empty should accept any again")
	}
}

func TestFileSigChanges(t *testing.T) {
	if fileSig("") != "" {
		t.Fatal("empty path should give empty signature")
	}
	if fileSig("/no/such/file/here") != "" {
		t.Fatal("missing file should give empty signature")
	}
	p := filepath.Join(t.TempDir(), "pool.txt")
	if err := os.WriteFile(p, []byte("1.1.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s1 := fileSig(p)
	if s1 == "" {
		t.Fatal("existing file should give a non-empty signature")
	}
	// A content change (different size) must change the signature.
	if err := os.WriteFile(p, []byte("1.1.1.1\n2.2.2.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if fileSig(p) == s1 {
		t.Fatal("signature should change when the file changes")
	}
}
