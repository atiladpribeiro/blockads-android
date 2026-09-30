package tunnel

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

type allowlistAppResolver struct{ packageName string }

func (r allowlistAppResolver) ResolveApp(int, []byte, []byte, int) string {
	return r.packageName
}

type blockingDomainChecker struct{}

func (blockingDomainChecker) IsBlocked(string) bool        { return true }
func (blockingDomainChecker) GetBlockReason(string) string { return "filter_list" }
func (blockingDomainChecker) HasCustomRule(string) int     { return -1 }

type allowlistResponseWriter struct{ response *dns.Msg }

func (w *allowlistResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 15353}
}
func (w *allowlistResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 34567}
}
func (w *allowlistResponseWriter) WriteMsg(m *dns.Msg) error { w.response = m; return nil }
func (w *allowlistResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (w *allowlistResponseWriter) Close() error              { return nil }
func (w *allowlistResponseWriter) TsigStatus() error         { return nil }
func (w *allowlistResponseWriter) TsigTimersOnly(bool)       {}
func (w *allowlistResponseWriter) Hijack()                   {}

func TestRootAllowlistBypassesDomainFilter(t *testing.T) {
	for _, tc := range []struct {
		name    string
		app     string
		allowed string
		blocked int64
	}{
		{"allowed app", "com.example.allowed", "com.example.allowed", 0},
		{"other app", "com.example.allowed", "com.example.other", 1},
		{"unidentified app", "", "com.example.other", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngine()
			e.SetAppResolver(allowlistAppResolver{packageName: tc.app})
			e.SetDomainChecker(blockingDomainChecker{})
			e.SetAllowedApps(tc.allowed)
			q := new(dns.Msg)
			q.SetQuestion("ads.example.", dns.TypeA)
			w := &allowlistResponseWriter{}
			e.ServeDNS(w, q)
			if w.response == nil {
				t.Fatal("no DNS response")
			}
			if got := e.blockedQueries.Load(); got != tc.blocked {
				t.Fatalf("blocked queries = %d, want %d", got, tc.blocked)
			}
		})
	}
}
