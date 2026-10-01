package dns

import "testing"

func TestConfigureClearsPreviousFallback(t *testing.T) {
	resolver := NewResolver(nil)
	resolver.Configure(ProtocolDoH, "9.9.9.9", "94.140.14.14", "https://example.test/dns-query")
	resolver.Configure(ProtocolPlain, "192.0.2.53", "", "")

	if resolver.primaryServer != "192.0.2.53" {
		t.Fatalf("primary = %q", resolver.primaryServer)
	}
	if resolver.fallbackServer != "" {
		t.Fatalf("old fallback persisted: %q", resolver.fallbackServer)
	}
	if resolver.dohURL != "" || resolver.protocol != ProtocolPlain {
		t.Fatalf("old transport persisted: protocol=%v, url=%q", resolver.protocol, resolver.dohURL)
	}
}
