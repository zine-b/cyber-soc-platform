package security

import "testing"

func TestParseLinuxAuthLog(t *testing.T) {
	parsed := ParseLinuxAuthLog("Failed password for root from 185.10.20.30 port 52344 ssh2")
	if parsed["action"] != "login_failed" || parsed["username"] != "root" || parsed["source_ip"] != "185.10.20.30" {
		t.Fatalf("unexpected parsed log: %#v", parsed)
	}
}

func TestParseUnknownLog(t *testing.T) {
	parsed := ParseLinuxAuthLog("service started")
	if parsed["category"] != "unknown" || parsed["source_ip"] != nil {
		t.Fatalf("unexpected parsed log: %#v", parsed)
	}
}
