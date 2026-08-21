package wgconfig

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const validConfig = `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/32, fd00::2/128
DNS = 1.1.1.1
PostUp = definitely-not-a-command

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
PresharedKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
Endpoint = vpn.example:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`

func TestParseValidConfig(t *testing.T) {
	config, err := parseScanner(validConfig)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Addresses) != 2 || len(config.Peers) != 1 || len(config.Peers[0].AllowedIPs) != 2 {
		t.Fatalf("unexpected parsed configuration: %#v", config)
	}
	if config.Peers[0].Endpoint != "vpn.example:51820" || config.Peers[0].PersistentKeepalive != 25 {
		t.Fatalf("unexpected peer: %#v", config.Peers[0])
	}
}

func TestParseNeverIncludesSecretValueInError(t *testing.T) {
	secret := "not-a-valid-private-key"
	_, err := parseScanner("[Interface]\nPrivateKey = " + secret + "\n")
	if err == nil {
		t.Fatal("parse unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked secret: %v", err)
	}
}

func TestParseRequiresSingleUsablePeer(t *testing.T) {
	withoutEndpoint := strings.Replace(validConfig, "Endpoint = vpn.example:51820\n", "", 1)
	_, err := parseScanner(withoutEndpoint)
	if err == nil || !strings.Contains(err.Error(), "Peer.Endpoint is required") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	_, err := parseScanner(strings.Replace(validConfig, "DNS = 1.1.1.1", "Surprise = yes", 1))
	if err == nil || !strings.Contains(err.Error(), "unsupported Interface field") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseAcceptsDisabledKeepalive(t *testing.T) {
	config, err := parseScanner(strings.Replace(validConfig, "PersistentKeepalive = 25", "PersistentKeepalive = off", 1))
	if err != nil {
		t.Fatal(err)
	}
	if config.Peers[0].PersistentKeepalive != 0 {
		t.Fatalf("PersistentKeepalive = %d", config.Peers[0].PersistentKeepalive)
	}
}

func TestLoadRejectsPermissivePrivateKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg.conf")
	if err := os.WriteFile(path, []byte(validConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "must not be accessible") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestSanitizedCompatibilityCorpus(t *testing.T) {
	fixtures, err := filepath.Glob(filepath.Join("testdata", "*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(fixtures)
	if len(fixtures) < 3 {
		t.Fatalf("compatibility corpus has only %d fixtures", len(fixtures))
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(strings.TrimSuffix(filepath.Base(fixture), filepath.Ext(fixture)), func(t *testing.T) {
			contents, err := os.ReadFile(fixture)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "provider.conf")
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			parsed, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(parsed.Peers) != 1 || parsed.Peers[0].Endpoint == "" {
				t.Fatalf("unexpected parsed fixture: %#v", parsed)
			}
		})
	}
}

func parseScanner(text string) (*Config, error) {
	return parse(bufio.NewScanner(strings.NewReader(text)))
}
