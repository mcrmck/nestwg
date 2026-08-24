package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAndValidate(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"entry.conf", "exit.conf"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(validWireGuardConfig), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	chain := `apiVersion: nestwg.io/v1alpha1
kind: Chain
metadata:
  name: mixed-chain
spec:
  baseMTU: 1500
  dns: [1.1.1.1, 2606:4700:4700::1111]
  hostRouting:
    mode: selected
    routes: [10.0.0.0/8]
  hops:
    - name: entry
      wireguardConfig: entry.conf
      outerFamily: ipv4
    - name: exit
      wireguardConfig: exit.conf
      outerFamily: ipv6
`
	chainPath := filepath.Join(directory, "chain.yaml")
	if err := os.WriteFile(chainPath, []byte(chain), 0o600); err != nil {
		t.Fatal(err)
	}

	document, err := Load(chainPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := document.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if got := document.Spec.Hops[0].WireGuardConfigPath; got != filepath.Join(directory, "entry.conf") {
		t.Fatalf("relative path resolved to %q", got)
	}
}

const validWireGuardConfig = `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/32

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Endpoint = vpn.example:51820
AllowedIPs = 0.0.0.0/0
`

func TestValidateRejectsInvalidWireGuardConfig(t *testing.T) {
	directory := t.TempDir()
	invalidPath := filepath.Join(directory, "invalid.conf")
	if err := os.WriteFile(invalidPath, []byte("[Interface]\nPrivateKey = secret-that-must-not-leak\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	document := &Document{
		APIVersion: APIVersion,
		Kind:       Kind,
		Metadata:   Metadata{Name: "example"},
		Spec: Spec{HostRouting: HostRouting{Mode: HostRoutingIsolated}, Hops: []Hop{
			{Name: "entry", WireGuardConfigPath: invalidPath, OuterFamily: "ipv4"},
			{Name: "exit", WireGuardConfigPath: invalidPath, OuterFamily: "ipv4"},
		}},
	}

	err := document.Validate()
	if err == nil || !strings.Contains(err.Error(), "PrivateKey") {
		t.Fatalf("Validate() error = %v", err)
	}
	if strings.Contains(err.Error(), "secret-that-must-not-leak") {
		t.Fatalf("Validate() leaked a private key: %v", err)
	}
}

func TestValidateReportsMultipleProblems(t *testing.T) {
	document := &Document{
		APIVersion: "wrong",
		Kind:       Kind,
		Metadata:   Metadata{Name: "INVALID"},
		Spec:       Spec{Hops: []Hop{{Name: "entry"}}},
	}

	err := document.Validate()
	if err == nil {
		t.Fatal("Validate() unexpectedly succeeded")
	}
	for _, expected := range []string{"apiVersion", "metadata.name", "hostRouting", "at least two hops", "wireguardConfig", "outerFamily"} {
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Validate() error %q does not contain %q", err, expected)
		}
	}
}

func TestHostRoutingValidation(t *testing.T) {
	valid := []HostRouting{
		{Mode: HostRoutingDefault},
		{Mode: HostRoutingIsolated},
		{Mode: HostRoutingSelected, Routes: []string{"10.0.0.0/8", "2001:db8::/32"}},
	}
	for _, routing := range valid {
		if err := routing.Validate(); err != nil {
			t.Errorf("Validate(%#v) = %v", routing, err)
		}
	}
	invalid := []HostRouting{
		{},
		{Mode: "other"},
		{Mode: HostRoutingDefault, Routes: []string{"10.0.0.0/8"}},
		{Mode: HostRoutingSelected},
		{Mode: HostRoutingSelected, Routes: []string{"0.0.0.0/0"}},
		{Mode: HostRoutingSelected, Routes: []string{"10.0.0.1/8", "10.0.0.0/8"}},
	}
	for _, routing := range invalid {
		if err := routing.Validate(); err == nil {
			t.Errorf("Validate(%#v) unexpectedly succeeded", routing)
		}
	}
}

func TestDocumentRejectsDNSInIsolatedMode(t *testing.T) {
	document := &Document{Spec: Spec{
		DNS:         []string{"1.1.1.1"},
		HostRouting: HostRouting{Mode: HostRoutingIsolated},
	}}
	if err := document.Validate(); err == nil || !strings.Contains(err.Error(), "not used with isolated") {
		t.Fatalf("Validate() error = %v", err)
	}
}
