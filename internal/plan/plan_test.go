package plan

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mcrmck/nestwg/internal/config"
)

type fakeResolver map[string][]netip.Addr

func (r fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	return r[network+":"+host], nil
}

func TestBuildTwoHopPlan(t *testing.T) {
	document := &config.Document{
		Metadata: config.Metadata{Name: "example"},
		Spec: config.Spec{
			BaseMTU: 1500,
			Hops: []config.Hop{
				{Name: "entry", WireGuardConfigPath: "/entry.conf", OuterFamily: "ipv4"},
				{Name: "exit", WireGuardConfigPath: "/exit.conf", OuterFamily: "ipv4"},
			},
		},
	}

	got, err := Build(document)
	if err != nil {
		t.Fatal(err)
	}
	if got.PayloadMTU != 1380 {
		t.Fatalf("PayloadMTU = %d, want 1380", got.PayloadMTU)
	}
	if got.Hops[0].BirthNamespace != "host" || got.Hops[0].InterfaceNamespace != "nwg-example-t1" {
		t.Fatalf("outer hop namespaces = %q -> %q", got.Hops[0].BirthNamespace, got.Hops[0].InterfaceNamespace)
	}
	if got.Hops[1].BirthNamespace != "nwg-example-t1" || got.Hops[1].InterfaceNamespace != "nwg-example-app" {
		t.Fatalf("inner hop namespaces = %q -> %q", got.Hops[1].BirthNamespace, got.Hops[1].InterfaceNamespace)
	}
}

func TestBuildRejectsTooManyLayersForMTU(t *testing.T) {
	document := &config.Document{Metadata: config.Metadata{Name: "small"}, Spec: config.Spec{BaseMTU: 1280}}
	for index := 0; index < 2; index++ {
		document.Spec.Hops = append(document.Spec.Hops, config.Hop{Name: "hop", OuterFamily: "ipv4"})
	}
	if _, err := Build(document); err == nil {
		t.Fatal("Build() unexpectedly succeeded")
	}
}

func TestBuildResolvedPinsEndpointsAndRedactsKeys(t *testing.T) {
	directory := t.TempDir()
	entry := writeWireGuardConfig(t, directory, "entry.conf", "entry.example:51820", "0.0.0.0/0")
	exit := writeWireGuardConfig(t, directory, "exit.conf", "exit.example:51821", "0.0.0.0/0")
	document := &config.Document{Metadata: config.Metadata{Name: "example"}, Spec: config.Spec{Hops: []config.Hop{
		{Name: "entry", WireGuardConfigPath: entry, OuterFamily: "ipv4"},
		{Name: "exit", WireGuardConfigPath: exit, OuterFamily: "ipv4"},
	}}}
	resolver := fakeResolver{
		"ip4:entry.example": {netip.MustParseAddr("192.0.2.1")},
		"ip4:exit.example":  {netip.MustParseAddr("198.51.100.2")},
	}

	got, err := BuildResolved(context.Background(), document, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hops[0].Endpoint != "192.0.2.1:51820" || got.Hops[1].Endpoint != "198.51.100.2:51821" {
		t.Fatalf("pinned endpoints = %q, %q", got.Hops[0].Endpoint, got.Hops[1].Endpoint)
	}
	if len(got.Hops[0].Addresses) != 1 || got.Hops[0].Addresses[0] != "10.0.0.2/32" {
		t.Fatalf("addresses = %#v", got.Hops[0].Addresses)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
	} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("plan contains key material: %s", encoded)
		}
	}
}

func TestBuildResolvedRejectsUnroutedNextEndpoint(t *testing.T) {
	directory := t.TempDir()
	entry := writeWireGuardConfig(t, directory, "entry.conf", "entry.example:51820", "10.0.0.0/8")
	exit := writeWireGuardConfig(t, directory, "exit.conf", "exit.example:51821", "0.0.0.0/0")
	document := &config.Document{Metadata: config.Metadata{Name: "example"}, Spec: config.Spec{Hops: []config.Hop{
		{Name: "entry", WireGuardConfigPath: entry, OuterFamily: "ipv4"},
		{Name: "exit", WireGuardConfigPath: exit, OuterFamily: "ipv4"},
	}}}
	resolver := fakeResolver{
		"ip4:entry.example": {netip.MustParseAddr("192.0.2.1")},
		"ip4:exit.example":  {netip.MustParseAddr("198.51.100.2")},
	}
	_, err := BuildResolved(context.Background(), document, resolver)
	if err == nil || !strings.Contains(err.Error(), "do not route the next endpoint") {
		t.Fatalf("BuildResolved() error = %v", err)
	}
}

func TestBuildResolvedRejectsUnroutedDNS(t *testing.T) {
	directory := t.TempDir()
	entry := writeWireGuardConfig(t, directory, "entry.conf", "entry.example:51820", "0.0.0.0/0")
	exit := writeWireGuardConfig(t, directory, "exit.conf", "exit.example:51821", "10.0.0.0/8")
	document := &config.Document{Metadata: config.Metadata{Name: "example"}, Spec: config.Spec{
		DNS: []string{"1.1.1.1"},
		Hops: []config.Hop{
			{Name: "entry", WireGuardConfigPath: entry, OuterFamily: "ipv4"},
			{Name: "exit", WireGuardConfigPath: exit, OuterFamily: "ipv4"},
		},
	}}
	resolver := fakeResolver{
		"ip4:entry.example": {netip.MustParseAddr("192.0.2.1")},
		"ip4:exit.example":  {netip.MustParseAddr("10.0.0.2")},
	}
	_, err := BuildResolved(context.Background(), document, resolver)
	if err == nil || !strings.Contains(err.Error(), "do not route DNS resolver") {
		t.Fatalf("BuildResolved() error = %v", err)
	}
}

func TestBuildResolvedRejectsHostRouteOutsideExitAllowedIPs(t *testing.T) {
	directory := t.TempDir()
	entry := writeWireGuardConfig(t, directory, "entry.conf", "entry.example:51820", "0.0.0.0/0")
	exit := writeWireGuardConfig(t, directory, "exit.conf", "exit.example:51821", "10.0.0.0/8")
	document := &config.Document{Metadata: config.Metadata{Name: "example"}, Spec: config.Spec{
		HostRouting: config.HostRouting{Mode: config.HostRoutingSelected, Routes: []string{"192.168.0.0/16"}},
		Hops: []config.Hop{
			{Name: "entry", WireGuardConfigPath: entry, OuterFamily: "ipv4"},
			{Name: "exit", WireGuardConfigPath: exit, OuterFamily: "ipv4"},
		},
	}}
	resolver := fakeResolver{
		"ip4:entry.example": {netip.MustParseAddr("192.0.2.1")},
		"ip4:exit.example":  {netip.MustParseAddr("10.0.0.2")},
	}
	_, err := BuildResolved(context.Background(), document, resolver)
	if err == nil || !strings.Contains(err.Error(), "do not cover host route") {
		t.Fatalf("BuildResolved() error = %v", err)
	}
}

func writeWireGuardConfig(t *testing.T, directory, name, endpoint, allowedIPs string) string {
	t.Helper()
	contents := `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/32
[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Endpoint = ` + endpoint + `
AllowedIPs = ` + allowedIPs + "\n"
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
