package main

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mcrmck/nestwg/internal/config"
	"github.com/mcrmck/nestwg/internal/engine"
)

func TestRunPrintsUsage(t *testing.T) {
	var output bytes.Buffer
	if err := run(nil, &output, engine.New()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "nestwg up") || !strings.Contains(output.String(), "nestwg doctor") {
		t.Fatalf("usage = %q", output.String())
	}
}

func TestRunPrintsGlobalHelp(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"--help"}, &output, engine.New()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Commands:") {
		t.Fatalf("help = %q", output.String())
	}
}

func TestRunVersion(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"version"}, &output, engine.New()); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "nestwg dev\n"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}

func TestRunPrintsCommandHelp(t *testing.T) {
	for _, args := range [][]string{{"up", "--help"}, {"help", "down"}} {
		var output bytes.Buffer
		if err := run(args, &output, engine.New()); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), "Usage: nestwg") || !strings.Contains(output.String(), "--verbose") {
			t.Fatalf("run(%q) output = %q", args, output.String())
		}
	}
}

func TestResolveChainPathUsesConventionalDirectoryForBareName(t *testing.T) {
	previous := chainConfigDirectory
	chainConfigDirectory = "/custom/nestwg"
	t.Cleanup(func() { chainConfigDirectory = previous })

	path, err := resolveChainPath("lab")
	if err != nil {
		t.Fatal(err)
	}
	if want := "/custom/nestwg/lab.yaml"; path != want {
		t.Fatalf("resolveChainPath() = %q, want %q", path, want)
	}
	path, err = resolveChainPath("./lab.yaml")
	if err != nil || path != "./lab.yaml" {
		t.Fatalf("explicit path = %q, %v", path, err)
	}
}

func TestResolveChainNameAcceptsConfigPath(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"entry.conf", "exit.conf"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(`[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/32
[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
AllowedIPs = 0.0.0.0/0
Endpoint = 192.0.2.1:51820
`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	chainPath := filepath.Join(directory, "friendly.yaml")
	chain := `apiVersion: nestwg.io/v1alpha1
kind: Chain
metadata:
  name: lab
spec:
  hostRouting:
    mode: default
  hops:
    - name: entry
      wireguardConfig: entry.conf
      outerFamily: ipv4
    - name: exit
      wireguardConfig: exit.conf
      outerFamily: ipv4
`
	if err := os.WriteFile(chainPath, []byte(chain), 0o600); err != nil {
		t.Fatal(err)
	}
	name, err := resolveChainName(chainPath)
	if err != nil {
		t.Fatal(err)
	}
	if name != "lab" {
		t.Fatalf("resolveChainName() = %q", name)
	}
}

func TestRunRejectsUnknownCommandBeforeOpeningFiles(t *testing.T) {
	err := run([]string{"unknown", "/does/not/exist"}, &bytes.Buffer{}, engine.New())
	if err == nil || !strings.Contains(err.Error(), `unknown command "unknown"`) {
		t.Fatalf("error = %v", err)
	}
}

func TestRemovedTerminalAndAttachmentCommandsAreUnknown(t *testing.T) {
	for _, command := range []string{"connect", "exec", "shell", "attach", "detach"} {
		err := run([]string{command}, &bytes.Buffer{}, engine.New())
		if err == nil || !strings.Contains(err.Error(), `unknown command "`+command+`"`) {
			t.Errorf("run(%q) error = %v", command, err)
		}
	}
}

func TestResolveHostRoutingUsesConfigAndCLIOverride(t *testing.T) {
	document := &config.Document{Spec: config.Spec{HostRouting: config.HostRouting{
		Mode: config.HostRoutingSelected, Routes: []string{"10.0.0.0/8"},
	}}}
	mode, routes, err := resolveHostRouting(document, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if mode != config.HostRoutingSelected || len(routes) != 1 || routes[0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Fatalf("resolveHostRouting() = %q, %#v", mode, routes)
	}
	mode, routes, err = resolveHostRouting(document, true, false, nil)
	if err != nil || mode != config.HostRoutingDefault || routes != nil {
		t.Fatalf("default override = %q, %#v, %v", mode, routes, err)
	}
}

func TestResolveHostRoutingRejectsConflictingOverrides(t *testing.T) {
	document := &config.Document{Spec: config.Spec{HostRouting: config.HostRouting{Mode: config.HostRoutingIsolated}}}
	if _, _, err := resolveHostRouting(document, true, true, nil); err == nil {
		t.Fatal("conflicting overrides unexpectedly succeeded")
	}
	if _, _, err := resolveHostRouting(document, true, false, []string{"10.0.0.0/8"}); err == nil {
		t.Fatal("default and selected overrides unexpectedly succeeded")
	}
}
