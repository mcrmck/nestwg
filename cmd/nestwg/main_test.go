package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mcrmck/nestwg/internal/engine"
)

func TestRunPrintsUsage(t *testing.T) {
	var output bytes.Buffer
	if err := run(nil, &output, engine.New()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "nestwg connect") || !strings.Contains(output.String(), "nestwg doctor") {
		t.Fatalf("usage = %q", output.String())
	}
}

func TestUserShell(t *testing.T) {
	t.Setenv("SHELL", "/bin/example-shell")
	if got, want := userShell(), "/bin/example-shell"; got != want {
		t.Fatalf("userShell() = %q, want %q", got, want)
	}
	t.Setenv("SHELL", "")
	if got, want := userShell(), "/bin/sh"; got != want {
		t.Fatalf("userShell() = %q, want %q", got, want)
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

func TestRunRejectsUnknownCommandBeforeOpeningFiles(t *testing.T) {
	err := run([]string{"unknown", "/does/not/exist"}, &bytes.Buffer{}, engine.New())
	if err == nil || !strings.Contains(err.Error(), `unknown command "unknown"`) {
		t.Fatalf("error = %v", err)
	}
}

func TestParseAttachArgumentsAcceptsRoutesBeforeAndAfterName(t *testing.T) {
	name, routes, err := parseAttachArguments([]string{"--route", "10.0.0.0/8", "example", "--route=2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	if name != "example" || strings.Join(routes, ",") != "10.0.0.0/8,2001:db8::/32" {
		t.Fatalf("parseAttachArguments() = %q, %#v", name, routes)
	}
}

func TestParseAttachArgumentsRejectsIncompleteInput(t *testing.T) {
	for _, arguments := range [][]string{{"example"}, {"--route"}, {"one", "two", "--route", "10.0.0.0/8"}} {
		if _, _, err := parseAttachArguments(arguments); err == nil {
			t.Errorf("parseAttachArguments(%q) unexpectedly succeeded", arguments)
		}
	}
}
