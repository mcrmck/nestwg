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
	if !strings.Contains(output.String(), "nestwg up") || !strings.Contains(output.String(), "nestwg doctor") {
		t.Fatalf("usage = %q", output.String())
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
