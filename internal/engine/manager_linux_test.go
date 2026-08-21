//go:build linux

package engine

import (
	"errors"
	"strings"
	"testing"

	"github.com/mcrmck/nestwg/internal/plan"
)

func TestNamespacesForPlan(t *testing.T) {
	chainPlan := &plan.Chain{PayloadNamespace: "nwg-test-app", Hops: []plan.Hop{
		{InterfaceNamespace: "nwg-test-t1"},
		{InterfaceNamespace: "nwg-test-t2"},
		{InterfaceNamespace: "nwg-test-app"},
	}}
	got := namespacesFor(chainPlan)
	want := []string{"nwg-test-t1", "nwg-test-t2", "nwg-test-app"}
	if len(got) != len(want) {
		t.Fatalf("namespaces = %#v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("namespaces = %#v", got)
		}
	}
}

func TestApplyFailureReportsRollbackSeparately(t *testing.T) {
	cause := errors.New("configure failed")
	rollback := errors.New("namespace remained")
	failure := &applyFailure{Cause: cause, Rollback: rollback}
	if !errors.Is(failure, cause) || !errors.Is(failure, rollback) {
		t.Fatalf("applyFailure does not unwrap both errors: %v", failure)
	}
	if !strings.Contains(failure.Error(), "rollback incomplete") {
		t.Fatalf("applyFailure error = %q", failure)
	}
}

func TestValidTransitSuffix(t *testing.T) {
	for _, suffix := range []string{"t1", "t2", "t100"} {
		if !validTransitSuffix(suffix) {
			t.Errorf("validTransitSuffix(%q) = false", suffix)
		}
	}
	for _, suffix := range []string{"", "app", "t", "t0", "t01", "t-1", "t1x"} {
		if validTransitSuffix(suffix) {
			t.Errorf("validTransitSuffix(%q) = true", suffix)
		}
	}
}
