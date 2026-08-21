//go:build linux

package engine

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/mcrmck/nestwg/internal/plan"
)

func TestHandshakeProbeAddressPrefersResolver(t *testing.T) {
	got := handshakeProbeAddress([]string{"10.0.0.53"}, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	if want := netip.MustParseAddr("10.0.0.53"); got != want {
		t.Fatalf("probe address = %s, want %s", got, want)
	}
}

func TestParseRoutesCanonicalizesAndSorts(t *testing.T) {
	got, err := ParseRoutes([]string{"2001:db8::1/64", "203.0.113.7/24"})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/64")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseRoutes() = %#v, want %#v", got, want)
	}
}

func TestParseRoutesRejectsMissingInvalidAndDuplicateRoutes(t *testing.T) {
	for _, routes := range [][]string{nil, {"not-a-cidr"}, {"0.0.0.0/0"}, {"10.0.0.0/8", "10.0.0.1/8"}} {
		if _, err := ParseRoutes(routes); err == nil {
			t.Errorf("ParseRoutes(%q) unexpectedly succeeded", routes)
		}
	}
}

func TestAttachmentInterfaceNameIsStableAndFitsLinuxLimit(t *testing.T) {
	first := attachmentInterfaceName("example-with-a-long-name")
	second := attachmentInterfaceName("example-with-a-long-name")
	if first != second || len(first) > 15 {
		t.Fatalf("attachmentInterfaceName() = %q, %q", first, second)
	}
}

func TestHandshakeProbeAddressUsesDocumentationAddressForDefaultRoute(t *testing.T) {
	got := handshakeProbeAddress(nil, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	if want := netip.MustParseAddr("192.0.2.1"); got != want {
		t.Fatalf("probe address = %s, want %s", got, want)
	}
}

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
