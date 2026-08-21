//go:build linux

package engine

import (
	"os/user"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestMergedEnvironment(t *testing.T) {
	got := mergedEnvironment([]string{"PATH=/bin", "NESTWG_CHAIN=old", "TERM=xterm"}, map[string]string{
		"NESTWG_VPN":   "1",
		"NESTWG_CHAIN": "example",
	})
	want := []string{"PATH=/bin", "TERM=xterm", "NESTWG_CHAIN=example", "NESTWG_VPN=1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged environment = %#v, want %#v", got, want)
	}
}

func TestInvokingUserEnvironmentRestoresIdentityVariables(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Skipf("current user unavailable: %v", err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	got := invokingUserEnvironment([]string{"PATH=/bin", "HOME=/root", "USER=root", "LOGNAME=root"}, uint32(uid))
	joined := "\n" + strings.Join(got, "\n") + "\n"
	for _, want := range []string{"\nHOME=" + account.HomeDir + "\n", "\nUSER=" + account.Username + "\n", "\nLOGNAME=" + account.Username + "\n"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("environment %#v does not contain %q", got, want)
		}
	}
}
