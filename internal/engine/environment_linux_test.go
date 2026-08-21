//go:build linux

package engine

import (
	"os/user"
	"strconv"
	"strings"
	"testing"
)

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
