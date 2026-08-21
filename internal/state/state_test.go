package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreRoundTripAndList(t *testing.T) {
	store := testStore(t)
	want := &Chain{Name: "example", Phase: PhaseActive, ChainFile: "/chain.yaml", PayloadNamespace: "nwg-example-app", Namespaces: []string{"nwg-example-app"}, ResolverFile: store.ResolverPath("example"), CreatedAt: time.Unix(123, 0).UTC()}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load("example")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != want.Name || got.PayloadNamespace != want.PayloadNamespace || got.Version != Version {
		t.Fatalf("Load() = %#v", got)
	}
	info, err := os.Stat(store.path("example"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state permissions = %o", info.Mode().Perm())
	}
	listed, err := store.List()
	if err != nil || len(listed) != 1 || listed[0].Name != "example" {
		t.Fatalf("List() = %#v, %v", listed, err)
	}
	if err := store.Delete("example"); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete("example"); err != nil {
		t.Fatalf("second Delete() = %v", err)
	}
}

func TestResolverFile(t *testing.T) {
	store := testStore(t)
	if err := store.SaveResolver("example", []string{"1.1.1.1", "2606:4700:4700::1111"}); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(store.ResolverPath("example"))
	if err != nil {
		t.Fatal(err)
	}
	want := "nameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\n"
	if !strings.Contains(string(contents), want) {
		t.Fatalf("resolver contents = %q", contents)
	}
	if err := store.DeleteResolver("example"); err != nil {
		t.Fatal(err)
	}
}

func TestResolverFileRejectsInjectedContent(t *testing.T) {
	store := testStore(t)
	if err := store.SaveResolver("example", []string{"1.1.1.1\noptions rotate"}); err == nil {
		t.Fatal("SaveResolver() accepted injected resolver content")
	}
	if _, err := os.Stat(store.ResolverPath("example")); !os.IsNotExist(err) {
		t.Fatalf("resolver file exists after rejected write: %v", err)
	}
}

func TestLoadRejectsUnsafeStateFiles(t *testing.T) {
	store := testStore(t)
	chain := &Chain{Name: "example", Phase: PhaseActive, ChainFile: "/chain.yaml", PayloadNamespace: "nwg-example-app", Namespaces: []string{"nwg-example-app"}, ResolverFile: store.ResolverPath("example"), CreatedAt: time.Unix(123, 0).UTC()}
	if err := store.Save(chain); err != nil {
		t.Fatal(err)
	}
	statePath := store.path("example")
	validState, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("permissive permissions", func(t *testing.T) {
		if err := os.Chmod(statePath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load("example"); err == nil || !strings.Contains(err.Error(), "permissions must be 0600") {
			t.Fatalf("Load() error = %v", err)
		}
		if err := os.Chmod(statePath, 0o600); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("symbolic link", func(t *testing.T) {
		target := filepath.Join(filepath.Dir(store.Directory), "target.json")
		if err := os.WriteFile(target, validState, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(statePath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, statePath); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load("example"); err == nil || !strings.Contains(err.Error(), "must be a regular file") {
			t.Fatalf("Load() error = %v", err)
		}
		if err := os.Remove(statePath); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(statePath, validState, 0o600); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("oversized file", func(t *testing.T) {
		oversized := make([]byte, maxStateSize+1)
		if err := os.WriteFile(statePath, oversized, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load("example"); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("Load() error = %v", err)
		}
	})
}

func TestLockIsExclusive(t *testing.T) {
	store := testStore(t)
	unlock, err := store.Lock("example")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := store.Lock("example"); err == nil {
		t.Fatal("second Lock() unexpectedly succeeded")
	}
}

func TestReadLocksCanShareButBlockWriter(t *testing.T) {
	store := testStore(t)
	first, err := store.RLock("example")
	if err != nil {
		t.Fatal(err)
	}
	defer first()
	second, err := store.RLock("example")
	if err != nil {
		t.Fatal(err)
	}
	defer second()
	if _, err := store.Lock("example"); err == nil {
		t.Fatal("exclusive Lock() unexpectedly succeeded during read locks")
	}
}

func TestRejectsPathTraversalNames(t *testing.T) {
	store := testStore(t)
	for _, name := range []string{"../escape", "/absolute", "UPPER", ""} {
		if _, err := store.Lock(name); err == nil {
			t.Errorf("Lock(%q) unexpectedly succeeded", name)
		}
		if err := store.Delete(name); err == nil {
			t.Errorf("Delete(%q) unexpectedly succeeded", name)
		}
	}
}

func testStore(t *testing.T) Store {
	t.Helper()
	directory, err := os.MkdirTemp(".", ".state-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	return Store{Directory: filepath.Join(directory, "state")}
}
