package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const Version = 3

const maxStateSize = 1 << 20

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

const (
	PhaseCreating = "creating"
	PhaseActive   = "active"
)

type Hop struct {
	Name               string `json:"name"`
	InterfaceName      string `json:"interfaceName"`
	InterfaceNamespace string `json:"interfaceNamespace"`
	Endpoint           string `json:"endpoint"`
}

const (
	HostRoutingPhaseCreating = "creating"
	HostRoutingPhaseActive   = "active"
)

type HostRoutingState struct {
	Phase                string   `json:"phase"`
	Mode                 string   `json:"mode"`
	HostInterface        string   `json:"hostInterface"`
	Routes               []string `json:"routes"`
	RoutingTable         int      `json:"routingTable,omitempty"`
	OriginalSrcValidMark int      `json:"originalSrcValidMark,omitempty"`
	DNSBackend           string   `json:"dnsBackend,omitempty"`
}

type Chain struct {
	Version          int               `json:"version"`
	Name             string            `json:"name"`
	Phase            string            `json:"phase"`
	ChainFile        string            `json:"chainFile"`
	PayloadNamespace string            `json:"payloadNamespace"`
	Namespaces       []string          `json:"namespaces"`
	ResolverFile     string            `json:"resolverFile"`
	Hops             []Hop             `json:"hops"`
	HostRouting      *HostRoutingState `json:"hostRouting,omitempty"`
	CreatedAt        time.Time         `json:"createdAt"`
}

type Store struct{ Directory string }

func DefaultStore() Store { return Store{Directory: "/run/nestwg"} }

func (s Store) Lock(name string) (func() error, error) {
	return s.lock(name, unix.LOCK_EX|unix.LOCK_NB)
}

func (s Store) RLock(name string) (func() error, error) {
	return s.lock(name, unix.LOCK_SH|unix.LOCK_NB)
}

func (s Store) lock(name string, operation int) (func() error, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	if err := s.ensureDirectory(); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(s.Directory, name+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open chain lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), operation); err != nil {
		file.Close()
		return nil, fmt.Errorf("chain %q is busy: %w", name, err)
	}
	return func() error {
		unlockErr := unix.Flock(int(file.Fd()), unix.LOCK_UN)
		closeErr := file.Close()
		return errors.Join(unlockErr, closeErr)
	}, nil
}

func (s Store) Save(chain *Chain) error {
	if err := validateChain(s, chain); err != nil {
		return err
	}
	if err := s.ensureDirectory(); err != nil {
		return err
	}
	chain.Version = Version
	encoded, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	encoded = append(encoded, '\n')
	temporary, err := os.CreateTemp(s.Directory, ".state-*")
	if err != nil {
		return fmt.Errorf("create temporary state: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure temporary state: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close state: %w", err)
	}
	if err := os.Rename(temporaryName, s.path(chain.Name)); err != nil {
		return fmt.Errorf("install state: %w", err)
	}
	return s.syncDirectory()
}

func (s Store) Load(name string) (*Chain, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	if err := s.ensureDirectory(); err != nil {
		return nil, err
	}
	encoded, err := secureReadState(s.path(name))
	if err != nil {
		return nil, err
	}
	var chain Chain
	if err := json.Unmarshal(encoded, &chain); err != nil {
		return nil, fmt.Errorf("decode state for %q: %w", name, err)
	}
	if chain.Version != Version || chain.Name != name {
		return nil, fmt.Errorf("state for %q has unsupported or inconsistent metadata", name)
	}
	if err := validateChain(s, &chain); err != nil {
		return nil, fmt.Errorf("unsafe state for %q: %w", name, err)
	}
	return &chain, nil
}

func (s Store) List() ([]Chain, error) {
	if err := s.ensureDirectory(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.Directory)
	if err != nil {
		return nil, err
	}
	var chains []Chain
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		name := entry.Name()[:len(entry.Name())-len(".json")]
		if err := validateName(name); err != nil {
			return nil, fmt.Errorf("unsafe state filename %q", entry.Name())
		}
		chain, err := s.Load(name)
		if err != nil {
			return nil, err
		}
		chains = append(chains, *chain)
	}
	sort.Slice(chains, func(i, j int) bool { return chains[i].Name < chains[j].Name })
	return chains, nil
}

func (s Store) Delete(name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	return s.removeAndSync(s.path(name), "state")
}

func (s Store) ResolverPath(name string) string {
	return filepath.Join(s.Directory, name+".resolv.conf")
}

func (s Store) SaveResolver(name string, resolvers []string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if err := s.ensureDirectory(); err != nil {
		return err
	}
	contents := "# Managed by nestwg; do not edit.\noptions attempts:1 timeout:2\n"
	for _, resolver := range resolvers {
		if _, err := netip.ParseAddr(resolver); err != nil {
			return fmt.Errorf("invalid resolver address %q", resolver)
		}
		contents += "nameserver " + resolver + "\n"
	}
	temporary, err := os.CreateTemp(s.Directory, ".resolver-*")
	if err != nil {
		return fmt.Errorf("create temporary resolver configuration: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.WriteString(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write payload resolver configuration: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, s.ResolverPath(name)); err != nil {
		return fmt.Errorf("install payload resolver configuration: %w", err)
	}
	return s.syncDirectory()
}

func (s Store) DeleteResolver(name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	return s.removeAndSync(s.ResolverPath(name), "resolver configuration")
}

func (s Store) path(name string) string { return filepath.Join(s.Directory, name+".json") }

func (s Store) ensureDirectory() error {
	if err := os.MkdirAll(s.Directory, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	info, err := os.Lstat(s.Directory)
	if err != nil {
		return fmt.Errorf("inspect state directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("state directory %q must be a directory", s.Directory)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("state directory %q must be owned by uid %d", s.Directory, os.Geteuid())
	}
	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(s.Directory, 0o700); err != nil {
			return fmt.Errorf("secure state directory permissions: %w", err)
		}
	}
	return nil
}

func (s Store) syncDirectory() error {
	directory, err := os.Open(s.Directory)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}

func (s Store) removeAndSync(path, description string) error {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("delete %s: %w", description, err)
	}
	return s.syncDirectory()
}

func secureReadState(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("state file %q must be a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) {
		return nil, fmt.Errorf("state file %q changed while opening", path)
	}
	stat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("state file %q must be owned by uid %d", path, os.Geteuid())
	}
	if after.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("state file %q permissions must be 0600", path)
	}
	if after.Size() > maxStateSize {
		return nil, fmt.Errorf("state file %q exceeds %d bytes", path, maxStateSize)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maxStateSize+1))
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxStateSize {
		return nil, fmt.Errorf("state file %q exceeds %d bytes", path, maxStateSize)
	}
	return encoded, nil
}

func validateName(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("invalid chain name %q", name)
	}
	return nil
}

func validateChain(store Store, chain *Chain) error {
	if chain == nil {
		return errors.New("state is nil")
	}
	if err := validateName(chain.Name); err != nil {
		return err
	}
	if chain.Phase != PhaseCreating && chain.Phase != PhaseActive {
		return fmt.Errorf("invalid phase %q", chain.Phase)
	}
	prefix := "nwg-" + chain.Name + "-"
	if chain.PayloadNamespace != prefix+"app" {
		return errors.New("payload namespace does not match chain name")
	}
	if len(chain.Namespaces) == 0 {
		return errors.New("state has no namespaces")
	}
	seen := make(map[string]struct{}, len(chain.Namespaces))
	for _, namespace := range chain.Namespaces {
		if !strings.HasPrefix(namespace, prefix) {
			return fmt.Errorf("namespace %q is outside the chain prefix", namespace)
		}
		if _, exists := seen[namespace]; exists {
			return fmt.Errorf("namespace %q is duplicated", namespace)
		}
		seen[namespace] = struct{}{}
	}
	if _, exists := seen[chain.PayloadNamespace]; !exists {
		return errors.New("payload namespace is absent from namespace list")
	}
	if chain.ResolverFile != store.ResolverPath(chain.Name) {
		return errors.New("resolver path does not match state directory")
	}
	for _, hop := range chain.Hops {
		if _, exists := seen[hop.InterfaceNamespace]; !exists {
			return fmt.Errorf("hop %q references an unknown namespace", hop.Name)
		}
	}
	if chain.HostRouting != nil {
		routing := chain.HostRouting
		if routing.Phase != HostRoutingPhaseCreating && routing.Phase != HostRoutingPhaseActive {
			return fmt.Errorf("invalid host-routing phase %q", routing.Phase)
		}
		if routing.HostInterface == "" || len(routing.HostInterface) > 15 {
			return errors.New("host-routing interface name must contain 1 to 15 characters")
		}
		if len(routing.Routes) == 0 {
			return errors.New("host routing has no routes")
		}
		if routing.Mode != "selected" && routing.Mode != "default" {
			return fmt.Errorf("invalid host-routing mode %q", routing.Mode)
		}
		if routing.Mode == "default" {
			if routing.RoutingTable < 1 || routing.RoutingTable > 0x7fffffff {
				return errors.New("default host routing has an invalid routing table")
			}
		} else if routing.RoutingTable != 0 {
			return errors.New("selected host routing unexpectedly has a routing table")
		}
		if routing.DNSBackend != "" && routing.DNSBackend != "resolvconf" && routing.DNSBackend != "resolvectl" {
			return fmt.Errorf("invalid host DNS backend %q", routing.DNSBackend)
		}
		seenRoutes := make(map[string]struct{}, len(routing.Routes))
		for _, route := range routing.Routes {
			prefix, err := netip.ParsePrefix(route)
			if err != nil || prefix.String() != route {
				return fmt.Errorf("host route %q is not a canonical CIDR", route)
			}
			if _, exists := seenRoutes[route]; exists {
				return fmt.Errorf("host route %q is duplicated", route)
			}
			seenRoutes[route] = struct{}{}
		}
	}
	return nil
}
