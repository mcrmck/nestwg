//go:build linux

package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/mcrmck/nestwg/internal/config"
	"github.com/mcrmck/nestwg/internal/plan"
	"github.com/mcrmck/nestwg/internal/state"
	"github.com/mcrmck/nestwg/internal/wgconfig"
)

type Manager struct {
	Store    state.Store
	Resolver plan.IPResolver
	Now      func() time.Time
}

func New() *Manager {
	return &Manager{Store: state.DefaultStore(), Resolver: net.DefaultResolver, Now: time.Now}
}

type preparedHop struct {
	planned  plan.Hop
	config   *wgconfig.Config
	endpoint *net.UDPAddr
}

type HopStatus struct {
	Name          string
	InterfaceName string
	Handshake     time.Time
	ReceiveBytes  int64
	TransmitBytes int64
	Error         string
}

type ChainStatus struct {
	Chain      state.Chain
	Ready      bool
	Hops       []HopStatus
	Attachment AttachmentStatus
	Problem    string
}

type DoctorCheck struct {
	Name    string
	OK      bool
	Message string
}

func (m *Manager) Up(ctx context.Context, chainPath string) (*state.Chain, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("up requires root privileges (try sudo)")
	}
	document, err := config.Load(chainPath)
	if err != nil {
		return nil, err
	}
	if err := document.Validate(); err != nil {
		return nil, fmt.Errorf("invalid chain: %w", err)
	}
	chainPlan, err := m.Plan(ctx, document)
	if err != nil {
		return nil, err
	}
	unlock, err := m.Store.Lock(document.Metadata.Name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if _, err := m.Store.Load(document.Metadata.Name); err == nil {
		return nil, fmt.Errorf("chain %q is already up", document.Metadata.Name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	hops, err := m.prepare(chainPlan)
	if err != nil {
		return nil, err
	}
	namespaces := namespacesFor(chainPlan)
	if err := preflightNamespaces(namespaces); err != nil {
		return nil, err
	}
	absPath, err := filepath.Abs(chainPath)
	if err != nil {
		return nil, err
	}
	chain := &state.Chain{
		Name:             document.Metadata.Name,
		Phase:            state.PhaseCreating,
		ChainFile:        absPath,
		PayloadNamespace: chainPlan.PayloadNamespace,
		Namespaces:       namespaces,
		ResolverFile:     m.Store.ResolverPath(document.Metadata.Name),
		CreatedAt:        m.Now().UTC(),
	}
	for _, hop := range hops {
		chain.Hops = append(chain.Hops, state.Hop{
			Name:               hop.planned.Name,
			InterfaceName:      hop.planned.InterfaceName,
			InterfaceNamespace: hop.planned.InterfaceNamespace,
			Endpoint:           hop.endpoint.String(),
		})
	}
	// Save the recovery record before the first kernel mutation. A process or
	// host crash can then be recovered with `nestwg down`.
	if err := m.Store.Save(chain); err != nil {
		return nil, err
	}
	if err := runtimeFailpoint("recovery-state-saved"); err != nil {
		return nil, errors.Join(err, m.Store.Delete(chain.Name))
	}
	if err := m.Store.SaveResolver(chain.Name, document.Spec.DNS); err != nil {
		_ = m.Store.Delete(chain.Name)
		return nil, err
	}
	if err := runtimeFailpoint("resolver-saved"); err != nil {
		return nil, errors.Join(err, m.Store.DeleteResolver(chain.Name), m.Store.Delete(chain.Name))
	}
	if err := apply(namespaces, hops); err != nil {
		var failed *applyFailure
		if errors.As(err, &failed) && failed.Rollback != nil {
			return nil, fmt.Errorf("%w; recovery state retained, run `nestwg down %s` after resolving the cleanup error", err, chain.Name)
		}
		resolverErr := m.Store.DeleteResolver(chain.Name)
		stateErr := m.Store.Delete(chain.Name)
		return nil, errors.Join(err, resolverErr, stateErr)
	}
	if err := runtimeFailpoint("apply-complete"); err != nil {
		if rollbackErr := rollbackNamespaces(namespaces); rollbackErr != nil {
			return nil, fmt.Errorf("%w (rollback incomplete: %v); recovery state retained, run `nestwg down %s` after resolving the cleanup error", err, rollbackErr, chain.Name)
		}
		return nil, errors.Join(err, m.Store.DeleteResolver(chain.Name), m.Store.Delete(chain.Name))
	}
	chain.Phase = state.PhaseActive
	if err := m.Store.Save(chain); err != nil {
		if rollbackErr := rollbackNamespaces(namespaces); rollbackErr != nil {
			return nil, fmt.Errorf("activate chain state: %w (rollback incomplete: %v); recovery state retained, run `nestwg down %s` after resolving the cleanup error", err, rollbackErr, chain.Name)
		}
		resolverErr := m.Store.DeleteResolver(chain.Name)
		stateErr := m.Store.Delete(chain.Name)
		return nil, errors.Join(fmt.Errorf("activate chain state: %w", err), resolverErr, stateErr)
	}
	return chain, nil
}

func (m *Manager) Down(name string) error {
	if os.Geteuid() != 0 {
		return errors.New("down requires root privileges (try sudo)")
	}
	unlock, err := m.Store.Lock(name)
	if err != nil {
		return err
	}
	defer unlock()
	chain, err := m.Store.Load(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if chain.Attachment != nil {
		return fmt.Errorf("VPN %q has protected host routes; run `nestwg detach %s` before taking it down", name, name)
	}
	for _, namespace := range chain.Namespaces {
		pids, err := namespacePIDs(namespace)
		if err != nil {
			return err
		}
		if len(pids) != 0 {
			return fmt.Errorf("namespace %q still contains processes %v", namespace, pids)
		}
	}
	var cleanupErrors []error
	for index := len(chain.Namespaces) - 1; index >= 0; index-- {
		if err := runtimeFailpoint("down-delete-namespace"); err != nil {
			cleanupErrors = append(cleanupErrors, err)
			break
		}
		if err := netns.DeleteNamed(chain.Namespaces[index]); err != nil && !errors.Is(err, os.ErrNotExist) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("delete namespace %q: %w", chain.Namespaces[index], err))
		}
	}
	if len(cleanupErrors) == 0 {
		if err := runtimeFailpoint("down-delete-resolver"); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		} else if err := m.Store.DeleteResolver(name); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	if len(cleanupErrors) == 0 {
		if err := runtimeFailpoint("down-delete-state"); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		} else if err := m.Store.Delete(name); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	return errors.Join(cleanupErrors...)
}

func (m *Manager) Recover(name string) ([]string, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("recover requires root privileges (try sudo)")
	}
	unlock, err := m.Store.Lock(name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if _, err := m.Store.Load(name); err == nil {
		return nil, fmt.Errorf("chain %q still has state; use `nestwg down %s`", name, name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	entries, err := os.ReadDir("/run/netns")
	if errors.Is(err, os.ErrNotExist) {
		entries = nil
	} else if err != nil {
		return nil, err
	}
	prefix := "nwg-" + name + "-"
	var namespaces []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		suffix := strings.TrimPrefix(entry.Name(), prefix)
		if suffix == "app" || validTransitSuffix(suffix) {
			namespaces = append(namespaces, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(namespaces)))
	for _, namespace := range namespaces {
		pids, err := namespacePIDs(namespace)
		if err != nil {
			return nil, err
		}
		if len(pids) != 0 {
			return nil, fmt.Errorf("refusing recovery: namespace %q still contains processes %v", namespace, pids)
		}
	}
	for _, namespace := range namespaces {
		if err := netns.DeleteNamed(namespace); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("recover namespace %q: %w", namespace, err)
		}
	}
	if err := m.Store.DeleteResolver(name); err != nil {
		return nil, err
	}
	return namespaces, nil
}

func (m *Manager) List() ([]state.Chain, error) { return m.Store.List() }

func (m *Manager) Plan(ctx context.Context, document *config.Document) (*plan.Chain, error) {
	return plan.BuildResolved(ctx, document, m.Resolver)
}

func (m *Manager) Doctor() []DoctorCheck {
	checks := []DoctorCheck{{Name: "root privileges", OK: os.Geteuid() == 0}}
	if !checks[0].OK {
		checks[0].Message = "run `sudo nestwg doctor` to test privileged operations"
		return checks
	}

	handle, err := netlink.NewHandle()
	checks = append(checks, DoctorCheck{Name: "netlink access", OK: err == nil, Message: errorMessage(err)})
	if err == nil {
		interfaceName := fmt.Sprintf("nwgdoc%x", os.Getpid())
		if len(interfaceName) > 15 {
			interfaceName = interfaceName[:15]
		}
		attributes := netlink.NewLinkAttrs()
		attributes.Name = interfaceName
		link := &netlink.Wireguard{LinkAttrs: attributes}
		createErr := handle.LinkAdd(link)
		if createErr == nil {
			createErr = handle.LinkDel(link)
		}
		checks = append(checks, DoctorCheck{Name: "kernel WireGuard", OK: createErr == nil, Message: errorMessage(createErr)})
		handle.Close()
	}

	_, err = filepath.EvalSymlinks("/etc/resolv.conf")
	checks = append(checks, DoctorCheck{Name: "resolver mount target", OK: err == nil, Message: errorMessage(err)})
	_, err = m.Store.List()
	checks = append(checks, DoctorCheck{Name: "secure runtime state", OK: err == nil, Message: errorMessage(err)})
	return checks
}

func (m *Manager) Inspect(name string) (*ChainStatus, error) {
	chain, err := m.Store.Load(name)
	if err != nil {
		return nil, err
	}
	result := &ChainStatus{Chain: *chain, Ready: chain.Phase == state.PhaseActive}
	result.Attachment = m.InspectAttachment(chain)
	if result.Attachment.Problem != "" {
		result.Ready = false
		result.Problem = result.Attachment.Problem
	}
	for _, namespace := range chain.Namespaces {
		handle, err := netns.GetFromName(namespace)
		if err != nil {
			result.Ready = false
			result.Problem = fmt.Sprintf("namespace %s is missing", namespace)
			return result, nil
		}
		handle.Close()
	}
	for index, hop := range chain.Hops {
		hopStatus := HopStatus{Name: hop.Name, InterfaceName: hop.InterfaceName}
		interfaceName := hop.InterfaceName
		var device *wgtypes.Device
		var err error
		if chain.Attachment != nil && index == len(chain.Hops)-1 {
			interfaceName = chain.Attachment.HostInterface
			hopStatus.InterfaceName = interfaceName
			device, err = currentWireGuardDevice(interfaceName)
		} else {
			device, err = wireGuardDevice(hop.InterfaceNamespace, interfaceName)
		}
		if err != nil {
			hopStatus.Error = err.Error()
			result.Ready = false
		} else if len(device.Peers) != 1 {
			hopStatus.Error = fmt.Sprintf("expected one peer, found %d", len(device.Peers))
			result.Ready = false
		} else {
			peer := device.Peers[0]
			hopStatus.Handshake = peer.LastHandshakeTime
			hopStatus.ReceiveBytes = peer.ReceiveBytes
			hopStatus.TransmitBytes = peer.TransmitBytes
			if peer.LastHandshakeTime.IsZero() {
				result.Ready = false
			}
		}
		result.Hops = append(result.Hops, hopStatus)
	}
	return result, nil
}

func (m *Manager) WaitReady(ctx context.Context, name string) (*ChainStatus, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := m.Inspect(name)
		if err != nil {
			return nil, err
		}
		if status.Ready {
			return status, nil
		}
		if status.Problem != "" {
			return status, errors.New(status.Problem)
		}
		select {
		case <-ctx.Done():
			var pending []string
			for _, hop := range status.Hops {
				if hop.Handshake.IsZero() || hop.Error != "" {
					pending = append(pending, hop.Name)
				}
			}
			return status, fmt.Errorf("wait for chain readiness: %w (pending hops: %s)", ctx.Err(), strings.Join(pending, ", "))
		case <-ticker.C:
		}
	}
}

// TriggerHandshake sends one byte through the innermost configured route. The
// packet makes WireGuard initiate every nested handshake before an interactive
// VPN session starts; no response is required.
func (m *Manager) TriggerHandshake(name string) (resultErr error) {
	if os.Geteuid() != 0 {
		return errors.New("handshake trigger requires root privileges (try sudo)")
	}
	unlock, err := m.Store.RLock(name)
	if err != nil {
		return err
	}
	defer unlock()
	chain, err := m.Store.Load(name)
	if err != nil {
		return err
	}
	document, err := config.Load(chain.ChainFile)
	if err != nil {
		return err
	}
	if err := document.Validate(); err != nil {
		return fmt.Errorf("invalid chain: %w", err)
	}
	lastHop := document.Spec.Hops[len(document.Spec.Hops)-1]
	imported, err := wgconfig.Load(lastHop.WireGuardConfigPath)
	if err != nil {
		return err
	}
	target := handshakeProbeAddress(document.Spec.DNS, imported.Peers[0].AllowedIPs)
	if !target.IsValid() {
		return errors.New("exit VPN has no route available for a handshake trigger")
	}

	original, err := netns.Get()
	if err != nil {
		return err
	}
	defer original.Close()
	payload, err := netns.GetFromName(chain.PayloadNamespace)
	if err != nil {
		return fmt.Errorf("open VPN network for %q: %w", name, err)
	}
	defer payload.Close()

	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	defer func() {
		if err := netns.Set(original); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("restore host network: %w", err))
		}
	}()
	if err := netns.Set(payload); err != nil {
		return fmt.Errorf("enter VPN network: %w", err)
	}
	endpoint := net.UDPAddrFromAddrPort(netip.AddrPortFrom(target, 9))
	connection, err := net.DialUDP("udp", nil, endpoint)
	if err != nil {
		return fmt.Errorf("prepare handshake trigger: %w", err)
	}
	_, writeErr := connection.Write([]byte{0})
	closeErr := connection.Close()
	return errors.Join(writeErr, closeErr)
}

func handshakeProbeAddress(resolvers []string, allowed []netip.Prefix) netip.Addr {
	for _, resolver := range resolvers {
		address, err := netip.ParseAddr(resolver)
		if err == nil {
			return address
		}
	}
	for _, candidate := range []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	} {
		for _, prefix := range allowed {
			if prefix.Contains(candidate) {
				return candidate
			}
		}
	}
	for _, prefix := range allowed {
		address := prefix.Masked().Addr()
		if next := address.Next(); next.IsValid() && prefix.Contains(next) {
			return next
		}
		return address
	}
	return netip.Addr{}
}

func (m *Manager) Exec(name string, argv []string) error {
	return m.ExecWithEnv(name, argv, nil)
}

// ExecWithEnv runs argv through a connected chain with the supplied environment
// values added or replaced for the payload process.
func (m *Manager) ExecWithEnv(name string, argv []string, values map[string]string) error {
	if len(argv) == 0 {
		return errors.New("no command specified")
	}
	if os.Geteuid() != 0 {
		return errors.New("exec requires root privileges (try sudo)")
	}
	unlock, err := m.Store.RLock(name)
	if err != nil {
		return err
	}
	defer unlock()
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	helperArguments := append([]string{"__exec", name, "--"}, argv...)
	command := exec.Command(executable, helperArguments...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	command.Env = mergedEnvironment(os.Environ(), values)
	if err := command.Start(); err != nil {
		return err
	}
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for received := range signals {
			_ = command.Process.Signal(received)
		}
	}()
	waitErr := command.Wait()
	signal.Stop(signals)
	close(signals)
	<-done
	return waitErr
}

func mergedEnvironment(environment []string, values map[string]string) []string {
	if len(values) == 0 {
		return environment
	}
	result := make([]string, 0, len(environment)+len(values))
	for _, item := range environment {
		key, _, found := strings.Cut(item, "=")
		if _, replace := values[key]; found && replace {
			continue
		}
		result = append(result, item)
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result
}

// EnterAndExec is the internal half of Exec. It enters both the payload
// network and a private mount namespace, installs the chain resolver, drops
// sudo privileges, and replaces itself with the requested command.
func (m *Manager) EnterAndExec(name string, argv []string) error {
	if os.Geteuid() != 0 {
		return errors.New("payload entry requires root privileges")
	}
	if len(argv) == 0 {
		return errors.New("no command specified")
	}
	chain, err := m.Store.Load(name)
	if err != nil {
		return fmt.Errorf("load chain %q: %w", name, err)
	}
	if chain.Phase != state.PhaseActive {
		return fmt.Errorf("chain %q is not ready (phase %s)", name, chain.Phase)
	}
	if chain.Attachment != nil {
		return fmt.Errorf("VPN %q is attached to the host; run commands normally or detach it before using exec/shell", name)
	}
	commandPath, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	ns, err := netns.GetFromName(chain.PayloadNamespace)
	if err != nil {
		return fmt.Errorf("open payload network for %q: %w", name, err)
	}
	defer ns.Close()

	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	if err := netns.Set(ns); err != nil {
		return fmt.Errorf("enter payload network: %w", err)
	}
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("create private mount namespace: %w", err)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	resolverTarget, err := filepath.EvalSymlinks("/etc/resolv.conf")
	if err != nil {
		return fmt.Errorf("resolve /etc/resolv.conf: %w", err)
	}
	if err := unix.Mount(chain.ResolverFile, resolverTarget, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("install payload DNS configuration: %w", err)
	}
	if credential := invokingUserCredential(); credential != nil {
		environment := invokingUserEnvironment(os.Environ(), credential.Uid)
		groups := make([]int, len(credential.Groups))
		for index, group := range credential.Groups {
			groups[index] = int(group)
		}
		if err := unix.Setgroups(groups); err != nil {
			return fmt.Errorf("drop supplementary groups: %w", err)
		}
		if err := unix.Setgid(int(credential.Gid)); err != nil {
			return fmt.Errorf("drop group privileges: %w", err)
		}
		if err := unix.Setuid(int(credential.Uid)); err != nil {
			return fmt.Errorf("drop user privileges: %w", err)
		}
		return unix.Exec(commandPath, argv, environment)
	}
	return unix.Exec(commandPath, argv, os.Environ())
}

func (m *Manager) prepare(chainPlan *plan.Chain) ([]preparedHop, error) {
	hops := make([]preparedHop, 0, len(chainPlan.Hops))
	for _, planned := range chainPlan.Hops {
		imported := planned.Material
		if imported == nil {
			return nil, fmt.Errorf("hop %q has no executable WireGuard material", planned.Name)
		}
		pinned, err := netip.ParseAddrPort(planned.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("hop %q pinned endpoint: %w", planned.Name, err)
		}
		endpoint := net.UDPAddrFromAddrPort(pinned)
		hops = append(hops, preparedHop{planned: planned, config: imported, endpoint: endpoint})
	}
	return hops, nil
}

func namespacesFor(chainPlan *plan.Chain) []string {
	namespaces := make([]string, 0, len(chainPlan.Hops))
	for _, hop := range chainPlan.Hops {
		if hop.InterfaceNamespace != chainPlan.PayloadNamespace {
			namespaces = append(namespaces, hop.InterfaceNamespace)
		}
	}
	return append(namespaces, chainPlan.PayloadNamespace)
}

func preflightNamespaces(names []string) error {
	for _, name := range names {
		namespace, err := netns.GetFromName(name)
		if err == nil {
			namespace.Close()
			return fmt.Errorf("namespace %q already exists; refusing to claim it", name)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect namespace %q: %w", name, err)
		}
	}
	return nil
}

type applyFailure struct {
	Cause    error
	Rollback error
}

func (failure *applyFailure) Error() string {
	if failure.Cause == nil {
		return fmt.Sprintf("rollback incomplete: %v", failure.Rollback)
	}
	if failure.Rollback == nil {
		return failure.Cause.Error()
	}
	return fmt.Sprintf("%v (rollback incomplete: %v)", failure.Cause, failure.Rollback)
}

func (failure *applyFailure) Unwrap() []error {
	var result []error
	if failure.Cause != nil {
		result = append(result, failure.Cause)
	}
	if failure.Rollback != nil {
		result = append(result, failure.Rollback)
	}
	return result
}

func apply(namespaces []string, hops []preparedHop) (resultErr error) {
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		return err
	}
	defer original.Close()
	created := make([]string, 0, len(namespaces))
	defer func() {
		restoreErr := netns.Set(original)
		if restoreErr != nil {
			restoreErr = fmt.Errorf("restore host network namespace: %w", restoreErr)
		}
		if resultErr != nil || restoreErr != nil {
			resultErr = &applyFailure{
				Cause:    errors.Join(resultErr, restoreErr),
				Rollback: rollbackNamespaces(created),
			}
		}
	}()
	for _, name := range namespaces {
		ns, err := netns.NewNamed(name)
		if err != nil {
			return fmt.Errorf("create namespace %q: %w", name, err)
		}
		created = append(created, name)
		if err := runtimeFailpoint("namespace-created"); err != nil {
			ns.Close()
			return err
		}
		handle, err := netlink.NewHandleAt(ns)
		if err == nil {
			var loopback netlink.Link
			loopback, err = handle.LinkByName("lo")
			if err == nil {
				err = handle.LinkSetUp(loopback)
			}
			handle.Close()
		}
		ns.Close()
		if err == nil {
			err = runtimeFailpoint("loopback-up")
		}
		if restoreErr := netns.Set(original); err == nil && restoreErr != nil {
			err = restoreErr
		}
		if err != nil {
			return fmt.Errorf("initialize namespace %q: %w", name, err)
		}
	}

	for index, hop := range hops {
		birth := original
		var birthOwned netns.NsHandle
		if index > 0 {
			birthOwned, err = netns.GetFromName(hops[index-1].planned.InterfaceNamespace)
			if err != nil {
				return err
			}
			defer birthOwned.Close()
			birth = birthOwned
		}
		destination, err := netns.GetFromName(hop.planned.InterfaceNamespace)
		if err != nil {
			return err
		}
		defer destination.Close()
		if err := configureHop(birth, destination, hop); err != nil {
			return fmt.Errorf("configure hop %q: %w", hop.planned.Name, err)
		}
	}
	return nil
}

func configureHop(birth, destination netns.NsHandle, hop preparedHop) error {
	handle, err := netlink.NewHandleAt(birth)
	if err != nil {
		return err
	}
	defer handle.Close()
	attributes := netlink.NewLinkAttrs()
	attributes.Name = hop.planned.InterfaceName
	link := &netlink.Wireguard{LinkAttrs: attributes}
	if err := handle.LinkAdd(link); err != nil {
		return err
	}
	configured := false
	defer func() {
		if !configured {
			handle.LinkDel(link)
		}
	}()
	if err := runtimeFailpoint("wireguard-created"); err != nil {
		return err
	}
	if err := configureWireGuard(birth, hop.planned.InterfaceName, hop.config, hop.endpoint); err != nil {
		return err
	}
	if err := runtimeFailpoint("wireguard-configured"); err != nil {
		return err
	}
	if err := handle.LinkSetNsFd(link, int(destination)); err != nil {
		return err
	}
	configured = true
	if err := runtimeFailpoint("wireguard-moved"); err != nil {
		return err
	}

	destinationHandle, err := netlink.NewHandleAt(destination)
	if err != nil {
		return err
	}
	defer destinationHandle.Close()
	moved, err := destinationHandle.LinkByName(hop.planned.InterfaceName)
	if err != nil {
		return err
	}
	if err := destinationHandle.LinkSetMTU(moved, hop.planned.InterfaceMTU); err != nil {
		return err
	}
	if err := runtimeFailpoint("mtu-set"); err != nil {
		return err
	}
	for _, prefix := range hop.config.Addresses {
		address, err := netlink.ParseAddr(prefix.String())
		if err != nil {
			return err
		}
		if err := destinationHandle.AddrAdd(moved, address); err != nil {
			return err
		}
		if err := runtimeFailpoint("address-added"); err != nil {
			return err
		}
	}
	if err := destinationHandle.LinkSetUp(moved); err != nil {
		return err
	}
	if err := runtimeFailpoint("wireguard-up"); err != nil {
		return err
	}
	for _, prefix := range hop.config.Peers[0].AllowedIPs {
		destinationPrefix := prefixToIPNet(prefix)
		if err := destinationHandle.RouteAdd(&netlink.Route{LinkIndex: moved.Attrs().Index, Dst: &destinationPrefix}); err != nil {
			return err
		}
		if err := runtimeFailpoint("route-added"); err != nil {
			return err
		}
	}
	return nil
}

func configureWireGuard(namespace netns.NsHandle, name string, imported *wgconfig.Config, endpoint *net.UDPAddr) (resultErr error) {
	original, err := netns.Get()
	if err != nil {
		return err
	}
	defer original.Close()
	if err := netns.Set(namespace); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, netns.Set(original)) }()
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()
	privateKey := wgtypes.Key(imported.PrivateKey)
	peer := imported.Peers[0]
	publicKey := wgtypes.Key(peer.PublicKey)
	configuration := wgtypes.Config{PrivateKey: &privateKey, ReplacePeers: true, Peers: []wgtypes.PeerConfig{{
		PublicKey:                   publicKey,
		Endpoint:                    endpoint,
		AllowedIPs:                  prefixesToIPNets(peer.AllowedIPs),
		PersistentKeepaliveInterval: durationPointer(time.Duration(peer.PersistentKeepalive) * time.Second),
	}}}
	if peer.PresharedKey != nil {
		key := wgtypes.Key(*peer.PresharedKey)
		configuration.Peers[0].PresharedKey = &key
	}
	return client.ConfigureDevice(name, configuration)
}

func wireGuardDevice(namespaceName, interfaceName string) (device *wgtypes.Device, resultErr error) {
	namespace, err := netns.GetFromName(namespaceName)
	if err != nil {
		return nil, err
	}
	defer namespace.Close()
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		return nil, err
	}
	defer original.Close()
	if err := netns.Set(namespace); err != nil {
		return nil, err
	}
	defer func() {
		if err := netns.Set(original); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.Device(interfaceName)
}

func currentWireGuardDevice(interfaceName string) (*wgtypes.Device, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.Device(interfaceName)
}

func rollbackNamespaces(names []string) error {
	var cleanupErrors []error
	for index := len(names) - 1; index >= 0; index-- {
		if err := runtimeFailpoint("rollback-delete-namespace"); err != nil {
			cleanupErrors = append(cleanupErrors, err)
			continue
		}
		if err := netns.DeleteNamed(names[index]); err != nil && !errors.Is(err, os.ErrNotExist) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("delete namespace %q: %w", names[index], err))
		}
	}
	return errors.Join(cleanupErrors...)
}

func prefixToIPNet(prefix netip.Prefix) net.IPNet {
	bits := 128
	if prefix.Addr().Is4() {
		bits = 32
	}
	return net.IPNet{IP: net.IP(prefix.Masked().Addr().AsSlice()), Mask: net.CIDRMask(prefix.Bits(), bits)}
}

func prefixesToIPNets(prefixes []netip.Prefix) []net.IPNet {
	result := make([]net.IPNet, 0, len(prefixes))
	for _, prefix := range prefixes {
		result = append(result, prefixToIPNet(prefix))
	}
	return result
}

func durationPointer(value time.Duration) *time.Duration { return &value }

func errorMessage(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func validTransitSuffix(suffix string) bool {
	if len(suffix) < 2 || suffix[0] != 't' || suffix[1] == '0' {
		return false
	}
	_, err := strconv.ParseUint(suffix[1:], 10, 31)
	return err == nil
}

func namespacePIDs(namespace string) ([]int, error) {
	target, err := os.Stat(filepath.Join("/run/netns", namespace))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		info, err := os.Stat(filepath.Join("/proc", entry.Name(), "ns/net"))
		if err == nil && os.SameFile(target, info) {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids, nil
}

func invokingUserCredential() *syscall.Credential {
	uidText, gidText := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
	if uidText == "" || gidText == "" {
		return nil
	}
	uid, uidErr := strconv.ParseUint(uidText, 10, 32)
	gid, gidErr := strconv.ParseUint(gidText, 10, 32)
	if uidErr != nil || gidErr != nil {
		return nil
	}
	credential := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	account, err := user.LookupId(uidText)
	if err != nil {
		return credential
	}
	groupIDs, err := account.GroupIds()
	if err != nil {
		return credential
	}
	for _, groupID := range groupIDs {
		parsed, err := strconv.ParseUint(groupID, 10, 32)
		if err == nil {
			credential.Groups = append(credential.Groups, uint32(parsed))
		}
	}
	return credential
}

func invokingUserEnvironment(environment []string, uid uint32) []string {
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return environment
	}
	values := map[string]string{
		"HOME":    account.HomeDir,
		"USER":    account.Username,
		"LOGNAME": account.Username,
	}
	result := make([]string, 0, len(environment)+len(values))
	for _, item := range environment {
		key, _, found := strings.Cut(item, "=")
		if _, replace := values[key]; found && replace {
			continue
		}
		result = append(result, item)
	}
	for _, key := range []string{"HOME", "USER", "LOGNAME"} {
		result = append(result, key+"="+values[key])
	}
	return result
}
