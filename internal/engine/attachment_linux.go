//go:build linux

package engine

import (
	"bytes"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"os"
	"os/exec"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/mcrmck/nestwg/internal/config"
	"github.com/mcrmck/nestwg/internal/state"
	"github.com/mcrmck/nestwg/internal/wgconfig"
)

const (
	activeRoutePriority = 50
	failClosedPriority  = 42760
	defaultTableBase    = 52000
	defaultRuleBase     = 29000
)

type HostRoutingStatus struct {
	Attached      bool
	Mode          string
	InterfaceName string
	InterfaceUp   bool
	Routes        []RouteStatus
	Problem       string
}

type RouteStatus struct {
	Prefix     string
	Active     bool
	FailClosed bool
	Protection string
}

// ParseRoutes validates and canonicalizes user-supplied protected CIDRs.
func ParseRoutes(values []string) ([]netip.Prefix, error) {
	if len(values) == 0 {
		return nil, errors.New("at least one --route CIDR is required")
	}
	seen := make(map[netip.Prefix]struct{}, len(values))
	routes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid route %q: %w", value, err)
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 {
			return nil, fmt.Errorf("route %s is a default route; use --default-route", prefix)
		}
		if _, exists := seen[prefix]; exists {
			return nil, fmt.Errorf("route %s is duplicated", prefix)
		}
		seen[prefix] = struct{}{}
		routes = append(routes, prefix)
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Addr().BitLen() != routes[j].Addr().BitLen() {
			return routes[i].Addr().BitLen() < routes[j].Addr().BitLen()
		}
		if routes[i].Bits() != routes[j].Bits() {
			return routes[i].Bits() < routes[j].Bits()
		}
		return routes[i].Addr().Less(routes[j].Addr())
	})
	return routes, nil
}

func (m *Manager) ConfigureHostRouting(name, mode string, routes []netip.Prefix) (*state.HostRoutingState, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("host routing requires root privileges (try sudo)")
	}
	unlock, err := m.Store.Lock(name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	chain, err := m.Store.Load(name)
	if err != nil {
		return nil, err
	}
	if chain.Phase != state.PhaseActive {
		return nil, fmt.Errorf("VPN %q is not active", name)
	}
	if chain.HostRouting != nil {
		return nil, fmt.Errorf("VPN %q already has host routing", name)
	}
	if mode == config.HostRoutingDefault {
		routes, err = defaultRoutes(chain)
		if err != nil {
			return nil, err
		}
	} else if mode != config.HostRoutingSelected {
		return nil, fmt.Errorf("invalid host routing mode %q", mode)
	} else if len(routes) == 0 {
		return nil, errors.New("selected host routing requires at least one route")
	}
	if err := validateHostRoutes(chain, routes); err != nil {
		return nil, err
	}
	document, err := config.Load(chain.ChainFile)
	if err != nil {
		return nil, err
	}
	if err := validateHostDNSRoutes(document.Spec.DNS, routes); err != nil {
		return nil, err
	}
	routing := &state.HostRoutingState{
		Phase:         state.HostRoutingPhaseCreating,
		Mode:          mode,
		HostInterface: hostInterfaceName(name),
	}
	if len(document.Spec.DNS) != 0 {
		routing.DNSBackend, err = hostDNSBackend()
		if err != nil {
			return nil, err
		}
	}
	if mode == config.HostRoutingDefault {
		routing.RoutingTable = hostRoutingTable(name)
		routing.OriginalSrcValidMark, err = readSrcValidMark()
		if err != nil {
			return nil, err
		}
	}
	for _, route := range routes {
		routing.Routes = append(routing.Routes, route.String())
	}
	chain.HostRouting = routing
	// Reserve route and interface ownership before changing the kernel. Down
	// can recover interrupted host setup from this creating-phase record.
	if err := m.Store.Save(chain); err != nil {
		return nil, err
	}
	if err := applyHostRouting(chain, routes); err != nil {
		cleanupErr := removeHostRoutingKernel(chain)
		if cleanupErr != nil {
			return nil, fmt.Errorf("configure host routing: %w (cleanup incomplete: %v); recovery state retained, run `nestwg down %s`", err, cleanupErr, name)
		}
		chain.HostRouting = nil
		return nil, errors.Join(err, m.Store.Save(chain))
	}
	routing.Phase = state.HostRoutingPhaseActive
	if err := m.Store.Save(chain); err != nil {
		cleanupErr := removeHostRoutingKernel(chain)
		if cleanupErr != nil {
			return nil, fmt.Errorf("activate host-routing state: %w (cleanup incomplete: %v); run `nestwg down %s`", err, cleanupErr, name)
		}
		chain.HostRouting = nil
		return nil, errors.Join(err, m.Store.Save(chain))
	}
	return routing, nil
}

func validateHostRoutes(chain *state.Chain, routes []netip.Prefix) error {
	document, err := config.Load(chain.ChainFile)
	if err != nil {
		return err
	}
	lastHop := document.Spec.Hops[len(document.Spec.Hops)-1]
	imported, err := wgconfig.Load(lastHop.WireGuardConfigPath)
	if err != nil {
		return err
	}
	allowed := imported.Peers[0].AllowedIPs
	for _, route := range routes {
		covered := false
		for _, candidate := range allowed {
			if candidate.Addr().BitLen() == route.Addr().BitLen() && candidate.Bits() <= route.Bits() && candidate.Contains(route.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			return fmt.Errorf("route %s is not covered by the exit hop AllowedIPs", route)
		}
	}
	return nil
}

func defaultRoutes(chain *state.Chain) ([]netip.Prefix, error) {
	document, err := config.Load(chain.ChainFile)
	if err != nil {
		return nil, err
	}
	lastHop := document.Spec.Hops[len(document.Spec.Hops)-1]
	imported, err := wgconfig.Load(lastHop.WireGuardConfigPath)
	if err != nil {
		return nil, err
	}
	candidates := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}
	var routes []netip.Prefix
	for _, candidate := range candidates {
		for _, allowed := range imported.Peers[0].AllowedIPs {
			if allowed == candidate {
				routes = append(routes, candidate)
				break
			}
		}
	}
	if len(routes) == 0 {
		return nil, errors.New("default routing requires the exit peer to allow 0.0.0.0/0, ::/0, or both")
	}
	return routes, nil
}

func validateHostDNSRoutes(resolvers []string, routes []netip.Prefix) error {
	for _, value := range resolvers {
		resolver, err := netip.ParseAddr(value)
		if err != nil {
			return err
		}
		covered := false
		for _, route := range routes {
			if route.Contains(resolver) {
				covered = true
				break
			}
		}
		if !covered {
			return fmt.Errorf("DNS resolver %s is not covered by host routing", resolver)
		}
	}
	return nil
}

func applyHostRouting(chain *state.Chain, routes []netip.Prefix) error {
	hostHandle, err := netlink.NewHandle()
	if err != nil {
		return err
	}
	defer hostHandle.Close()
	if _, err := hostHandle.LinkByName(chain.HostRouting.HostInterface); err == nil {
		return fmt.Errorf("host interface %q already exists", chain.HostRouting.HostInterface)
	}
	for _, route := range routes {
		if route.Bits() == 0 {
			continue
		}
		existing, err := exactRoutes(hostHandle, route)
		if err != nil {
			return err
		}
		if len(existing) != 0 {
			return fmt.Errorf("host already has an exact route for %s; refusing to replace it", route)
		}
	}
	// Install unreachable alternatives before exposing the device. If setup is
	// interrupted, protected destinations cannot use the normal default route.
	for _, route := range routes {
		if route.Bits() == 0 {
			continue
		}
		blocked := failClosedRoute(route)
		if err := hostHandle.RouteAdd(&blocked); err != nil {
			return fmt.Errorf("install fail-closed route for %s: %w", route, err)
		}
	}

	payload, err := netns.GetFromName(chain.PayloadNamespace)
	if err != nil {
		return err
	}
	defer payload.Close()
	payloadHandle, err := netlink.NewHandleAt(payload)
	if err != nil {
		return err
	}
	defer payloadHandle.Close()
	hostNamespace, err := netns.Get()
	if err != nil {
		return err
	}
	defer hostNamespace.Close()
	finalHop := chain.Hops[len(chain.Hops)-1]
	link, err := payloadHandle.LinkByName(finalHop.InterfaceName)
	if err != nil {
		return fmt.Errorf("find exit VPN device: %w", err)
	}
	if err := payloadHandle.LinkSetName(link, chain.HostRouting.HostInterface); err != nil {
		return fmt.Errorf("name host VPN device: %w", err)
	}
	if err := payloadHandle.LinkSetNsFd(link, int(hostNamespace)); err != nil {
		return fmt.Errorf("expose exit VPN device to host: %w", err)
	}
	hostLink, err := hostHandle.LinkByName(chain.HostRouting.HostInterface)
	if err != nil {
		return err
	}
	addresses, err := finalInterfaceAddresses(chain)
	if err != nil {
		return err
	}
	for _, address := range addresses {
		parsed, err := netlink.ParseAddr(address.String())
		if err != nil {
			return err
		}
		if err := hostHandle.AddrAdd(hostLink, parsed); err != nil && !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("restore host VPN address %s: %w", address, err)
		}
	}
	if err := hostHandle.LinkSetUp(hostLink); err != nil {
		return fmt.Errorf("bring up host VPN device: %w", err)
	}
	if chain.HostRouting.Mode == config.HostRoutingDefault {
		if err := applyDefaultRouting(chain, hostHandle, hostLink, routes); err != nil {
			return err
		}
	} else {
		for _, route := range routes {
			active := activeHostRoute(route, hostLink.Attrs().Index)
			if err := hostHandle.RouteAdd(&active); err != nil {
				return fmt.Errorf("route %s through host VPN: %w", route, err)
			}
		}
	}
	if chain.HostRouting.DNSBackend != "" {
		if err := applyHostDNS(chain); err != nil {
			return err
		}
	}
	return nil
}

func applyDefaultRouting(chain *state.Chain, handle *netlink.Handle, link netlink.Link, routes []netip.Prefix) error {
	mark := chain.HostRouting.RoutingTable
	if err := setOuterFirewallMark(chain, mark); err != nil {
		return fmt.Errorf("mark outer WireGuard socket: %w", err)
	}
	if chain.HostRouting.OriginalSrcValidMark == 0 {
		if err := writeSrcValidMark(1); err != nil {
			return err
		}
	}
	for _, prefix := range routes {
		family := prefixFamily(prefix)
		if err := ensureDefaultPolicyAvailable(handle, chain, family); err != nil {
			return err
		}
		if err := changeKillSwitch(chain.HostRouting.HostInterface, mark, family, "-I"); err != nil {
			return err
		}
		route := defaultHostRoute(prefix, link.Attrs().Index, mark)
		if err := handle.RouteAdd(&route); err != nil {
			return fmt.Errorf("install VPN default route for IPv%d: %w", prefix.Addr().BitLen(), err)
		}
		for _, rule := range defaultPolicyRules(chain, family) {
			if err := netlink.RuleAdd(rule); err != nil {
				return fmt.Errorf("install VPN policy rule: %w", err)
			}
		}
	}
	return nil
}

func ensureDefaultPolicyAvailable(handle *netlink.Handle, chain *state.Chain, family int) error {
	rules, err := netlink.RuleList(family)
	if err != nil {
		return err
	}
	for _, existing := range rules {
		if existing.Invert && existing.Table >= defaultTableBase && existing.Table < defaultTableBase+1000 {
			return errors.New("another NestWG default route is already active for this address family")
		}
		for _, wanted := range defaultPolicyRules(chain, family) {
			if existing.Priority == wanted.Priority || (wanted.Table == chain.HostRouting.RoutingTable && existing.Table == wanted.Table) {
				return fmt.Errorf("routing policy priority %d or table %d is already in use", wanted.Priority, chain.HostRouting.RoutingTable)
			}
		}
	}
	routes, err := handle.RouteListFiltered(family, &netlink.Route{Table: chain.HostRouting.RoutingTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	if len(routes) != 0 {
		return fmt.Errorf("routing table %d is already in use", chain.HostRouting.RoutingTable)
	}
	return nil
}

func defaultPolicyRules(chain *state.Chain, family int) []*netlink.Rule {
	priority := hostRoutingRulePriority(chain.Name)
	suppress := netlink.NewRule()
	suppress.Family = family
	suppress.Priority = priority
	suppress.Table = unix.RT_TABLE_MAIN
	suppress.SuppressPrefixlen = 0

	mark := uint32(chain.HostRouting.RoutingTable)
	mask := uint32(0xffffffff)
	vpn := netlink.NewRule()
	vpn.Family = family
	vpn.Priority = priority + 1
	vpn.Table = chain.HostRouting.RoutingTable
	vpn.Mark = mark
	vpn.Mask = &mask
	vpn.Invert = true
	return []*netlink.Rule{suppress, vpn}
}

func removeHostRoutingKernel(chain *state.Chain) error {
	if chain.HostRouting == nil {
		return nil
	}
	routes := make([]netip.Prefix, 0, len(chain.HostRouting.Routes))
	for _, value := range chain.HostRouting.Routes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return err
		}
		routes = append(routes, prefix)
	}
	hostHandle, err := netlink.NewHandle()
	if err != nil {
		return err
	}
	defer hostHandle.Close()
	var cleanup []error
	if chain.HostRouting.DNSBackend != "" {
		if err := removeHostDNS(chain); err != nil {
			cleanup = append(cleanup, err)
		}
	}
	if chain.HostRouting.Mode == config.HostRoutingDefault {
		for _, prefix := range routes {
			family := prefixFamily(prefix)
			for _, rule := range reverseRules(defaultPolicyRules(chain, family)) {
				if err := netlink.RuleDel(rule); err != nil && !errors.Is(err, syscall.ENOENT) {
					cleanup = append(cleanup, fmt.Errorf("remove VPN policy rule: %w", err))
				}
			}
			if err := deleteDefaultHostRoute(hostHandle, prefix, chain.HostRouting.RoutingTable); err != nil && !errors.Is(err, syscall.ESRCH) {
				cleanup = append(cleanup, fmt.Errorf("remove VPN default route: %w", err))
			}
		}
	}
	payload, err := netns.GetFromName(chain.PayloadNamespace)
	if err != nil {
		return errors.Join(errors.Join(cleanup...), err)
	}
	defer payload.Close()
	payloadHandle, err := netlink.NewHandleAt(payload)
	if err != nil {
		return err
	}
	defer payloadHandle.Close()
	finalHop := chain.Hops[len(chain.Hops)-1]

	// The device may be on the host, renamed but not yet moved after an
	// interrupted host setup, or already restored by a previous down attempt.
	if link, findErr := hostHandle.LinkByName(chain.HostRouting.HostInterface); findErr == nil {
		if err := hostHandle.LinkSetNsFd(link, int(payload)); err != nil {
			return fmt.Errorf("return exit VPN device to payload: %w", err)
		}
	}
	if link, findErr := payloadHandle.LinkByName(chain.HostRouting.HostInterface); findErr == nil {
		if err := payloadHandle.LinkSetName(link, finalHop.InterfaceName); err != nil {
			return fmt.Errorf("restore exit VPN device name: %w", err)
		}
	} else if _, originalErr := payloadHandle.LinkByName(finalHop.InterfaceName); originalErr != nil {
		return errors.New("exit VPN device is missing; protected routes retained")
	}
	restored, err := payloadHandle.LinkByName(finalHop.InterfaceName)
	if err != nil {
		return errors.New("exit VPN device is missing; protected routes retained")
	}
	addresses, err := finalInterfaceAddresses(chain)
	if err != nil {
		return err
	}
	for _, address := range addresses {
		parsed, err := netlink.ParseAddr(address.String())
		if err != nil {
			return err
		}
		if err := payloadHandle.AddrAdd(restored, parsed); err != nil && !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("restore payload VPN address %s: %w", address, err)
		}
	}
	if err := payloadHandle.LinkSetUp(restored); err != nil {
		return fmt.Errorf("bring up restored exit VPN device: %w", err)
	}

	// Moving the device removes its live routes. Remove fail-closed alternatives
	// last, only after the nested device is safely back in the payload.
	if chain.HostRouting.Mode == config.HostRoutingDefault {
		if err := setOuterFirewallMark(chain, 0); err != nil {
			cleanup = append(cleanup, fmt.Errorf("clear outer WireGuard mark: %w", err))
		}
		if chain.HostRouting.OriginalSrcValidMark == 0 {
			if err := writeSrcValidMark(0); err != nil {
				cleanup = append(cleanup, err)
			}
		}
		for _, prefix := range routes {
			family := prefixFamily(prefix)
			if killSwitchExists(chain.HostRouting.HostInterface, chain.HostRouting.RoutingTable, family) {
				if err := changeKillSwitch(chain.HostRouting.HostInterface, chain.HostRouting.RoutingTable, family, "-D"); err != nil {
					cleanup = append(cleanup, err)
				}
			}
		}
	} else {
		for _, prefix := range routes {
			blocked := failClosedRoute(prefix)
			if err := hostHandle.RouteDel(&blocked); err != nil && !errors.Is(err, syscall.ESRCH) {
				cleanup = append(cleanup, fmt.Errorf("remove fail-closed route %s: %w", prefix, err))
			}
		}
	}
	return errors.Join(cleanup...)
}

func finalInterfaceAddresses(chain *state.Chain) ([]netip.Prefix, error) {
	document, err := config.Load(chain.ChainFile)
	if err != nil {
		return nil, err
	}
	lastHop := document.Spec.Hops[len(document.Spec.Hops)-1]
	imported, err := wgconfig.Load(lastHop.WireGuardConfigPath)
	if err != nil {
		return nil, err
	}
	return imported.Addresses, nil
}

func (m *Manager) InspectHostRouting(chain *state.Chain) HostRoutingStatus {
	if chain.HostRouting == nil {
		return HostRoutingStatus{}
	}
	status := HostRoutingStatus{Attached: true, Mode: chain.HostRouting.Mode, InterfaceName: chain.HostRouting.HostInterface}
	handle, err := netlink.NewHandle()
	if err != nil {
		status.Problem = err.Error()
		return status
	}
	defer handle.Close()
	link, linkErr := handle.LinkByName(chain.HostRouting.HostInterface)
	status.InterfaceUp = linkErr == nil && link.Attrs().Flags&net.FlagUp != 0
	if linkErr != nil {
		status.Problem = "host VPN device is missing; protected routes remain blocked"
	}
	for _, value := range chain.HostRouting.Routes {
		prefix, _ := netip.ParsePrefix(value)
		routeStatus := RouteStatus{Prefix: value}
		var existing []netlink.Route
		var routeErr error
		if chain.HostRouting.Mode == config.HostRoutingDefault {
			destination := prefixToIPNet(prefix)
			existing, routeErr = handle.RouteListFiltered(prefixFamily(prefix), &netlink.Route{Dst: &destination, Table: chain.HostRouting.RoutingTable}, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
		} else {
			existing, routeErr = exactRoutes(handle, prefix)
		}
		if routeErr != nil && status.Problem == "" {
			status.Problem = routeErr.Error()
		}
		for _, route := range existing {
			if route.Type == syscall.RTN_UNREACHABLE && route.Priority == failClosedPriority {
				routeStatus.FailClosed = true
			}
			if linkErr == nil && route.LinkIndex == link.Attrs().Index && (route.Priority == activeRoutePriority || chain.HostRouting.Mode == config.HostRoutingDefault) {
				routeStatus.Active = true
			}
		}
		if chain.HostRouting.Mode == config.HostRoutingDefault {
			routeStatus.FailClosed = defaultPolicyHealthy(chain, prefixFamily(prefix)) && killSwitchExists(chain.HostRouting.HostInterface, chain.HostRouting.RoutingTable, prefixFamily(prefix))
			routeStatus.Protection = "policy routing and OUTPUT kill switch"
		} else {
			routeStatus.Protection = "unreachable backup route"
		}
		if !routeStatus.FailClosed && status.Problem == "" {
			status.Problem = "a fail-closed backup route is missing"
		}
		status.Routes = append(status.Routes, routeStatus)
	}
	return status
}

func hostInterfaceName(name string) string {
	const directPrefix = "nwg-"
	if len(directPrefix)+len(name) <= 15 {
		return directPrefix + name
	}
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(name))
	readable := strings.Trim(name[:6], "-")
	return fmt.Sprintf("nwg-%s-%04x", readable, hash.Sum32()&0xffff)
}

func hostRoutingTable(name string) int {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(name))
	return defaultTableBase + int(hash.Sum32()%1000)
}

func hostRoutingRulePriority(name string) int {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(name))
	return defaultRuleBase + int(hash.Sum32()%1000)*2
}

func prefixFamily(prefix netip.Prefix) int {
	if prefix.Addr().Is4() {
		return netlink.FAMILY_V4
	}
	return netlink.FAMILY_V6
}

func defaultHostRoute(prefix netip.Prefix, linkIndex, table int) netlink.Route {
	destination := prefixToIPNet(prefix)
	return netlink.Route{LinkIndex: linkIndex, Dst: &destination, Table: table}
}

func deleteDefaultHostRoute(handle *netlink.Handle, prefix netip.Prefix, table int) error {
	destination := prefixToIPNet(prefix)
	filter := &netlink.Route{Dst: &destination, Table: table}
	routes, err := handle.RouteListFiltered(prefixFamily(prefix), filter, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if err := handle.RouteDel(&route); err != nil {
			return err
		}
	}
	return nil
}

func reverseRules(rules []*netlink.Rule) []*netlink.Rule {
	result := make([]*netlink.Rule, len(rules))
	for index := range rules {
		result[len(rules)-1-index] = rules[index]
	}
	return result
}

func setOuterFirewallMark(chain *state.Chain, mark int) (resultErr error) {
	if len(chain.Hops) == 0 {
		return errors.New("chain has no WireGuard hops")
	}
	hop := chain.Hops[0]
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	namespace, err := netns.GetFromName(hop.InterfaceNamespace)
	if err != nil {
		return err
	}
	defer namespace.Close()
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
	configuration := wgtypes.Config{FirewallMark: &mark}
	return client.ConfigureDevice(hop.InterfaceName, configuration)
}

const srcValidMarkPath = "/proc/sys/net/ipv4/conf/all/src_valid_mark"

func readSrcValidMark() (int, error) {
	encoded, err := os.ReadFile(srcValidMarkPath)
	if err != nil {
		return 0, fmt.Errorf("read src_valid_mark: %w", err)
	}
	value, err := strconv.Atoi(string(bytes.TrimSpace(encoded)))
	if err != nil || (value != 0 && value != 1) {
		return 0, fmt.Errorf("unexpected src_valid_mark value %q", bytes.TrimSpace(encoded))
	}
	return value, nil
}

func writeSrcValidMark(value int) error {
	if err := os.WriteFile(srcValidMarkPath, []byte(strconv.Itoa(value)+"\n"), 0o644); err != nil {
		return fmt.Errorf("set src_valid_mark=%d: %w", value, err)
	}
	return nil
}

func changeKillSwitch(interfaceName string, mark, family int, operation string) error {
	binary := "iptables"
	if family == netlink.FAMILY_V6 {
		binary = "ip6tables"
	}
	path, err := exec.LookPath(binary)
	if err != nil {
		return fmt.Errorf("%s is required for default-route leak protection", binary)
	}
	args := killSwitchArguments(interfaceName, mark, operation)
	output, err := exec.Command(path, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("configure %s kill switch: %w: %s", binary, err, bytes.TrimSpace(output))
	}
	return nil
}

func killSwitchArguments(interfaceName string, mark int, operation string) []string {
	args := []string{"-w", "5", operation, "OUTPUT"}
	if operation == "-I" {
		args = append(args, "1")
	}
	return append(args,
		"!", "-o", interfaceName,
		"-m", "mark", "!", "--mark", strconv.Itoa(mark),
		"-m", "addrtype", "!", "--dst-type", "LOCAL",
		"-m", "comment", "--comment", "nestwg:"+interfaceName,
		"-j", "REJECT",
	)
}

func killSwitchExists(interfaceName string, mark, family int) bool {
	binary := "iptables"
	if family == netlink.FAMILY_V6 {
		binary = "ip6tables"
	}
	path, err := exec.LookPath(binary)
	if err != nil {
		return false
	}
	return exec.Command(path, killSwitchArguments(interfaceName, mark, "-C")...).Run() == nil
}

func defaultPolicyHealthy(chain *state.Chain, family int) bool {
	rules, err := netlink.RuleList(family)
	if err != nil {
		return false
	}
	wanted := defaultPolicyRules(chain, family)
	found := make([]bool, len(wanted))
	for _, existing := range rules {
		for index, candidate := range wanted {
			if existing.Priority == candidate.Priority && existing.Table == candidate.Table && existing.Invert == candidate.Invert && existing.SuppressPrefixlen == candidate.SuppressPrefixlen {
				found[index] = true
			}
		}
	}
	for _, ok := range found {
		if !ok {
			return false
		}
	}
	return true
}

func applyHostDNS(chain *state.Chain) error {
	var command *exec.Cmd
	switch chain.HostRouting.DNSBackend {
	case "resolvconf":
		path, _ := exec.LookPath("resolvconf")
		contents, err := os.ReadFile(chain.ResolverFile)
		if err != nil {
			return err
		}
		command = exec.Command(path, "-a", "tun."+chain.HostRouting.HostInterface, "-m", "0", "-x")
		command.Stdin = bytes.NewReader(contents)
	case "resolvectl":
		path, _ := exec.LookPath("resolvectl")
		document, err := config.Load(chain.ChainFile)
		if err != nil {
			return err
		}
		arguments := append([]string{"dns", chain.HostRouting.HostInterface}, document.Spec.DNS...)
		command = exec.Command(path, arguments...)
	default:
		return errors.New("host DNS backend is not recorded")
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install host DNS: %w: %s", err, bytes.TrimSpace(output))
	}
	if chain.HostRouting.DNSBackend == "resolvectl" {
		path, _ := exec.LookPath("resolvectl")
		for _, arguments := range [][]string{
			{"domain", chain.HostRouting.HostInterface, "~."},
			{"default-route", chain.HostRouting.HostInterface, "yes"},
		} {
			output, err := exec.Command(path, arguments...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("configure host DNS routing: %w: %s", err, bytes.TrimSpace(output))
			}
		}
	}
	return nil
}

func removeHostDNS(chain *state.Chain) error {
	var command *exec.Cmd
	switch chain.HostRouting.DNSBackend {
	case "resolvconf":
		path, err := exec.LookPath("resolvconf")
		if err != nil {
			return errors.New("cannot restore host DNS: resolvconf is unavailable")
		}
		command = exec.Command(path, "-d", "tun."+chain.HostRouting.HostInterface, "-f")
	case "resolvectl":
		path, err := exec.LookPath("resolvectl")
		if err != nil {
			return errors.New("cannot restore host DNS: resolvectl is unavailable")
		}
		command = exec.Command(path, "revert", chain.HostRouting.HostInterface)
	default:
		return nil
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("restore host DNS: %w: %s", err, bytes.TrimSpace(output))
	}
	return nil
}

func hostDNSBackend() (string, error) {
	if _, err := exec.LookPath("resolvconf"); err == nil {
		return "resolvconf", nil
	}
	if path, err := exec.LookPath("resolvectl"); err == nil {
		if err := exec.Command(path, "status").Run(); err == nil {
			return "resolvectl", nil
		}
	}
	return "", errors.New("spec.dns requires resolvconf or systemd-resolved's resolvectl")
}

func exactRoutes(handle *netlink.Handle, prefix netip.Prefix) ([]netlink.Route, error) {
	destination := prefixToIPNet(prefix)
	family := netlink.FAMILY_V6
	if prefix.Addr().Is4() {
		family = netlink.FAMILY_V4
	}
	return handle.RouteListFiltered(family, &netlink.Route{Dst: &destination}, netlink.RT_FILTER_DST)
}

func failClosedRoute(prefix netip.Prefix) netlink.Route {
	destination := prefixToIPNet(prefix)
	return netlink.Route{Dst: &destination, Type: syscall.RTN_UNREACHABLE, Priority: failClosedPriority}
}

func activeHostRoute(prefix netip.Prefix, linkIndex int) netlink.Route {
	destination := prefixToIPNet(prefix)
	return netlink.Route{Dst: &destination, LinkIndex: linkIndex, Priority: activeRoutePriority}
}
