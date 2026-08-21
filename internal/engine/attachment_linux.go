//go:build linux

package engine

import (
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"os"
	"sort"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/mcrmck/nestwg/internal/config"
	"github.com/mcrmck/nestwg/internal/state"
	"github.com/mcrmck/nestwg/internal/wgconfig"
)

const (
	activeRoutePriority = 50
	failClosedPriority  = 42760
)

type AttachmentStatus struct {
	Attached      bool
	InterfaceName string
	InterfaceUp   bool
	Routes        []RouteStatus
	Problem       string
}

type RouteStatus struct {
	Prefix     string
	Active     bool
	FailClosed bool
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
			return nil, fmt.Errorf("route %s is a default route; use `nestwg connect` for an isolated full-tunnel session", prefix)
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

func (m *Manager) Attach(name string, routes []netip.Prefix) (*state.Attachment, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("attach requires root privileges (try sudo)")
	}
	if len(routes) == 0 {
		return nil, errors.New("attach requires at least one route")
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
	if chain.Attachment != nil {
		return nil, fmt.Errorf("VPN %q is already attached; detach it before changing routes", name)
	}
	if err := validateAttachmentRoutes(chain, routes); err != nil {
		return nil, err
	}
	attachment := &state.Attachment{
		Phase:         state.AttachmentPhaseCreating,
		HostInterface: attachmentInterfaceName(name),
	}
	for _, route := range routes {
		attachment.Routes = append(attachment.Routes, route.String())
	}
	chain.Attachment = attachment
	// Reserve route and interface ownership before changing the kernel. Detach
	// can recover an interrupted attach from this creating-phase record.
	if err := m.Store.Save(chain); err != nil {
		return nil, err
	}
	if err := applyAttachment(chain, routes); err != nil {
		cleanupErr := removeAttachmentKernel(chain)
		if cleanupErr != nil {
			return nil, fmt.Errorf("attach VPN: %w (cleanup incomplete: %v); recovery state retained, run `nestwg detach %s`", err, cleanupErr, name)
		}
		chain.Attachment = nil
		return nil, errors.Join(err, m.Store.Save(chain))
	}
	attachment.Phase = state.AttachmentPhaseActive
	if err := m.Store.Save(chain); err != nil {
		cleanupErr := removeAttachmentKernel(chain)
		if cleanupErr != nil {
			return nil, fmt.Errorf("activate attachment state: %w (cleanup incomplete: %v); run `nestwg detach %s`", err, cleanupErr, name)
		}
		chain.Attachment = nil
		return nil, errors.Join(err, m.Store.Save(chain))
	}
	return attachment, nil
}

func (m *Manager) Detach(name string) error {
	if os.Geteuid() != 0 {
		return errors.New("detach requires root privileges (try sudo)")
	}
	unlock, err := m.Store.Lock(name)
	if err != nil {
		return err
	}
	defer unlock()
	chain, err := m.Store.Load(name)
	if err != nil {
		return err
	}
	if chain.Attachment == nil {
		return nil
	}
	if err := removeAttachmentKernel(chain); err != nil {
		return fmt.Errorf("detach VPN %q: %w; protected routes remain fail-closed", name, err)
	}
	chain.Attachment = nil
	return m.Store.Save(chain)
}

func validateAttachmentRoutes(chain *state.Chain, routes []netip.Prefix) error {
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

func applyAttachment(chain *state.Chain, routes []netip.Prefix) error {
	hostHandle, err := netlink.NewHandle()
	if err != nil {
		return err
	}
	defer hostHandle.Close()
	if _, err := hostHandle.LinkByName(chain.Attachment.HostInterface); err == nil {
		return fmt.Errorf("host interface %q already exists", chain.Attachment.HostInterface)
	}
	for _, route := range routes {
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
	if err := payloadHandle.LinkSetName(link, chain.Attachment.HostInterface); err != nil {
		return fmt.Errorf("name host VPN device: %w", err)
	}
	if err := payloadHandle.LinkSetNsFd(link, int(hostNamespace)); err != nil {
		return fmt.Errorf("expose exit VPN device to host: %w", err)
	}
	hostLink, err := hostHandle.LinkByName(chain.Attachment.HostInterface)
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
	for _, route := range routes {
		active := activeAttachmentRoute(route, hostLink.Attrs().Index)
		if err := hostHandle.RouteAdd(&active); err != nil {
			return fmt.Errorf("route %s through attachment: %w", route, err)
		}
	}
	return nil
}

func removeAttachmentKernel(chain *state.Chain) error {
	if chain.Attachment == nil {
		return nil
	}
	routes := make([]netip.Prefix, 0, len(chain.Attachment.Routes))
	for _, value := range chain.Attachment.Routes {
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
	finalHop := chain.Hops[len(chain.Hops)-1]

	// The device may be on the host, renamed but not yet moved after an
	// interrupted attach, or already restored by a previous detach attempt.
	if link, findErr := hostHandle.LinkByName(chain.Attachment.HostInterface); findErr == nil {
		if err := hostHandle.LinkSetNsFd(link, int(payload)); err != nil {
			return fmt.Errorf("return exit VPN device to payload: %w", err)
		}
	}
	if link, findErr := payloadHandle.LinkByName(chain.Attachment.HostInterface); findErr == nil {
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
	var cleanup []error
	for _, prefix := range routes {
		blocked := failClosedRoute(prefix)
		if err := hostHandle.RouteDel(&blocked); err != nil && !errors.Is(err, syscall.ESRCH) {
			cleanup = append(cleanup, fmt.Errorf("remove fail-closed route %s: %w", prefix, err))
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

func (m *Manager) InspectAttachment(chain *state.Chain) AttachmentStatus {
	if chain.Attachment == nil {
		return AttachmentStatus{}
	}
	status := AttachmentStatus{Attached: true, InterfaceName: chain.Attachment.HostInterface}
	handle, err := netlink.NewHandle()
	if err != nil {
		status.Problem = err.Error()
		return status
	}
	defer handle.Close()
	link, linkErr := handle.LinkByName(chain.Attachment.HostInterface)
	status.InterfaceUp = linkErr == nil && link.Attrs().Flags&net.FlagUp != 0
	if linkErr != nil {
		status.Problem = "host VPN device is missing; protected routes remain blocked"
	}
	for _, value := range chain.Attachment.Routes {
		prefix, _ := netip.ParsePrefix(value)
		routeStatus := RouteStatus{Prefix: value}
		existing, routeErr := exactRoutes(handle, prefix)
		if routeErr != nil && status.Problem == "" {
			status.Problem = routeErr.Error()
		}
		for _, route := range existing {
			if route.Type == syscall.RTN_UNREACHABLE && route.Priority == failClosedPriority {
				routeStatus.FailClosed = true
			}
			if linkErr == nil && route.LinkIndex == link.Attrs().Index && route.Priority == activeRoutePriority {
				routeStatus.Active = true
			}
		}
		if !routeStatus.FailClosed && status.Problem == "" {
			status.Problem = "a fail-closed backup route is missing"
		}
		status.Routes = append(status.Routes, routeStatus)
	}
	return status
}

func attachmentInterfaceName(name string) string {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(name))
	return fmt.Sprintf("nwg%08x", hash.Sum32())
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

func activeAttachmentRoute(prefix netip.Prefix, linkIndex int) netlink.Route {
	destination := prefixToIPNet(prefix)
	return netlink.Route{Dst: &destination, LinkIndex: linkIndex, Priority: activeRoutePriority}
}
