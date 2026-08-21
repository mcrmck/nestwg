package plan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/mcrmck/nestwg/internal/config"
	"github.com/mcrmck/nestwg/internal/wgconfig"
)

const defaultBaseMTU = 1500

type Chain struct {
	Name             string `json:"name"`
	BaseMTU          int    `json:"baseMTU"`
	PayloadNamespace string `json:"payloadNamespace"`
	PayloadMTU       int    `json:"payloadMTU"`
	Hops             []Hop  `json:"hops"`
}

type Hop struct {
	Index              int              `json:"index"`
	Name               string           `json:"name"`
	WireGuardConfig    string           `json:"wireguardConfig"`
	OuterFamily        string           `json:"outerFamily"`
	EncapsulationBytes int              `json:"encapsulationBytes"`
	BirthNamespace     string           `json:"birthNamespace"`
	InterfaceNamespace string           `json:"interfaceNamespace"`
	InterfaceName      string           `json:"interfaceName"`
	InterfaceMTU       int              `json:"interfaceMTU"`
	Endpoint           string           `json:"endpoint,omitempty"`
	Addresses          []string         `json:"addresses,omitempty"`
	AllowedIPs         []string         `json:"allowedIPs,omitempty"`
	Material           *wgconfig.Config `json:"-"`
}

type IPResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

func Build(document *config.Document) (*Chain, error) {
	baseMTU := document.Spec.BaseMTU
	if baseMTU == 0 {
		baseMTU = defaultBaseMTU
	}
	payloadNamespace := fmt.Sprintf("nwg-%s-app", document.Metadata.Name)
	result := &Chain{
		Name:             document.Metadata.Name,
		BaseMTU:          baseMTU,
		PayloadNamespace: payloadNamespace,
		Hops:             make([]Hop, 0, len(document.Spec.Hops)),
	}

	currentMTU := baseMTU
	for index, configuredHop := range document.Spec.Hops {
		overhead, err := overheadFor(configuredHop.OuterFamily)
		if err != nil {
			return nil, fmt.Errorf("hop %q: %w", configuredHop.Name, err)
		}
		currentMTU -= overhead
		if currentMTU < 1280 {
			return nil, fmt.Errorf("hop %q reduces MTU to %d, below the IPv6 minimum of 1280", configuredHop.Name, currentMTU)
		}

		birthNamespace := "host"
		if index > 0 {
			birthNamespace = transitNamespace(document.Metadata.Name, index)
		}
		interfaceNamespace := payloadNamespace
		if index < len(document.Spec.Hops)-1 {
			interfaceNamespace = transitNamespace(document.Metadata.Name, index+1)
		}

		result.Hops = append(result.Hops, Hop{
			Index:              index,
			Name:               configuredHop.Name,
			WireGuardConfig:    configuredHop.WireGuardConfigPath,
			OuterFamily:        configuredHop.OuterFamily,
			EncapsulationBytes: overhead,
			BirthNamespace:     birthNamespace,
			InterfaceNamespace: interfaceNamespace,
			InterfaceName:      fmt.Sprintf("nwg%d", index),
			InterfaceMTU:       currentMTU,
		})
	}
	result.PayloadMTU = currentMTU
	return result, nil
}

// BuildResolved imports the WireGuard configuration and pins every endpoint
// before returning the plan. It contains no private or preshared keys.
func BuildResolved(ctx context.Context, document *config.Document, resolver IPResolver) (*Chain, error) {
	result, err := Build(document)
	if err != nil {
		return nil, err
	}
	if len(result.Hops) == 0 {
		return nil, errors.New("resolved plan requires at least one hop")
	}
	configs := make([]*wgconfig.Config, 0, len(result.Hops))
	for index := range result.Hops {
		imported, err := wgconfig.Load(result.Hops[index].WireGuardConfig)
		if err != nil {
			return nil, err
		}
		endpoint, err := resolveEndpoint(ctx, resolver, imported.Peers[0].Endpoint, result.Hops[index].OuterFamily)
		if err != nil {
			return nil, fmt.Errorf("hop %q endpoint: %w", result.Hops[index].Name, err)
		}
		result.Hops[index].Endpoint = endpoint.String()
		result.Hops[index].Material = imported
		for _, address := range imported.Addresses {
			result.Hops[index].Addresses = append(result.Hops[index].Addresses, address.String())
		}
		for _, allowed := range imported.Peers[0].AllowedIPs {
			result.Hops[index].AllowedIPs = append(result.Hops[index].AllowedIPs, allowed.String())
		}
		configs = append(configs, imported)
	}
	for index := 1; index < len(result.Hops); index++ {
		endpoint, err := netip.ParseAddrPort(result.Hops[index].Endpoint)
		if err != nil {
			return nil, err
		}
		if !prefixesContain(configs[index-1].Peers[0].AllowedIPs, endpoint.Addr()) {
			return nil, fmt.Errorf("hop %q AllowedIPs do not route the next endpoint %s", result.Hops[index-1].Name, endpoint.Addr())
		}
	}
	finalAllowed := configs[len(configs)-1].Peers[0].AllowedIPs
	for _, resolver := range document.Spec.DNS {
		address, err := netip.ParseAddr(resolver)
		if err != nil {
			return nil, err
		}
		if !prefixesContain(finalAllowed, address) {
			return nil, fmt.Errorf("exit hop %q AllowedIPs do not route DNS resolver %s", result.Hops[len(result.Hops)-1].Name, address)
		}
	}
	return result, nil
}

func resolveEndpoint(ctx context.Context, resolver IPResolver, endpoint, family string) (netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, errors.New("port must be between 1 and 65535")
	}
	network := "ip4"
	if family == "ipv6" {
		network = "ip6"
	}
	addresses, err := resolver.LookupNetIP(ctx, network, host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(addresses) == 0 {
		return netip.AddrPort{}, errors.New("resolved to no addresses")
	}
	address := addresses[0].Unmap()
	if (family == "ipv4" && !address.Is4()) || (family == "ipv6" && !address.Is6()) {
		return netip.AddrPort{}, fmt.Errorf("resolver returned %s for requested %s endpoint", address, family)
	}
	return netip.AddrPortFrom(address, uint16(port)), nil
}

func prefixesContain(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func transitNamespace(chainName string, inwardIndex int) string {
	return fmt.Sprintf("nwg-%s-t%d", chainName, inwardIndex)
}

func overheadFor(family string) (int, error) {
	switch family {
	case "ipv4":
		return 60, nil
	case "ipv6":
		return 80, nil
	default:
		return 0, fmt.Errorf("unsupported outer family %q", family)
	}
}
