// Package wgconfig imports the subset of wg-quick configuration that nestwg
// needs. It deliberately treats hook commands as data and never executes them.
package wgconfig

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Addresses  []netip.Prefix
	PrivateKey [32]byte
	Peers      []Peer
}

type Peer struct {
	PublicKey           [32]byte
	PresharedKey        *[32]byte
	Endpoint            string
	AllowedIPs          []netip.Prefix
	PersistentKeepalive uint16
}

func Load(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open WireGuard configuration %q: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect WireGuard configuration %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("WireGuard configuration %q must be a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("WireGuard configuration %q permissions are %04o; private-key files must not be accessible by group or other users", path, info.Mode().Perm())
	}

	config, err := parse(bufio.NewScanner(file))
	if err != nil {
		return nil, fmt.Errorf("parse WireGuard configuration %q: %w", path, err)
	}
	return config, nil
}

func parse(scanner *bufio.Scanner) (*Config, error) {
	config := &Config{}
	section := ""
	privateKeySet := false
	var peer *Peer

	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
				peer = nil
			case "peer":
				config.Peers = append(config.Peers, Peer{})
				peer = &config.Peers[len(config.Peers)-1]
			default:
				return nil, lineError(lineNumber, "unsupported section")
			}
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found || section == "" {
			return nil, lineError(lineNumber, "expected key = value inside a section")
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		var err error
		switch section {
		case "interface":
			err = parseInterfaceField(config, key, value, &privateKeySet)
		case "peer":
			err = parsePeerField(peer, key, value)
		}
		if err != nil {
			return nil, lineError(lineNumber, err.Error())
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}

	var validationErrors []error
	if !privateKeySet {
		validationErrors = append(validationErrors, errors.New("Interface.PrivateKey is required"))
	}
	if len(config.Addresses) == 0 {
		validationErrors = append(validationErrors, errors.New("Interface.Address is required"))
	}
	if len(config.Peers) != 1 {
		validationErrors = append(validationErrors, fmt.Errorf("exactly one Peer is required, found %d", len(config.Peers)))
	} else {
		if config.Peers[0].PublicKey == ([32]byte{}) {
			validationErrors = append(validationErrors, errors.New("Peer.PublicKey is required"))
		}
		if config.Peers[0].Endpoint == "" {
			validationErrors = append(validationErrors, errors.New("Peer.Endpoint is required"))
		}
		if len(config.Peers[0].AllowedIPs) == 0 {
			validationErrors = append(validationErrors, errors.New("Peer.AllowedIPs is required"))
		}
	}
	if err := errors.Join(validationErrors...); err != nil {
		return nil, err
	}
	return config, nil
}

func parseInterfaceField(config *Config, key, value string, privateKeySet *bool) error {
	switch key {
	case "privatekey":
		parsed, err := parseKey(value)
		if err != nil {
			return errors.New("Interface.PrivateKey must be a base64-encoded 32-byte key")
		}
		config.PrivateKey = parsed
		*privateKeySet = true
	case "address":
		prefixes, err := parsePrefixes(value)
		if err != nil {
			return fmt.Errorf("Interface.Address: %w", err)
		}
		config.Addresses = append(config.Addresses, prefixes...)
	case "dns", "mtu", "table", "preup", "postup", "predown", "postdown", "listenport", "fwmark", "saveconfig":
		// wg-quick metadata and hooks are intentionally not applied by nestwg.
	default:
		return fmt.Errorf("unsupported Interface field %q", key)
	}
	return nil
}

func parsePeerField(peer *Peer, key, value string) error {
	switch key {
	case "publickey":
		parsed, err := parseKey(value)
		if err != nil {
			return errors.New("Peer.PublicKey must be a base64-encoded 32-byte key")
		}
		peer.PublicKey = parsed
	case "presharedkey":
		parsed, err := parseKey(value)
		if err != nil {
			return errors.New("Peer.PresharedKey must be a base64-encoded 32-byte key")
		}
		peer.PresharedKey = &parsed
	case "endpoint":
		if err := validateEndpoint(value); err != nil {
			return fmt.Errorf("Peer.Endpoint: %w", err)
		}
		peer.Endpoint = value
	case "allowedips":
		prefixes, err := parsePrefixes(value)
		if err != nil {
			return fmt.Errorf("Peer.AllowedIPs: %w", err)
		}
		peer.AllowedIPs = append(peer.AllowedIPs, prefixes...)
	case "persistentkeepalive":
		if strings.EqualFold(value, "off") {
			peer.PersistentKeepalive = 0
			return nil
		}
		seconds, err := strconv.ParseUint(value, 10, 16)
		if err != nil || seconds > 65535 {
			return errors.New("Peer.PersistentKeepalive must be an integer from 0 to 65535")
		}
		peer.PersistentKeepalive = uint16(seconds)
	default:
		return fmt.Errorf("unsupported Peer field %q", key)
	}
	return nil
}

func parseKey(value string) ([32]byte, error) {
	var result [32]byte
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != len(result) {
		return result, errors.New("invalid key")
	}
	copy(result[:], decoded)
	return result, nil
}

func parsePrefixes(value string) ([]netip.Prefix, error) {
	parts := strings.Split(value, ",")
	result := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil {
			return nil, errors.New("must contain only IP prefixes")
		}
		result = append(result, prefix)
	}
	return result, nil
}

func validateEndpoint(value string) error {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || strings.TrimSpace(host) == "" {
		return errors.New("must be host:port (IPv6 addresses must use brackets)")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

func lineError(line int, message string) error {
	return fmt.Errorf("line %d: %s", line, message)
}
