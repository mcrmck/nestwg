package config

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mcrmck/nestwg/internal/wgconfig"

	"gopkg.in/yaml.v3"
)

const (
	APIVersion = "nestwg.io/v1alpha1"
	Kind       = "Chain"
)

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

type Document struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

type Metadata struct {
	Name string `yaml:"name"`
}

type Spec struct {
	BaseMTU     int         `yaml:"baseMTU,omitempty"`
	DNS         []string    `yaml:"dns,omitempty"`
	HostRouting HostRouting `yaml:"hostRouting"`
	Hops        []Hop       `yaml:"hops"`
}

const (
	HostRoutingDefault  = "default"
	HostRoutingSelected = "selected"
	HostRoutingIsolated = "isolated"
)

// HostRouting describes how the innermost WireGuard interface is exposed to
// the host after the nested chain is constructed.
type HostRouting struct {
	Mode   string   `yaml:"mode" json:"mode"`
	Routes []string `yaml:"routes,omitempty" json:"routes,omitempty"`
}

type Hop struct {
	Name                string `yaml:"name"`
	WireGuardConfigPath string `yaml:"wireguardConfig"`
	OuterFamily         string `yaml:"outerFamily"`
}

func Load(path string) (*Document, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open chain %q: %w", path, err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)

	var document Document
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode chain %q: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("decode chain %q: multiple YAML documents are not allowed", path)
		}
		return nil, fmt.Errorf("decode chain %q: %w", path, err)
	}

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve chain path %q: %w", path, err)
	}
	baseDirectory := filepath.Dir(absolutePath)
	for index := range document.Spec.Hops {
		configPath := document.Spec.Hops[index].WireGuardConfigPath
		if configPath != "" && !filepath.IsAbs(configPath) {
			document.Spec.Hops[index].WireGuardConfigPath = filepath.Clean(filepath.Join(baseDirectory, configPath))
		}
	}

	return &document, nil
}

func (document *Document) Validate() error {
	var validationErrors []error
	if document.APIVersion != APIVersion {
		validationErrors = append(validationErrors, fmt.Errorf("apiVersion must be %q", APIVersion))
	}
	if document.Kind != Kind {
		validationErrors = append(validationErrors, fmt.Errorf("kind must be %q", Kind))
	}
	if !namePattern.MatchString(document.Metadata.Name) {
		validationErrors = append(validationErrors, errors.New("metadata.name must start with a letter and contain at most 32 lowercase letters, numbers, or hyphens"))
	}
	if document.Spec.BaseMTU != 0 && (document.Spec.BaseMTU < 1280 || document.Spec.BaseMTU > 9216) {
		validationErrors = append(validationErrors, errors.New("spec.baseMTU must be between 1280 and 9216"))
	}
	if len(document.Spec.Hops) < 2 {
		validationErrors = append(validationErrors, errors.New("spec.hops must contain at least two hops"))
	}
	if err := document.Spec.HostRouting.Validate(); err != nil {
		validationErrors = append(validationErrors, fmt.Errorf("spec.hostRouting: %w", err))
	}
	if document.Spec.HostRouting.Mode == HostRoutingIsolated && len(document.Spec.DNS) != 0 {
		validationErrors = append(validationErrors, errors.New("spec.dns is not used with isolated host routing"))
	}

	for index, resolver := range document.Spec.DNS {
		if _, err := netip.ParseAddr(resolver); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("spec.dns[%d] must be an IP address: %q", index, resolver))
		}
	}

	seenNames := make(map[string]struct{}, len(document.Spec.Hops))
	for index, hop := range document.Spec.Hops {
		field := fmt.Sprintf("spec.hops[%d]", index)
		if !namePattern.MatchString(hop.Name) {
			validationErrors = append(validationErrors, fmt.Errorf("%s.name is invalid", field))
		}
		if _, exists := seenNames[hop.Name]; exists {
			validationErrors = append(validationErrors, fmt.Errorf("%s.name %q is duplicated", field, hop.Name))
		}
		seenNames[hop.Name] = struct{}{}

		if strings.TrimSpace(hop.WireGuardConfigPath) == "" {
			validationErrors = append(validationErrors, fmt.Errorf("%s.wireguardConfig is required", field))
		} else if info, err := os.Stat(hop.WireGuardConfigPath); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("%s.wireguardConfig: %w", field, err))
		} else if !info.Mode().IsRegular() {
			validationErrors = append(validationErrors, fmt.Errorf("%s.wireguardConfig must be a regular file", field))
		} else if _, err := wgconfig.Load(hop.WireGuardConfigPath); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("%s.wireguardConfig: %w", field, err))
		}

		if hop.OuterFamily != "ipv4" && hop.OuterFamily != "ipv6" {
			validationErrors = append(validationErrors, fmt.Errorf("%s.outerFamily must be ipv4 or ipv6", field))
		}
	}

	return errors.Join(validationErrors...)
}

func (routing HostRouting) Validate() error {
	switch routing.Mode {
	case HostRoutingDefault, HostRoutingIsolated:
		if len(routing.Routes) != 0 {
			return fmt.Errorf("mode %q does not accept routes", routing.Mode)
		}
	case HostRoutingSelected:
		if len(routing.Routes) == 0 {
			return errors.New("mode \"selected\" requires at least one route")
		}
	case "":
		return errors.New("mode is required (default, selected, or isolated)")
	default:
		return fmt.Errorf("mode must be default, selected, or isolated, not %q", routing.Mode)
	}
	seen := make(map[netip.Prefix]struct{}, len(routing.Routes))
	for index, value := range routing.Routes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return fmt.Errorf("routes[%d] is not a CIDR: %q", index, value)
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 {
			return fmt.Errorf("routes[%d] is a default route; use mode \"default\"", index)
		}
		if _, exists := seen[prefix]; exists {
			return fmt.Errorf("route %s is duplicated", prefix)
		}
		seen[prefix] = struct{}{}
	}
	return nil
}
