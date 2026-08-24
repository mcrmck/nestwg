package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/mcrmck/nestwg/internal/config"
	"github.com/mcrmck/nestwg/internal/engine"
)

const usage = `Usage:
  nestwg validate <chain>
  nestwg plan <chain>
  nestwg up [options] <chain>
  nestwg down [--verbose] <chain>
  nestwg status [chain-name]
  nestwg diagnose <chain-name>
  nestwg doctor
  nestwg recover <chain-name>
  nestwg version

Commands:
  validate  Parse a chain and check its structure and referenced files
  plan      Preview endpoints, interfaces, routes, and MTUs without changing the host
  up        Create a nested VPN and expose one WireGuard interface to the host
  down      Remove host routing, the interface, and every nested VPN resource
  status    List active chains or show one active chain
  diagnose  Explain VPN, handshake, host-routing, and leak-protection health
  doctor    Check privileges and required Linux networking features
  recover   Remove orphaned VPN resources after state loss
  version   Print the NestWG version
`

var commandUsage = map[string]string{
	"validate": "Usage: nestwg validate <chain>\n\nValidate a chain and every referenced WireGuard configuration.\n",
	"plan":     "Usage: nestwg plan <chain>\n\nPreview endpoints, interfaces, routes, and MTUs without changing the host.\n",
	"up": `Usage: nestwg up [options] <chain>

Bring up a nested VPN and expose its final WireGuard interface to the host.

Options:
  --wait <duration>  Wait for every hop to handshake (default 10s; 0 disables)
  --default-route    Route every supported address family through the VPN
  --route <CIDR>     Route one destination through the VPN (repeatable)
  --isolated         Construct the chain without host routing (diagnostics only)
  -v, --verbose      Print lifecycle progress
`,
	"down":     "Usage: nestwg down [--verbose] <chain>\n\nRemove host routing, the visible interface, and every nested VPN resource.\n\nOptions:\n  -v, --verbose  Print lifecycle progress\n",
	"status":   "Usage: nestwg status [chain-name]\n\nList active VPNs or show detailed status for one VPN.\n",
	"diagnose": "Usage: nestwg diagnose <chain-name>\n\nCheck handshakes, routing, and leak protection for an active VPN.\n",
	"doctor":   "Usage: nestwg doctor\n\nCheck privileges and required Linux networking features.\n",
	"recover":  "Usage: nestwg recover <chain-name>\n\nRemove process-free orphan resources after runtime state is lost.\n",
	"version":  "Usage: nestwg version\n\nPrint the NestWG version.\n",
}

var chainConfigDirectory = "/etc/nestwg"
var bareChainName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, engine.New()); err != nil {
		fmt.Fprintf(os.Stderr, "nestwg: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer, manager *engine.Manager) error {
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return nil
	}
	if args[0] == "--help" || args[0] == "-h" {
		if len(args) != 1 {
			return errors.New("global help does not accept arguments")
		}
		fmt.Fprint(stdout, usage)
		return nil
	}
	if args[0] == "help" {
		if len(args) == 1 {
			fmt.Fprint(stdout, usage)
			return nil
		}
		if len(args) != 2 {
			return errors.New("help accepts at most one command")
		}
		return printCommandUsage(stdout, args[1])
	}
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		return printCommandUsage(stdout, args[0])
	}

	switch args[0] {
	case "validate":
		document, err := loadDocumentArgument(args)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "VPN configuration %q is valid (%d hops)\n", document.Metadata.Name, len(document.Spec.Hops))
		return nil
	case "plan":
		document, err := loadDocumentArgument(args)
		if err != nil {
			return err
		}
		chainPlan, err := manager.Plan(context.Background(), document)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(chainPlan)
	case "up":
		flags := flag.NewFlagSet("up", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		wait := flags.Duration("wait", 10*time.Second, "wait for every hop to handshake (0 disables)")
		defaultRoute := flags.Bool("default-route", false, "route every supported address family through the VPN")
		isolated := flags.Bool("isolated", false, "construct the nested chain without host routing")
		verbose := flags.Bool("verbose", false, "print lifecycle progress")
		flags.BoolVar(verbose, "v", false, "print lifecycle progress")
		var routeValues stringList
		flags.Var(&routeValues, "route", "route one destination CIDR through the VPN (repeatable)")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 1 || *wait < 0 {
			return errors.New("up usage: nestwg up [--wait <duration>] [--default-route | --route <CIDR>... | --isolated] <chain.yaml>")
		}
		chainPath, err := resolveChainPath(flags.Arg(0))
		if err != nil {
			return err
		}
		document, err := config.Load(chainPath)
		if err != nil {
			return err
		}
		if err := document.Validate(); err != nil {
			return fmt.Errorf("invalid chain: %w", err)
		}
		if *verbose {
			fmt.Fprintf(stdout, "validating %s\n", chainPath)
			fmt.Fprintf(stdout, "creating %d-hop VPN %q\n", len(document.Spec.Hops), document.Metadata.Name)
		}
		mode, routes, err := resolveHostRouting(document, *defaultRoute, *isolated, routeValues)
		if err != nil {
			return err
		}
		operationContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		effectiveDocument := *document
		effectiveDocument.Spec = document.Spec
		effectiveDocument.Spec.HostRouting = config.HostRouting{Mode: mode}
		for _, route := range routes {
			effectiveDocument.Spec.HostRouting.Routes = append(effectiveDocument.Spec.HostRouting.Routes, route.String())
		}
		chain, err := manager.Up(operationContext, chainPath, effectiveDocument.Spec.HostRouting)
		if err != nil {
			return err
		}
		cleanupOnError := func(operationErr error) error {
			return errors.Join(operationErr, manager.Down(chain.Name))
		}
		if *wait > 0 {
			if *verbose {
				fmt.Fprintf(stdout, "waiting up to %s for all handshakes\n", wait.String())
			}
			if err := manager.TriggerHandshake(chain.Name); err != nil {
				return cleanupOnError(fmt.Errorf("start VPN handshakes: %w", err))
			}
			ctx, cancel := context.WithTimeout(operationContext, *wait)
			_, waitErr := manager.WaitReady(ctx, chain.Name)
			cancel()
			if waitErr != nil {
				return cleanupOnError(fmt.Errorf("bring up VPN %q: %w", chain.Name, waitErr))
			}
		}
		if err := operationContext.Err(); err != nil {
			return cleanupOnError(err)
		}
		if mode != config.HostRoutingIsolated {
			if *verbose {
				fmt.Fprintf(stdout, "configuring %s host routing\n", mode)
			}
			routing, err := manager.ConfigureHostRouting(chain.Name, mode, routes)
			if err != nil {
				return cleanupOnError(err)
			}
			fmt.Fprintf(stdout, "VPN %q is up as %s (%s host routing)\n", chain.Name, routing.HostInterface, mode)
		} else {
			fmt.Fprintf(stdout, "VPN %q is up in isolated diagnostic mode\n", chain.Name)
		}
		return nil
	case "down":
		flags := flag.NewFlagSet("down", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		verbose := flags.Bool("verbose", false, "print lifecycle progress")
		flags.BoolVar(verbose, "v", false, "print lifecycle progress")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 1 {
			return errors.New("down usage: nestwg down [--verbose] <chain>")
		}
		name, err := resolveChainName(flags.Arg(0))
		if err != nil {
			return err
		}
		if *verbose {
			fmt.Fprintf(stdout, "removing host routing and nested VPN %q\n", name)
		}
		if err := manager.Down(name); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "VPN %q is down\n", name)
		return nil
	case "status":
		if len(args) > 2 {
			return errors.New("status accepts at most one chain name")
		}
		chains, err := manager.List()
		if err != nil {
			return err
		}
		found := false
		for _, chain := range chains {
			if len(args) == 2 && chain.Name != args[1] {
				continue
			}
			found = true
			status, err := manager.Inspect(chain.Name)
			if err != nil {
				return err
			}
			condition := "connecting"
			if status.Ready {
				condition = "ready"
			} else if status.Problem != "" || chain.Phase != "active" {
				condition = "degraded"
			}
			fmt.Fprintf(stdout, "%s\t%s\tsince %s\n", chain.Name, condition, chain.CreatedAt.Format(time.RFC3339))
			if len(args) == 2 {
				if status.Problem != "" {
					fmt.Fprintf(stdout, "  problem: %s\n", status.Problem)
				}
				for _, hop := range status.Hops {
					handshake := "pending"
					if !hop.Handshake.IsZero() {
						handshake = hop.Handshake.Format(time.RFC3339)
					}
					if hop.Error != "" {
						handshake = "error: " + hop.Error
					}
					fmt.Fprintf(stdout, "  %s (%s): handshake %s, rx %d, tx %d\n", hop.Name, hop.InterfaceName, handshake, hop.ReceiveBytes, hop.TransmitBytes)
				}
				if status.HostRouting.Attached {
					deviceState := "down"
					if status.HostRouting.InterfaceUp {
						deviceState = "up"
					}
					fmt.Fprintf(stdout, "  host device %s: %s (%s routing)\n", status.HostRouting.InterfaceName, deviceState, status.HostRouting.Mode)
					for _, route := range status.HostRouting.Routes {
						condition := "blocked"
						if route.Active && route.FailClosed {
							condition = "VPN, fail-closed"
						} else if !route.FailClosed {
							condition = "unsafe"
						}
						fmt.Fprintf(stdout, "  route %s: %s\n", route.Prefix, condition)
					}
				}
			}
		}
		if len(args) == 2 && !found {
			return fmt.Errorf("VPN %q is not up", args[1])
		}
		if len(args) == 1 && !found {
			fmt.Fprintln(stdout, "no VPNs are up")
		}
		return nil
	case "diagnose":
		if len(args) != 2 {
			return errors.New("diagnose expects one chain name")
		}
		status, err := manager.Inspect(args[1])
		if err != nil {
			return err
		}
		failed := printDiagnostics(stdout, status)
		if failed {
			return fmt.Errorf("VPN %q has one or more failed checks", args[1])
		}
		return nil
	case "doctor":
		if len(args) != 1 {
			return errors.New("doctor does not accept arguments")
		}
		failed := false
		for _, check := range manager.Doctor() {
			result := "ok"
			if !check.OK {
				result = "failed"
				failed = true
			}
			fmt.Fprintf(stdout, "%-24s %s", check.Name, result)
			if check.Message != "" {
				fmt.Fprintf(stdout, ": %s", check.Message)
			}
			fmt.Fprintln(stdout)
		}
		if failed {
			return errors.New("one or more prerequisite checks failed")
		}
		return nil
	case "recover":
		if len(args) != 2 {
			return errors.New("recover expects one chain name")
		}
		namespaces, err := manager.Recover(args[1])
		if err != nil {
			return err
		}
		if len(namespaces) == 0 {
			fmt.Fprintf(stdout, "no orphaned resources found for chain %q\n", args[1])
			return nil
		}
		fmt.Fprintf(stdout, "recovered chain %q (%s)\n", args[1], strings.Join(namespaces, ", "))
		return nil
	case "version":
		if len(args) != 1 {
			return errors.New("version does not accept arguments")
		}
		fmt.Fprintf(stdout, "nestwg %s\n", version)
		return nil
	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
	}
}

func printCommandUsage(stdout io.Writer, command string) error {
	commandHelp, ok := commandUsage[command]
	if !ok {
		return fmt.Errorf("unknown command %q\n\n%s", command, usage)
	}
	fmt.Fprint(stdout, commandHelp)
	return nil
}

func resolveChainPath(reference string) (string, error) {
	if bareChainName.MatchString(reference) {
		return filepath.Join(chainConfigDirectory, reference+".yaml"), nil
	}
	if strings.TrimSpace(reference) == "" {
		return "", errors.New("chain reference must not be empty")
	}
	return reference, nil
}

func resolveChainName(reference string) (string, error) {
	if bareChainName.MatchString(reference) {
		return reference, nil
	}
	path, err := resolveChainPath(reference)
	if err != nil {
		return "", err
	}
	document, err := config.Load(path)
	if err != nil {
		return "", err
	}
	if err := document.Validate(); err != nil {
		return "", fmt.Errorf("invalid chain: %w", err)
	}
	return document.Metadata.Name, nil
}

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func resolveHostRouting(document *config.Document, defaultRoute, isolated bool, values []string) (string, []netip.Prefix, error) {
	overrides := 0
	if defaultRoute {
		overrides++
	}
	if isolated {
		overrides++
	}
	if len(values) != 0 {
		overrides++
	}
	if overrides > 1 {
		return "", nil, errors.New("--default-route, --route, and --isolated are mutually exclusive")
	}
	mode := document.Spec.HostRouting.Mode
	routeValues := document.Spec.HostRouting.Routes
	switch {
	case defaultRoute:
		mode, routeValues = config.HostRoutingDefault, nil
	case isolated:
		mode, routeValues = config.HostRoutingIsolated, nil
	case len(values) != 0:
		mode, routeValues = config.HostRoutingSelected, values
	}
	if mode != config.HostRoutingSelected {
		return mode, nil, nil
	}
	routes, err := engine.ParseRoutes(routeValues)
	return mode, routes, err
}

func printDiagnostics(stdout io.Writer, status *engine.ChainStatus) bool {
	failed := false
	printCheck := func(name string, ok bool, message string) {
		result := "ok"
		if !ok {
			result = "failed"
			failed = true
		}
		fmt.Fprintf(stdout, "%-28s %s", name, result)
		if message != "" {
			fmt.Fprintf(stdout, ": %s", message)
		}
		fmt.Fprintln(stdout)
	}
	printCheck("runtime state", status.Chain.Phase == "active", "phase "+status.Chain.Phase)
	constructionOK := len(status.Hops) == len(status.Chain.Hops)
	constructionMessage := ""
	if !constructionOK {
		constructionMessage = status.Problem
	}
	printCheck("network construction", constructionOK, constructionMessage)
	for _, hop := range status.Hops {
		message := "no handshake yet"
		ok := hop.Error == "" && !hop.Handshake.IsZero()
		if hop.Error != "" {
			message = hop.Error
		} else if ok {
			message = fmt.Sprintf("last handshake %s; rx %d, tx %d", hop.Handshake.Format(time.RFC3339), hop.ReceiveBytes, hop.TransmitBytes)
		}
		printCheck("hop "+hop.Name, ok, message)
	}
	if !status.HostRouting.Attached {
		printCheck("host routing", true, "isolated diagnostic mode")
		return failed
	}
	printCheck("host device", status.HostRouting.InterfaceUp, status.HostRouting.InterfaceName)
	for _, route := range status.HostRouting.Routes {
		printCheck("route "+route.Prefix, route.Active, "selected through "+status.HostRouting.InterfaceName)
		printCheck("leak protection "+route.Prefix, route.FailClosed, route.Protection)
	}
	return failed
}

func loadDocumentArgument(args []string) (*config.Document, error) {
	if len(args) != 2 {
		return nil, errors.New("expected one chain")
	}
	path, err := resolveChainPath(args[1])
	if err != nil {
		return nil, err
	}
	document, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if err := document.Validate(); err != nil {
		return nil, fmt.Errorf("invalid chain: %w", err)
	}
	return document, nil
}
