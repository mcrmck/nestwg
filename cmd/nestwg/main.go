package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mcrmck/nestwg/internal/config"
	"github.com/mcrmck/nestwg/internal/engine"
)

const usage = `Usage:
  nestwg connect [--wait <duration>] <chain.yaml>
  nestwg validate <chain.yaml>
  nestwg plan <chain.yaml>
  nestwg up [--wait <duration>] <chain.yaml>
  nestwg down <chain-name>
  nestwg status [chain-name]
  nestwg exec <chain-name> -- <command> [arguments...]
  nestwg shell <chain-name>
  nestwg doctor
  nestwg recover <chain-name>
  nestwg version

Commands:
  connect   Connect a nested VPN, open a terminal through it, and disconnect on exit
  validate  Parse a chain and check its structure and referenced files
  plan      Preview endpoints, interfaces, routes, and MTUs without changing the host
  up        Create a persistent nested VPN chain
  down      Remove a chain and all resources owned by it
  status    List active chains or show one active chain
  exec      Run one command through a connected VPN
  shell     Open a shell through a connected VPN
  doctor    Check privileges and required Linux networking features
  recover   Remove orphaned VPN resources after state loss
  version   Print the NestWG version
`

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, engine.New()); err != nil {
		fmt.Fprintf(os.Stderr, "nestwg: %v\n", err)
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			os.Exit(exitError.ExitCode())
		}
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer, manager *engine.Manager) error {
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return nil
	}

	switch args[0] {
	case "__exec":
		if len(args) < 4 || args[2] != "--" {
			return errors.New("invalid internal payload invocation")
		}
		return manager.EnterAndExec(args[1], args[3:])
	case "validate":
		document, err := loadDocumentArgument(args)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "VPN configuration %q is valid (%d hops)\n", document.Metadata.Name, len(document.Spec.Hops))
		return nil
	case "connect":
		flags := flag.NewFlagSet("connect", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		wait := flags.Duration("wait", 10*time.Second, "wait for every VPN hop to handshake (0 disables)")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 1 || *wait < 0 {
			return errors.New("connect usage: nestwg connect [--wait <duration>] <chain.yaml>")
		}
		chain, err := manager.Up(context.Background(), flags.Arg(0))
		if err != nil {
			return err
		}
		cleaned := false
		defer func() {
			if !cleaned {
				_ = manager.Down(chain.Name)
			}
		}()
		if *wait > 0 {
			if err := manager.TriggerHandshake(chain.Name); err != nil {
				downErr := manager.Down(chain.Name)
				cleaned = downErr == nil
				return errors.Join(fmt.Errorf("start VPN handshakes: %w", err), downErr)
			}
			ctx, cancel := context.WithTimeout(context.Background(), *wait)
			_, waitErr := manager.WaitReady(ctx, chain.Name)
			cancel()
			if waitErr != nil {
				downErr := manager.Down(chain.Name)
				cleaned = downErr == nil
				return errors.Join(fmt.Errorf("connect VPN %q: %w", chain.Name, waitErr), downErr)
			}
		}
		fmt.Fprintf(stdout, "VPN %q ready through %d hops\n", chain.Name, len(chain.Hops))
		fmt.Fprintln(stdout, "VPN terminal started; type `exit` to disconnect")
		execErr := manager.ExecWithEnv(chain.Name, []string{userShell()}, map[string]string{
			"NESTWG_CHAIN": chain.Name,
			"NESTWG_VPN":   "1",
		})
		downErr := manager.Down(chain.Name)
		if downErr == nil {
			cleaned = true
			fmt.Fprintf(stdout, "VPN %q disconnected\n", chain.Name)
		}
		return errors.Join(execErr, downErr)
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
		wait := flags.Duration("wait", 0, "wait for every hop to handshake")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 1 || *wait < 0 {
			return errors.New("up usage: nestwg up [--wait <duration>] <chain.yaml>")
		}
		chain, err := manager.Up(context.Background(), flags.Arg(0))
		if err != nil {
			return err
		}
		if *wait > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), *wait)
			defer cancel()
			if _, err := manager.WaitReady(ctx, chain.Name); err != nil {
				return fmt.Errorf("chain %q is up but not ready: %w", chain.Name, err)
			}
		}
		fmt.Fprintf(stdout, "VPN %q is up\n", chain.Name)
		return nil
	case "down":
		if len(args) != 2 {
			return errors.New("down expects one chain name")
		}
		if err := manager.Down(args[1]); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "VPN %q is down\n", args[1])
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
			}
		}
		if len(args) == 2 && !found {
			return fmt.Errorf("VPN %q is not up", args[1])
		}
		if len(args) == 1 && !found {
			fmt.Fprintln(stdout, "no VPNs are up")
		}
		return nil
	case "exec":
		if len(args) < 4 || args[2] != "--" {
			return errors.New("exec usage: nestwg exec <chain-name> -- <command> [arguments...]")
		}
		return manager.Exec(args[1], args[3:])
	case "shell":
		if len(args) != 2 {
			return errors.New("shell expects one chain name")
		}
		fmt.Fprintf(stdout, "VPN terminal for %q; type `exit` to leave it\n", args[1])
		return manager.ExecWithEnv(args[1], []string{userShell()}, map[string]string{
			"NESTWG_CHAIN": args[1],
			"NESTWG_VPN":   "1",
		})
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

func userShell() string {
	shell := os.Getenv("SHELL")
	if shell == "" {
		return "/bin/sh"
	}
	return shell
}

func loadDocumentArgument(args []string) (*config.Document, error) {
	if len(args) != 2 {
		return nil, errors.New("expected one chain file")
	}
	document, err := config.Load(args[1])
	if err != nil {
		return nil, err
	}
	if err := document.Validate(); err != nil {
		return nil, fmt.Errorf("invalid chain: %w", err)
	}
	return document, nil
}
