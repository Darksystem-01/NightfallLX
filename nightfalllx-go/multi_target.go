package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"nightfalllx/pkg/targetlist"
	"nightfalllx/pkg/update"
)

type multiTargetOptions struct {
	Path          string
	BaseOutput    string
	LogFile       string
	NoUpdateCheck bool
	Args          []string
}

func runTargetList(ctx context.Context, opts multiTargetOptions) int {
	targets, err := targetlist.Load(opts.Path)
	if err != nil {
		fmt.Printf("\033[31m[!] %v\033[0m\n", err)
		return 1
	}

	executable, err := os.Executable()
	if err != nil {
		fmt.Printf("\033[31m[!] Could not locate the NightfallLX executable: %v\033[0m\n", err)
		return 1
	}

	if !opts.NoUpdateCheck {
		printUpdateNotice(ctx)
	}

	fmt.Printf("\033[36m[*] Multi-target mode: %d target(s), sequential execution\033[0m\n", len(targets))
	failures := 0
	for index, target := range targets {
		if ctx.Err() != nil {
			fmt.Println("\033[33m[!] Multi-target scan interrupted.\033[0m")
			return 130
		}

		outputBase := targetlist.OutputBase(opts.BaseOutput, target)
		logPath := ""
		if opts.LogFile != "" {
			logPath = outputBase + ".log"
		}
		args := targetArgs(opts.Args, target, outputBase, logPath)

		fmt.Printf("\n\033[1;36m[%d/%d] Scanning %s\033[0m\n", index+1, len(targets), target)
		fmt.Printf("\033[90m       report base: %s\033[0m\n", outputBase)

		command := exec.CommandContext(ctx, executable, args...)
		command.Stdin = os.Stdin
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		command.Env = append(os.Environ(), "NIGHTFALLX_NO_UPDATE_CHECK=1")

		if err := command.Run(); err != nil {
			if ctx.Err() != nil {
				fmt.Println("\033[33m[!] Multi-target scan interrupted.\033[0m")
				return 130
			}
			failures++
			fmt.Printf("\033[31m[!] %s failed: %v\033[0m\n", target, err)
			continue
		}
		fmt.Printf("\033[32m[+] %s completed\033[0m\n", target)
	}

	succeeded := len(targets) - failures
	fmt.Printf("\n\033[1;36m[*] Multi-target summary: %d succeeded, %d failed, %d total\033[0m\n", succeeded, failures, len(targets))
	if failures > 0 {
		return 1
	}
	return 0
}

func targetArgs(args []string, target, outputBase, logPath string) []string {
	cleaned := stripTargetFlags(args, "l", "list", "u", "o", "log")
	cleaned = append(cleaned, "-u", target, "-o", outputBase)
	if logPath != "" {
		cleaned = append(cleaned, "-log", logPath)
	}
	cleaned = append(cleaned, "-l=", "-list=", "-no-update-check")
	return cleaned
}

func stripTargetFlags(args []string, names ...string) []string {
	blocked := make(map[string]struct{}, len(names))
	for _, name := range names {
		blocked[name] = struct{}{}
	}

	cleaned := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") {
			cleaned = append(cleaned, arg)
			continue
		}

		name := strings.TrimLeft(arg, "-")
		if equals := strings.IndexByte(name, '='); equals >= 0 {
			name = name[:equals]
		}
		if _, remove := blocked[name]; !remove {
			cleaned = append(cleaned, arg)
			continue
		}
		if !strings.Contains(arg, "=") && index+1 < len(args) {
			index++
		}
	}
	return cleaned
}

func printUpdateNotice(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	updateCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	check, err := update.NewClient().Check(updateCtx)
	if err == nil && check != nil && check.UpdateAvailable {
		fmt.Printf("\033[33m[!] NightfallLX %s is available (current %s). %s\033[0m\n",
			check.LatestVersion, check.CurrentVersion, check.URL)
	}
}
