package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const hookMarker = "# sentinelflow-pre-commit-hook"

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Manage git hooks",
	Long:  "Install or uninstall SentinelFlow pre-commit hooks for shift-left security scanning",
}

var hookInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install pre-commit hook",
	RunE: func(cmd *cobra.Command, args []string) error {
		gitDir, err := findGitDir()
		if err != nil {
			return err
		}

		hookPath := filepath.Join(gitDir, "hooks", "pre-commit")
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to resolve executable: %w", err)
		}

		hookContent := fmt.Sprintf(`#!/bin/sh
%s
exec "%s" scan --secrets --iac --fail-on high
`, hookMarker, exe)

		if err := os.MkdirAll(filepath.Dir(hookPath), 0755); err != nil {
			return fmt.Errorf("failed to create hooks directory: %w", err)
		}

		if data, err := os.ReadFile(hookPath); err == nil {
			if containsMarker(string(data)) {
				fmt.Println(color.YellowString("Pre-commit hook already installed"))
				return nil
			}
		}

		if err := os.WriteFile(hookPath, []byte(hookContent), 0755); err != nil {
			return fmt.Errorf("failed to write hook: %w", err)
		}

		fmt.Printf("%s Installed pre-commit hook at %s\n", color.GreenString("✓"), hookPath)
		return nil
	},
}

var hookUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall pre-commit hook",
	RunE: func(cmd *cobra.Command, args []string) error {
		gitDir, err := findGitDir()
		if err != nil {
			return err
		}

		hookPath := filepath.Join(gitDir, "hooks", "pre-commit")
		data, err := os.ReadFile(hookPath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println(color.YellowString("No pre-commit hook found"))
				return nil
			}
			return fmt.Errorf("failed to read hook: %w", err)
		}

		if !containsMarker(string(data)) {
			fmt.Println(color.YellowString("Pre-commit hook was not installed by SentinelFlow"))
			return nil
		}

		if err := os.Remove(hookPath); err != nil {
			return fmt.Errorf("failed to remove hook: %w", err)
		}

		fmt.Printf("%s Removed pre-commit hook from %s\n", color.GreenString("✓"), hookPath)
		return nil
	},
}

func findGitDir() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("not a git repository: run this command from within a git repo")
	}
	return filepath.Clean(strings.TrimSpace(string(output))), nil
}

func containsMarker(content string) bool {
	return len(content) > 0 && (content == hookMarker || len(content) > len(hookMarker) && content[:len(hookMarker)] == hookMarker || containsSubstring(content, hookMarker))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func init() {
	hookCmd.AddCommand(hookInstallCmd)
	hookCmd.AddCommand(hookUninstallCmd)
}
