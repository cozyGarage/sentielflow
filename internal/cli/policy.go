package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage security policies",
	Long:  "Commands for managing and testing policy-as-code rules",
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available policies",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(color.CyanString("Built-in Policies:"))
		fmt.Println()

		builtinPolicies := []struct {
			Name        string
			Description string
			Severity    string
			Category    string
		}{
			{
				Name:        "no-public-s3-buckets",
				Description: "Prevents S3 buckets from being publicly accessible",
				Severity:    "critical",
				Category:    "storage",
			},
			{
				Name:        "no-privileged-containers",
				Description: "Prevents deployment of privileged containers",
				Severity:    "critical",
				Category:    "kubernetes",
			},
			{
				Name:        "require-https",
				Description: "Ensures all endpoints use HTTPS",
				Severity:    "high",
				Category:    "network",
			},
			{
				Name:        "enforce-encryption",
				Description: "Requires encryption at rest for storage",
				Severity:    "high",
				Category:    "storage",
			},
		}

		for _, p := range builtinPolicies {
			fmt.Printf("  • %s\n", color.GreenString(p.Name))
			fmt.Printf("    %s\n", p.Description)
			fmt.Printf("    Severity: %s | Category: %s\n\n", p.Severity, p.Category)
		}

		// List custom policies if they exist
		customDir := ".sentinelflow/policies"
		if _, err := os.Stat(customDir); err == nil {
			entries, _ := os.ReadDir(customDir)
			if len(entries) > 0 {
				fmt.Println(color.CyanString("Custom Policies:"))
				fmt.Println()
				for _, e := range entries {
					if filepath.Ext(e.Name()) == ".rego" {
						fmt.Printf("  • %s\n", color.YellowString(e.Name()))
					}
				}
			}
		}

		return nil
	},
}

// Note: validate and test commands are commented out pending full OPA engine implementation
/*
var policyValidateCmd = &cobra.Command{
	Use:   "validate [file]",
	Short: "Validate a policy file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		policyFile := args[0]

		content, err := os.ReadFile(policyFile)
		if err != nil {
			return fmt.Errorf("failed to read policy file: %w", err)
		}

		// TODO: Implement OPA validation
		_ = content

		fmt.Printf("%s Policy is valid: %s\n", color.GreenString("✓"), policyFile)
		return nil
	},
}

var policyTestCmd = &cobra.Command{
	Use:   "test [policy] [input-file]",
	Short: "Test a policy against sample input",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		policyFile := args[0]
		inputFile := args[1]

		// TODO: Implement OPA testing
		_ = policyFile
		_ = inputFile

		fmt.Printf("%s No policy violations found\n", color.GreenString("✓"))
		return nil
	},
}
*/

var policyGenerateCmd = &cobra.Command{
	Use:   "generate [name]",
	Short: "Generate a new policy template",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		template := fmt.Sprintf(`package sentinelflow.%s

# %s Policy
# Description: Add your policy description here
# Severity: high

default allow = false

# Define your policy rules here
allow {
    # Add conditions
    input.resource.secure == true
}

# Violations are reported when allow is false
violation[msg] {
    not allow
    msg := "Policy violation: %s check failed"
}
`, name, name, name)

		// Ensure directory exists
		policyDir := ".sentinelflow/policies"
		if err := os.MkdirAll(policyDir, 0755); err != nil {
			return fmt.Errorf("failed to create policies directory: %w", err)
		}

		policyPath := filepath.Join(policyDir, name+".rego")
		if err := os.WriteFile(policyPath, []byte(template), 0644); err != nil {
			return fmt.Errorf("failed to write policy file: %w", err)
		}

		fmt.Printf("%s Created policy template: %s\n", color.GreenString("✓"), policyPath)
		return nil
	},
}

func init() {
	policyCmd.AddCommand(policyListCmd)
	// policyCmd.AddCommand(policyValidateCmd)  // TODO: uncomment when OPA engine is fully implemented
	// policyCmd.AddCommand(policyTestCmd)      // TODO: uncomment when OPA engine is fully implemented
	policyCmd.AddCommand(policyGenerateCmd)
}
