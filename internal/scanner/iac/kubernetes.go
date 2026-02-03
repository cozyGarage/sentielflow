package iac

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
	"gopkg.in/yaml.v3"
)

// KubernetesScanner scans Kubernetes manifests for security issues
type KubernetesScanner struct {
	config *config.Config
}

// NewKubernetesScanner creates a new Kubernetes scanner
func NewKubernetesScanner(cfg *config.Config) *KubernetesScanner {
	return &KubernetesScanner{
		config: cfg,
	}
}

// IsKubernetesManifest checks if a YAML file is a Kubernetes manifest
func (s *KubernetesScanner) IsKubernetesManifest(filePath string) bool {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}

	// Quick check for Kubernetes API version
	return strings.Contains(string(content), "apiVersion:") &&
		(strings.Contains(string(content), "kind:"))
}

// ScanFile scans a Kubernetes manifest file
func (s *KubernetesScanner) ScanFile(ctx context.Context, filePath, basePath string) []api.Finding {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return []api.Finding{}
	}

	var findings []api.Finding
	relPath, _ := filepath.Rel(basePath, filePath)

	// Parse YAML
	var manifest map[string]interface{}
	if err := yaml.Unmarshal(content, &manifest); err != nil {
		return findings
	}

	// Check kind
	kind, ok := manifest["kind"].(string)
	if !ok {
		return findings
	}

	// Run checks based on resource type
	switch kind {
	case "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
		findings = append(findings, s.checkPodSecurity(manifest, relPath)...)
	case "Service":
		findings = append(findings, s.checkServiceSecurity(manifest, relPath)...)
	case "NetworkPolicy":
		findings = append(findings, s.checkNetworkPolicy(manifest, relPath)...)
	case "Role", "ClusterRole":
		findings = append(findings, s.checkRBAC(manifest, relPath)...)
	}

	return findings
}

// checkPodSecurity checks pod security settings
func (s *KubernetesScanner) checkPodSecurity(manifest map[string]interface{}, relPath string) []api.Finding {
	var findings []api.Finding

	// Get pod spec
	spec := s.getPodSpec(manifest)
	if spec == nil {
		return findings
	}

	// Check containers
	containers, ok := spec["containers"].([]interface{})
	if !ok {
		return findings
	}

	for _, cont := range containers {
		container, ok := cont.(map[string]interface{})
		if !ok {
			continue
		}

		// Check privileged containers
		if secContext, ok := container["securityContext"].(map[string]interface{}); ok {
			if privileged, ok := secContext["privileged"].(bool); ok && privileged {
				findings = append(findings, api.Finding{
					ID:          "IAC-K8S-privileged-container",
					Type:        api.FindingTypeMisconfiguration,
					Severity:    api.SeverityCritical,
					Title:       "Privileged Container Detected",
					Description: "Container is running in privileged mode, which grants all capabilities",
					Location: api.Location{
						File:    relPath,
						Snippet: "privileged: true",
					},
					Remediation: "Remove privileged flag or use specific capabilities instead",
					Scanner:     "iac",
					RuleID:      "k8s-privileged",
					Confidence:  1.0,
				})
			}

			// Check if running as root
			if runAsUser, ok := secContext["runAsUser"].(int); ok && runAsUser == 0 {
				findings = append(findings, api.Finding{
					ID:          "IAC-K8S-run-as-root",
					Type:        api.FindingTypeMisconfiguration,
					Severity:    api.SeverityHigh,
					Title:       "Container Running as Root",
					Description: "Container is configured to run as root user (UID 0)",
					Location: api.Location{
						File:    relPath,
						Snippet: "runAsUser: 0",
					},
					Remediation: "Set runAsUser to a non-root UID (e.g., 1000)",
					Scanner:     "iac",
					RuleID:      "k8s-run-as-root",
					Confidence:  1.0,
				})
			}

			// Check if runAsNonRoot is not set
			if runAsNonRoot, ok := secContext["runAsNonRoot"].(bool); !ok || !runAsNonRoot {
				findings = append(findings, api.Finding{
					ID:          "IAC-K8S-missing-run-as-non-root",
					Type:        api.FindingTypeMisconfiguration,
					Severity:    api.SeverityMedium,
					Title:       "runAsNonRoot Not Enforced",
					Description: "Container does not enforce running as non-root user",
					Location: api.Location{
						File:    relPath,
						Snippet: "securityContext",
					},
					Remediation: "Set runAsNonRoot: true in securityContext",
					Scanner:     "iac",
					RuleID:      "k8s-run-as-non-root",
					Confidence:  0.8,
				})
			}

			// Check if allowPrivilegeEscalation is enabled
			if allowPrivEsc, ok := secContext["allowPrivilegeEscalation"].(bool); ok && allowPrivEsc {
				findings = append(findings, api.Finding{
					ID:          "IAC-K8S-priv-escalation",
					Type:        api.FindingTypeMisconfiguration,
					Severity:    api.SeverityHigh,
					Title:       "Privilege Escalation Allowed",
					Description: "Container allows privilege escalation",
					Location: api.Location{
						File:    relPath,
						Snippet: "allowPrivilegeEscalation: true",
					},
					Remediation: "Set allowPrivilegeEscalation: false",
					Scanner:     "iac",
					RuleID:      "k8s-priv-escalation",
					Confidence:  1.0,
				})
			}
		}

		// Check for resource limits
		if _, hasResources := container["resources"]; !hasResources {
			findings = append(findings, api.Finding{
				ID:          "IAC-K8S-no-resource-limits",
				Type:        api.FindingTypeMisconfiguration,
				Severity:    api.SeverityLow,
				Title:       "Missing Resource Limits",
				Description: "Container does not have CPU/memory limits defined",
				Location: api.Location{
					File:    relPath,
					Snippet: fmt.Sprintf("container: %s", container["name"]),
				},
				Remediation: "Define resource requests and limits",
				Scanner:     "iac",
				RuleID:      "k8s-resource-limits",
				Confidence:  0.9,
			})
		}

		// Check for latest tag
		if image, ok := container["image"].(string); ok {
			if strings.HasSuffix(image, ":latest") || !strings.Contains(image, ":") {
				findings = append(findings, api.Finding{
					ID:          "IAC-K8S-latest-tag",
					Type:        api.FindingTypeMisconfiguration,
					Severity:    api.SeverityMedium,
					Title:       "Using 'latest' Image Tag",
					Description: "Container uses 'latest' or no tag, which can lead to unpredictable deployments",
					Location: api.Location{
						File:    relPath,
						Snippet: fmt.Sprintf("image: %s", image),
					},
					Remediation: "Use specific image tags or digests",
					Scanner:     "iac",
					RuleID:      "k8s-latest-tag",
					Confidence:  1.0,
				})
			}
		}
	}

	// Check hostNetwork
	if hostNetwork, ok := spec["hostNetwork"].(bool); ok && hostNetwork {
		findings = append(findings, api.Finding{
			ID:          "IAC-K8S-host-network",
			Type:        api.FindingTypeMisconfiguration,
			Severity:    api.SeverityHigh,
			Title:       "Host Network Enabled",
			Description: "Pod uses host network namespace",
			Location: api.Location{
				File:    relPath,
				Snippet: "hostNetwork: true",
			},
			Remediation: "Remove hostNetwork or set to false",
			Scanner:     "iac",
			RuleID:      "k8s-host-network",
			Confidence:  1.0,
		})
	}

	// Check hostPID
	if hostPID, ok := spec["hostPID"].(bool); ok && hostPID {
		findings = append(findings, api.Finding{
			ID:          "IAC-K8S-host-pid",
			Type:        api.FindingTypeMisconfiguration,
			Severity:    api.SeverityHigh,
			Title:       "Host PID Namespace Enabled",
			Description: "Pod uses host PID namespace",
			Location: api.Location{
				File:    relPath,
				Snippet: "hostPID: true",
			},
			Remediation: "Remove hostPID or set to false",
			Scanner:     "iac",
			RuleID:      "k8s-host-pid",
			Confidence:  1.0,
		})
	}

	return findings
}

// checkServiceSecurity checks service security
func (s *KubernetesScanner) checkServiceSecurity(manifest map[string]interface{}, relPath string) []api.Finding {
	var findings []api.Finding

	spec, ok := manifest["spec"].(map[string]interface{})
	if !ok {
		return findings
	}

	// Check for LoadBalancer type without appropriate controls
	if svcType, ok := spec["type"].(string); ok && svcType == "LoadBalancer" {
		findings = append(findings, api.Finding{
			ID:          "IAC-K8S-loadbalancer-service",
			Type:        api.FindingTypeMisconfiguration,
			Severity:    api.SeverityMedium,
			Title:       "LoadBalancer Service Exposes Public IP",
			Description: "Service type LoadBalancer may expose services publicly",
			Location: api.Location{
				File:    relPath,
				Snippet: "type: LoadBalancer",
			},
			Remediation: "Ensure LoadBalancer has appropriate firewall rules and consider using Ingress",
			Scanner:     "iac",
			RuleID:      "k8s-loadbalancer",
			Confidence:  0.8,
		})
	}

	return findings
}

// checkNetworkPolicy checks network policy configuration
func (s *KubernetesScanner) checkNetworkPolicy(manifest map[string]interface{}, relPath string) []api.Finding {
	// Placeholder for network policy checks
	return []api.Finding{}
}

// checkRBAC checks RBAC permissions
func (s *KubernetesScanner) checkRBAC(manifest map[string]interface{}, relPath string) []api.Finding {
	var findings []api.Finding

	rules, ok := manifest["rules"].([]interface{})
	if !ok {
		return findings
	}

	for _, r := range rules {
		rule, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		// Check for wildcard permissions
		if verbs, ok := rule["verbs"].([]interface{}); ok {
			for _, v := range verbs {
				if v == "*" {
					findings = append(findings, api.Finding{
						ID:          "IAC-K8S-rbac-wildcard-verbs",
						Type:        api.FindingTypeMisconfiguration,
						Severity:    api.SeverityHigh,
						Title:       "RBAC Wildcard Verbs",
						Description: "RBAC rule uses wildcard (*) for verbs",
						Location: api.Location{
							File:    relPath,
							Snippet: "verbs: ['*']",
						},
						Remediation: "Specify exact verbs needed instead of wildcard",
						Scanner:     "iac",
						RuleID:      "k8s-rbac-wildcard",
						Confidence:  1.0,
					})
					break
				}
			}
		}
	}

	return findings
}

// getPodSpec extracts pod spec from various resource types
func (s *KubernetesScanner) getPodSpec(manifest map[string]interface{}) map[string]interface{} {
	kind, _ := manifest["kind"].(string)

	if kind == "Pod" {
		spec, _ := manifest["spec"].(map[string]interface{})
		return spec
	}

	// For Deployment, StatefulSet, etc., get template.spec
	spec, ok := manifest["spec"].(map[string]interface{})
	if !ok {
		return nil
	}

	template, ok := spec["template"].(map[string]interface{})
	if !ok {
		return nil
	}

	podSpec, _ := template["spec"].(map[string]interface{})
	return podSpec
}
