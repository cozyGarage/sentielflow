package vulndb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// OSVSource implements the OSV (Open Source Vulnerabilities) API
// https://osv.dev/
type OSVSource struct {
	baseURL string
	client  *http.Client
}

// NewOSVSource creates a new OSV source
func NewOSVSource(client *http.Client) *OSVSource {
	if client == nil {
		client = http.DefaultClient
	}

	return &OSVSource{
		baseURL: "https://api.osv.dev",
		client:  client,
	}
}

func (s *OSVSource) Name() string {
	return "osv"
}

// SetBaseURL overrides the OSV API base URL (for tests).
func (s *OSVSource) SetBaseURL(url string) {
	s.baseURL = url
}

// OSVRequest is the request format for OSV API
type OSVRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version,omitempty"`
}

// OSVResponse is the response format from OSV API
type OSVResponse struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

// OSVVulnerability represents an OSV vulnerability entry
type OSVVulnerability struct {
	ID        string `json:"id"`
	Summary   string `json:"summary"`
	Details   string `json:"details"`
	Published string `json:"published"`
	Modified  string `json:"modified"`
	Affected  []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions,omitempty"`
	} `json:"affected"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity,omitempty"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references,omitempty"`
	Aliases []string `json:"aliases,omitempty"`
}

// Query queries the OSV API for vulnerabilities
func (s *OSVSource) Query(ctx context.Context, ecosystem, pkg, version string) ([]Vulnerability, error) {
	// Map ecosystem names to OSV format
	osvEcosystem := mapEcosystem(ecosystem)

	// Build request
	req := OSVRequest{}
	req.Package.Name = pkg
	req.Package.Ecosystem = osvEcosystem
	req.Version = version

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	apiURL := s.baseURL + "/v1/query"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to query OSV: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}

	var osvResp OSVResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert OSV vulnerabilities to our format
	var vulns []Vulnerability
	for _, osv := range osvResp.Vulns {
		v := Vulnerability{
			ID:        osv.ID,
			Package:   pkg,
			Ecosystem: ecosystem,
			Summary:   osv.Summary,
			Details:   osv.Details,
			Source:    "osv",
		}

		// Extract CVE from aliases
		for _, alias := range osv.Aliases {
			if len(alias) > 3 && alias[:3] == "CVE" {
				v.CVE = alias
				break
			}
		}

		// Extract CVSS score from vector or numeric score field
		for _, sev := range osv.Severity {
			if sev.Type == "CVSS_V3" || sev.Type == "CVSS_V4" {
				v.CVSSVector = sev.Score
				if score, err := strconv.ParseFloat(sev.Score, 64); err == nil {
					v.CVSS = score
					v.Severity = cvssToSeverity(score)
				} else if score := parseCVSSBaseScore(sev.Score); score > 0 {
					v.CVSS = score
					v.Severity = cvssToSeverity(score)
				} else {
					v.Severity = "medium"
				}
				break
			}
		}
		if v.Severity == "" {
			v.Severity = "medium"
		}

		// Extract references
		for _, ref := range osv.References {
			v.References = append(v.References, ref.URL)
		}

		// Extract affected ranges
		for _, affected := range osv.Affected {
			for _, r := range affected.Ranges {
				for _, event := range r.Events {
					if event.Introduced != "" || event.Fixed != "" {
						v.Affected = append(v.Affected, Range{
							Introduced: event.Introduced,
							Fixed:      event.Fixed,
						})
					}
				}
			}
		}

		vulns = append(vulns, v)
	}

	return vulns, nil
}

// mapEcosystem maps our ecosystem names to OSV ecosystem names
func mapEcosystem(ecosystem string) string {
	mapping := map[string]string{
		"npm":   "npm",
		"go":    "Go",
		"pip":   "PyPI",
		"maven": "Maven",
		"cargo": "crates.io",
	}

	if mapped, ok := mapping[ecosystem]; ok {
		return mapped
	}
	return ecosystem
}

func cvssToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "info"
	}
}

func parseCVSSBaseScore(vector string) float64 {
	// CVSS vector format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
	parts := strings.Split(vector, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, "CVSS:") {
			continue
		}
		// Cannot derive exact score without full calculator; return 0 to use default
		_ = part
	}
	return 0
}
