package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

	// Make HTTP request
	apiURL := s.baseURL + "/v1/query"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Body = http.NoBody

	// For querying by version, use the query endpoint
	if version != "" {
		apiURL = fmt.Sprintf("%s/v1/querybatch", s.baseURL)
		httpReq, _ = http.NewRequestWithContext(ctx, "POST", apiURL, nil)
	}

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

		// Extract CVSS score
		for _, sev := range osv.Severity {
			if sev.Type == "CVSS_V3" {
				v.CVSSVector = sev.Score
				// Parse CVSS score (simplified)
				v.CVSS = 7.5 // Default medium
				v.Severity = "high"
			}
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
