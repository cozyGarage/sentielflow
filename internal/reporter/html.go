package reporter

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

// HTMLFormatter formats reports as HTML
type HTMLFormatter struct{}

func (f *HTMLFormatter) Format(result *api.ScanResult) (string, error) {
	var htmlBuilder strings.Builder

	// HTML header with CSS
	htmlBuilder.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelFlow Security Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; background: #f5f7fa; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .header p { opacity: 0.9; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; background: #f8f9fa; }
        .summary-card { background: white; padding: 20px; border-radius: 6px; border-left: 4px solid #667eea; }
        .summary-card h3 { color: #666; font-size: 14px; margin-bottom: 8px; font-weight: 500; }
        .summary-card .value { font-size: 32px; font-weight: bold; color: #333; }
        .severity-badges { padding: 20px 30px; display: flex; gap: 15px; flex-wrap: wrap; }
        .badge { padding: 8px 16px; border-radius: 20px; font-weight: 600; font-size: 14px; }
        .badge-critical { background: #fee; color: #c00; }
        .badge-high { background: #fff3e0; color: #e65100; }
        .badge-medium { background: #fff8e1; color: #f57f17; }
        .badge-low { background: #e3f2fd; color: #1565c0; }
        .badge-info { background: #f5f5f5; color: #666; }
        .findings { padding: 30px; }
        .finding { background: #f8f9fa; border-left: 4px solid #ddd; padding: 20px; margin-bottom: 15px; border-radius: 4px; }
        .finding.critical { border-left-color: #c00; }
        .finding.high { border-left-color: #e65100; }
        .finding.medium { border-left-color: #f57f17; }
        .finding.low { border-left-color: #1565c0; }
        .finding-header { display: flex; justify-content: space-between; align-items: start; margin-bottom: 12px; }
        .finding-title { font-size: 18px; font-weight: 600; color: #333; }
        .finding-severity { padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; }
        .finding-meta { color: #666; font-size: 14px; margin-bottom: 12px; }
        .finding-desc { color: #444; line-height: 1.6; margin-bottom: 12px; }
        .finding-remediation { background: #e8f5e9; border-left: 3px solid #4caf50; padding: 12px; border-radius: 4px; margin-top: 12px; }
        .finding-remediation strong { color: #2e7d32; }
        .code-snippet { background: #282c34; color: #abb2bf; padding: 15px; border-radius: 4px; overflow-x: auto; font-family: 'Consolas', monospace; font-size: 13px; margin-top: 12px; }
        .footer { text-align: center; padding: 20px; color: #999; font-size: 14px; border-top: 1px solid #eee; }
        .no-findings { text-align: center; padding: 60px 30px; color: #666; }
        .no-findings svg { width: 80px; height: 80px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
`)

	// Header
	htmlBuilder.WriteString(fmt.Sprintf(`
        <div class="header">
            <h1>🛡️ SentinelFlow Security Report</h1>
            <p>Target: %s | Duration: %s</p>
        </div>
`, html.EscapeString(result.Metadata.TargetPath), result.Duration.Std().Round(time.Millisecond)))

	// Summary cards
	counts := result.CountBySeverity()
	htmlBuilder.WriteString(`
        <div class="summary">
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="value">` + fmt.Sprintf("%d", len(result.Findings)) + `</div>
            </div>
            <div class="summary-card">
                <h3>Scanners Run</h3>
                <div class="value">` + fmt.Sprintf("%d", len(result.ScannerRuns)) + `</div>
            </div>
            <div class="summary-card">
                <h3>Files Scanned</h3>
                <div class="value">` + fmt.Sprintf("%d", f.getTotalFiles(result)) + `</div>
            </div>
        </div>
`)

	// Severity badges
	htmlBuilder.WriteString(`<div class="severity-badges">`)
	if counts[api.SeverityCritical] > 0 {
		htmlBuilder.WriteString(fmt.Sprintf(`<span class="badge badge-critical">🔴 Critical: %d</span>`, counts[api.SeverityCritical]))
	}
	if counts[api.SeverityHigh] > 0 {
		htmlBuilder.WriteString(fmt.Sprintf(`<span class="badge badge-high">🟠 High: %d</span>`, counts[api.SeverityHigh]))
	}
	if counts[api.SeverityMedium] > 0 {
		htmlBuilder.WriteString(fmt.Sprintf(`<span class="badge badge-medium">🟡 Medium: %d</span>`, counts[api.SeverityMedium]))
	}
	if counts[api.SeverityLow] > 0 {
		htmlBuilder.WriteString(fmt.Sprintf(`<span class="badge badge-low">🔵 Low: %d</span>`, counts[api.SeverityLow]))
	}
	htmlBuilder.WriteString(`</div>`)

	// Findings
	htmlBuilder.WriteString(`<div class="findings">`)

	if len(result.Findings) == 0 {
		htmlBuilder.WriteString(`
            <div class="no-findings">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <h2>No Security Issues Found!</h2>
                <p>Great job! The scan did not detect any security vulnerabilities.</p>
            </div>
        `)
	} else {
		for _, severity := range []api.Severity{api.SeverityCritical, api.SeverityHigh, api.SeverityMedium, api.SeverityLow} {
			findings := result.FilterBySeverity(severity)
			if len(findings) == 0 {
				continue
			}

			for _, finding := range findings {
				htmlBuilder.WriteString(fmt.Sprintf(`<div class="finding %s">`, severity))
				htmlBuilder.WriteString(`<div class="finding-header">`)
				htmlBuilder.WriteString(fmt.Sprintf(`<div class="finding-title">%s</div>`, html.EscapeString(finding.Title)))
				htmlBuilder.WriteString(fmt.Sprintf(`<span class="finding-severity badge badge-%s">%s</span>`, severity, strings.ToUpper(string(severity))))
				htmlBuilder.WriteString(`</div>`)
				htmlBuilder.WriteString(fmt.Sprintf(`<div class="finding-meta">📁 %s:%d | 🔖 %s</div>`,
					html.EscapeString(finding.Location.File), finding.Location.StartLine, html.EscapeString(finding.Scanner)))
				htmlBuilder.WriteString(fmt.Sprintf(`<div class="finding-desc">%s</div>`, html.EscapeString(finding.Description)))

				if finding.CVE != "" {
					htmlBuilder.WriteString(fmt.Sprintf(`<div class="finding-meta">🔗 CVE: <a href="https://nvd.nist.gov/vuln/detail/%s">%s</a></div>`, finding.CVE, finding.CVE))
				}

				if finding.Location.Snippet != "" {
					htmlBuilder.WriteString(fmt.Sprintf(`<pre class="code-snippet">%s</pre>`, html.EscapeString(finding.Location.Snippet)))
				}

				if finding.Remediation != "" {
					htmlBuilder.WriteString(fmt.Sprintf(`<div class="finding-remediation"><strong>💡 Remediation:</strong> %s</div>`, html.EscapeString(finding.Remediation)))
				}

				htmlBuilder.WriteString(`</div>`)
			}
		}
	}

	htmlBuilder.WriteString(`</div>`)

	// Footer
	htmlBuilder.WriteString(fmt.Sprintf(`
        <div class="footer">
            Generated by SentinelFlow %s at %s
        </div>
    </div>
</body>
</html>
`, result.Metadata.SentinelFlowVersion, result.Metadata.EndTime.Format("2006-01-02 15:04:05")))

	return htmlBuilder.String(), nil
}

func (f *HTMLFormatter) getTotalFiles(result *api.ScanResult) int {
	total := 0
	for _, run := range result.ScannerRuns {
		total += run.FilesCount
	}
	return total
}
