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

	htmlBuilder.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelFlow Security Report</title>
    <style>
        :root {
            --bg: #f4f7f8;
            --surface: #ffffff;
            --ink: #0f1c24;
            --muted: #5b6b75;
            --line: #d7e0e6;
            --accent: #0e7490;
            --accent-soft: #ecfeff;
            --critical: #b91c1c;
            --critical-bg: #fef2f2;
            --high: #c2410c;
            --high-bg: #fff7ed;
            --medium: #a16207;
            --medium-bg: #fefce8;
            --low: #1d4ed8;
            --low-bg: #eff6ff;
            --ok: #166534;
            --ok-bg: #f0fdf4;
            --code-bg: #0b1220;
            --code-fg: #d1d5db;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: "IBM Plex Sans", "Segoe UI", Helvetica, Arial, sans-serif;
            background:
                radial-gradient(circle at top left, rgba(14,116,144,0.08), transparent 28%),
                linear-gradient(180deg, #eef4f6 0%, var(--bg) 100%);
            color: var(--ink);
            padding: 28px 16px 48px;
            line-height: 1.5;
        }
        .container {
            max-width: 1080px;
            margin: 0 auto;
            background: var(--surface);
            border: 1px solid var(--line);
            border-radius: 18px;
            overflow: hidden;
            box-shadow: 0 18px 40px rgba(15, 28, 36, 0.08);
        }
        .header {
            padding: 32px 36px;
            background:
                linear-gradient(135deg, rgba(14,116,144,0.12), transparent 42%),
                linear-gradient(180deg, #0b1220 0%, #132533 100%);
            color: #f8fafc;
        }
        .header .eyebrow {
            display: inline-block;
            font-size: 12px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: #67e8f9;
            margin-bottom: 10px;
            font-weight: 600;
        }
        .header h1 {
            font-family: "IBM Plex Serif", Georgia, "Times New Roman", serif;
            font-size: 32px;
            font-weight: 600;
            margin-bottom: 8px;
        }
        .header p { color: #cbd5e1; font-size: 15px; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 14px;
            padding: 24px 36px;
            background: #f8fbfc;
            border-bottom: 1px solid var(--line);
        }
        .summary-card {
            background: var(--surface);
            padding: 18px 18px 16px;
            border: 1px solid var(--line);
            border-radius: 12px;
        }
        .summary-card h3 {
            color: var(--muted);
            font-size: 12px;
            letter-spacing: 0.04em;
            text-transform: uppercase;
            margin-bottom: 8px;
            font-weight: 600;
        }
        .summary-card .value {
            font-size: 30px;
            font-weight: 700;
            color: var(--ink);
            font-variant-numeric: tabular-nums;
        }
        .severity-badges {
            padding: 18px 36px 0;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .badge {
            padding: 6px 12px;
            border-radius: 999px;
            font-weight: 650;
            font-size: 13px;
            border: 1px solid transparent;
        }
        .badge-critical { background: var(--critical-bg); color: var(--critical); border-color: #fecaca; }
        .badge-high { background: var(--high-bg); color: var(--high); border-color: #fed7aa; }
        .badge-medium { background: var(--medium-bg); color: var(--medium); border-color: #fde68a; }
        .badge-low { background: var(--low-bg); color: var(--low); border-color: #bfdbfe; }
        .badge-info { background: #f8fafc; color: var(--muted); border-color: var(--line); }
        .findings { padding: 24px 36px 36px; }
        .finding {
            background: #fbfdfe;
            border: 1px solid var(--line);
            border-left: 4px solid #94a3b8;
            padding: 18px 18px 16px;
            margin-bottom: 14px;
            border-radius: 12px;
        }
        .finding.critical { border-left-color: var(--critical); }
        .finding.high { border-left-color: var(--high); }
        .finding.medium { border-left-color: var(--medium); }
        .finding.low { border-left-color: var(--low); }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            gap: 12px;
            margin-bottom: 10px;
        }
        .finding-title { font-size: 17px; font-weight: 650; color: var(--ink); }
        .finding-severity { padding: 4px 10px; border-radius: 999px; font-size: 11px; font-weight: 700; letter-spacing: 0.04em; }
        .finding-meta { color: var(--muted); font-size: 13px; margin-bottom: 10px; }
        .finding-meta code {
            font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
            font-size: 12px;
            background: var(--accent-soft);
            color: var(--accent);
            padding: 2px 6px;
            border-radius: 6px;
        }
        .finding-desc { color: #334155; margin-bottom: 10px; }
        .finding-remediation {
            background: var(--ok-bg);
            border: 1px solid #bbf7d0;
            padding: 12px 14px;
            border-radius: 10px;
            margin-top: 12px;
            color: #14532d;
        }
        .finding-remediation strong { color: var(--ok); }
        .code-snippet {
            background: var(--code-bg);
            color: var(--code-fg);
            padding: 14px 16px;
            border-radius: 10px;
            overflow-x: auto;
            font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
            font-size: 12.5px;
            margin-top: 12px;
            line-height: 1.55;
        }
        .footer {
            text-align: center;
            padding: 18px 20px;
            color: var(--muted);
            font-size: 13px;
            border-top: 1px solid var(--line);
            background: #f8fbfc;
        }
        .no-findings { text-align: center; padding: 64px 30px; color: var(--muted); }
        .no-findings h2 { color: var(--ink); margin-bottom: 8px; }
        @media (max-width: 720px) {
            .header, .summary, .findings, .severity-badges { padding-left: 18px; padding-right: 18px; }
            .header h1 { font-size: 26px; }
            .finding-header { flex-direction: column; }
        }
    </style>
</head>
<body>
    <div class="container">
`)

	htmlBuilder.WriteString(fmt.Sprintf(`
        <div class="header">
            <div class="eyebrow">SentinelFlow</div>
            <h1>Security Report</h1>
            <p>Target: %s · Duration: %s</p>
        </div>
`, html.EscapeString(result.Metadata.TargetPath), result.Duration.Std().Round(time.Millisecond)))

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

	htmlBuilder.WriteString(`<div class="severity-badges">`)
	if counts[api.SeverityCritical] > 0 {
		htmlBuilder.WriteString(fmt.Sprintf(`<span class="badge badge-critical">Critical: %d</span>`, counts[api.SeverityCritical]))
	}
	if counts[api.SeverityHigh] > 0 {
		htmlBuilder.WriteString(fmt.Sprintf(`<span class="badge badge-high">High: %d</span>`, counts[api.SeverityHigh]))
	}
	if counts[api.SeverityMedium] > 0 {
		htmlBuilder.WriteString(fmt.Sprintf(`<span class="badge badge-medium">Medium: %d</span>`, counts[api.SeverityMedium]))
	}
	if counts[api.SeverityLow] > 0 {
		htmlBuilder.WriteString(fmt.Sprintf(`<span class="badge badge-low">Low: %d</span>`, counts[api.SeverityLow]))
	}
	htmlBuilder.WriteString(`</div>`)

	htmlBuilder.WriteString(`<div class="findings">`)

	if len(result.Findings) == 0 {
		htmlBuilder.WriteString(`
            <div class="no-findings">
                <h2>No security issues found</h2>
                <p>The scan did not detect findings at the configured thresholds.</p>
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
				htmlBuilder.WriteString(fmt.Sprintf(`<div class="finding-meta"><code>%s:%d</code> · scanner <code>%s</code>`,
					html.EscapeString(finding.Location.File), finding.Location.StartLine, html.EscapeString(finding.Scanner)))
				if finding.RuleID != "" {
					htmlBuilder.WriteString(fmt.Sprintf(` · rule <code>%s</code>`, html.EscapeString(finding.RuleID)))
				}
				htmlBuilder.WriteString(`</div>`)
				htmlBuilder.WriteString(fmt.Sprintf(`<div class="finding-desc">%s</div>`, html.EscapeString(finding.Description)))

				if finding.CVE != "" {
					htmlBuilder.WriteString(fmt.Sprintf(`<div class="finding-meta">CVE: <a href="https://nvd.nist.gov/vuln/detail/%s">%s</a></div>`, finding.CVE, finding.CVE))
				}

				if finding.Location.Snippet != "" {
					htmlBuilder.WriteString(fmt.Sprintf(`<pre class="code-snippet">%s</pre>`, html.EscapeString(finding.Location.Snippet)))
				}

				if finding.Remediation != "" {
					htmlBuilder.WriteString(fmt.Sprintf(`<div class="finding-remediation"><strong>Remediation:</strong> %s</div>`, html.EscapeString(finding.Remediation)))
				}

				htmlBuilder.WriteString(`</div>`)
			}
		}
	}

	htmlBuilder.WriteString(`</div>`)

	htmlBuilder.WriteString(fmt.Sprintf(`
        <div class="footer">
            Generated by SentinelFlow %s · %s
        </div>
    </div>
</body>
</html>
`, html.EscapeString(result.Metadata.SentinelFlowVersion), result.Metadata.EndTime.Format("2006-01-02 15:04:05")))

	return htmlBuilder.String(), nil
}

func (f *HTMLFormatter) getTotalFiles(result *api.ScanResult) int {
	total := 0
	for _, run := range result.ScannerRuns {
		total += run.FilesCount
	}
	return total
}
