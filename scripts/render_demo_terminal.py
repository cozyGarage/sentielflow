#!/usr/bin/env python3
from pathlib import Path
import html
import re

raw = Path("/tmp/demo-clean.txt").read_text(errors="replace")
lines = raw.splitlines()
body = ["$ sentinelflow scan --secrets --iac --sast examples/demo-project", ""]
seen = []
wanted = {
    "k8s-privileged",
    "aws-s3-public-acl",
    "github-token",
    "user-root",
    "aws-s3-no-encryption",
    "missing-user",
    "k8s-latest-tag",
}
for line in lines:
    m = re.match(r"^\[([^\]]+)\] (.+)$", line)
    if not m:
        continue
    rid, title = m.group(1), m.group(2)
    if rid in {x[0] for x in seen}:
        continue
    if rid.startswith("no-") or rid in wanted:
        if rid.startswith("no-") or rid in {"k8s-privileged", "aws-s3-public-acl", "github-token"}:
            sev = "CRITICAL"
        elif rid == "k8s-latest-tag":
            sev = "MEDIUM"
        else:
            sev = "HIGH"
        seen.append((rid, sev, title))
    if len(seen) >= 7:
        break

for _, sev, title in seen:
    body.append(f"  ✗ [{sev:<8}] {title}")

for i, line in enumerate(lines):
    if "SUMMARY" in line:
        body += [
            "",
            "─────────────────────────────────────────────",
            "                  SUMMARY",
            "─────────────────────────────────────────────",
            "",
        ]
        for line2 in lines[i + 1 : i + 20]:
            s = line2.strip()
            if s.startswith("●") or s.startswith("Total"):
                body.append("  " + s)
            if "Total findings" in line2:
                break
        break

body += ["", "  ✗ Gate failed — findings exceed threshold"]
text = "\n".join(body)
esc = html.escape(text)
out = Path("/workspace/docs/assets/screenshots/_terminal.html")
out.write_text(
    f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
html,body{{margin:0;background:#070b16}}
.frame{{margin:20px;border:1px solid #1e293b;border-radius:14px;overflow:hidden;box-shadow:0 18px 40px rgba(0,0,0,.5)}}
.bar{{display:flex;gap:8px;align-items:center;padding:12px 16px;background:#111827;border-bottom:1px solid #1f2937}}
.dot{{width:12px;height:12px;border-radius:50%}}
.r{{background:#ff5f56}}.y{{background:#ffbd2e}}.g{{background:#27c93f}}
.title{{color:#7dd3fc;font:600 13px ui-monospace,Menlo,Consolas,monospace;margin-left:10px}}
pre{{margin:0;padding:20px 22px 26px;color:#e2e8f0;font:13.5px/1.55 ui-monospace,Menlo,Consolas,monospace;white-space:pre-wrap;background:linear-gradient(180deg,#0b1220,#070b16)}}
</style></head><body><div class="frame"><div class="bar"><div class="dot r"></div><div class="dot y"></div><div class="dot g"></div><div class="title">sentinelflow — CI/CD security gatekeeper</div></div><pre>{esc}</pre></div></body></html>"""
)
print(text)
print("wrote", out)
