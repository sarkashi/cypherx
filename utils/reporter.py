#!/usr/bin/env python3

import os
import json
import glob
from datetime import datetime
from typing import Optional

from rich.console import Console

console = Console()


class ReportGenerator:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def find_last(self, results_dir: str = "results") -> Optional[str]:
        files = glob.glob(os.path.join(results_dir, "*.json"))
        return max(files, key=os.path.getmtime) if files else None

    def _load(self, path: str) -> dict:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _html(self, data: dict, path: str) -> str:
        target = data.get("target", data.get("metadata",{}).get("target","Unknown"))
        now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rows   = ""
        for k, v in data.items():
            if k in ("tool","scan_time"):
                continue
            val = json.dumps(v, indent=2, ensure_ascii=False, default=str) if isinstance(v,(dict,list)) else str(v)
            rows += f'<tr><td class="k">{k}</td><td><pre>{val[:3000]}</pre></td></tr>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CypherX Report — {target}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;padding:24px}}
.header{{border:1px solid #30363d;border-radius:6px;padding:20px;margin-bottom:20px;background:#161b22}}
.title{{font-size:24px;color:#58a6ff;font-weight:bold}}
.meta{{color:#8b949e;font-size:13px;margin-top:6px}}
.badge{{background:#21262d;border:1px solid #30363d;border-radius:3px;padding:2px 8px;font-size:12px;margin-right:6px;color:#58a6ff}}
table{{width:100%;border-collapse:collapse}}
tr{{border-bottom:1px solid #21262d}}
tr:hover{{background:#161b22}}
.k{{color:#58a6ff;padding:10px 14px;width:160px;vertical-align:top;font-weight:bold}}
td{{padding:10px 14px;vertical-align:top}}
pre{{background:#010409;padding:8px;border-radius:4px;font-size:12px;color:#3fb950;overflow-x:auto;white-space:pre-wrap;word-break:break-all}}
.section{{border:1px solid #30363d;border-radius:6px;background:#0d1117;margin-bottom:14px;overflow:hidden}}
.footer{{text-align:center;color:#8b949e;font-size:12px;margin-top:20px}}
</style>
</head>
<body>
<div class="header">
<div class="title">CypherX Report</div>
<div class="meta">
<span class="badge">Target: {target}</span>
<span class="badge">Generated: {now}</span>
<span class="badge">CypherX v1.0.0</span>
</div>
</div>
<div class="section"><table>{rows}</table></div>
<div class="footer">CypherX v1.0.0 — github.com/CypherX/cypherx</div>
</body>
</html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    def _txt(self, data: dict, path: str) -> str:
        target = data.get("target","Unknown")
        lines  = [
            "=" * 60,
            "  CypherX Report",
            "=" * 60,
            f"  Target    : {target}",
            f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 60, "",
        ]
        for k, v in data.items():
            if k == "tool":
                continue
            val = json.dumps(v, indent=2, default=str) if isinstance(v,(dict,list)) else str(v)
            lines.append(f"[ {k.upper()} ]")
            lines.append(val[:3000])
            lines.append("")
        lines += ["=" * 60, "  CypherX v1.0.0", "=" * 60]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path

    def generate(self, source: str, fmt: str = "html") -> str:
        data     = self._load(source)
        target   = data.get("target", data.get("metadata",{}).get("target","report"))
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        name     = f"cypherx_{target.replace('/','_').replace('.','_')}_{ts}"
        out_path = os.path.join(self.output_dir, f"{name}.{fmt}")
        if fmt == "html":
            return self._html(data, out_path)
        elif fmt == "pdf":
            try:
                from reportlab.lib.pagesizes import letter
                from reportlab.pdfgen import canvas as rl_canvas
                c = rl_canvas.Canvas(out_path, pagesize=letter)
                c.setFont("Courier", 10)
                y = 750
                c.drawString(50, y, f"CypherX Report — {target}")
                y -= 20
                c.drawString(50, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                y -= 30
                for k, v in data.items():
                    if y < 50:
                        c.showPage()
                        c.setFont("Courier", 10)
                        y = 750
                    c.drawString(50, y, f"{k}: {str(v)[:100]}")
                    y -= 15
                c.save()
                return out_path
            except ImportError:
                txt_path = out_path.replace(".pdf",".txt")
                console.print("  [yellow]⚠[/yellow]  reportlab not found → saving as TXT")
                return self._txt(data, txt_path)
        else:
            return self._txt(data, out_path)
