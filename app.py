"""Dependency-free local web dashboard for process activity logs."""

import csv
import html
import sys
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common.paths import ACTIVITY_LOG, AI_RESULTS_LOG
from detector.ml_detector import analyze_activity
from detector.threat_score import calculate_threat_score

HOST, PORT = "127.0.0.1", 8501


def read_csv(path):
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def dashboard_html():
    activity = read_csv(ACTIVITY_LOG)
    results = {(r.get("timestamp", ""), r.get("pid", "")): r for r in read_csv(AI_RESULTS_LOG)}
    for row in activity:
        for col in ("cpu_usage", "memory_usage"):
            try:
                row[col] = float(row.get(col, 0))
            except (ValueError, TypeError):
                row[col] = 0.0
        result = results.get((row.get("timestamp", ""), row.get("pid", "")), {})
        try:
            row["threat_score"] = int(float(result.get("threat_score", "")))
        except (ValueError, TypeError):
            row["threat_score"] = calculate_threat_score(row["cpu_usage"], row["memory_usage"], row.get("status", "SAFE"))
        row["severity"] = result.get("severity", "")
        row["anomaly"] = result.get("anomaly", "false").lower() == "true"

    flagged = [r for r in activity if r.get("status") != "SAFE" or r["anomaly"]]
    statuses = Counter(r.get("status", "UNKNOWN") for r in activity)
    avg = sum(r["threat_score"] for r in activity) / max(len(activity), 1)
    total = max(len(activity), 1)
    safe_count = statuses.get("SAFE", 0)
    risk_label = "Elevated" if avg >= 60 else "Guarded" if avg >= 30 else "Low"
    risk_class = "critical" if avg >= 85 else "high" if avg >= 60 else "medium" if avg >= 30 else "low"

    status_colors = {"SAFE": "#39d98a", "SUSPICIOUS": "#ff667d", "HIGH_CPU": "#ffb454"}
    status_bars = "".join(
        f"<div class='bar-row'><span>{html.escape(name)}</span><div class='bar-track'><i style='width:{count / total * 100:.1f}%;background:{status_colors.get(name, '#78a9ff')}'></i></div><b>{count:,}</b></div>"
        for name, count in statuses.most_common(5)
    ) or "<div class='empty'>No records yet</div>"

    def table(rows):
        head = "<th>Process</th><th>PID</th><th>Last seen</th><th>CPU</th><th>Memory</th><th>Status</th><th>Risk</th>"
        cells = []
        for row in rows:
            status = html.escape(str(row.get("status", "UNKNOWN")))
            severity = row.get("severity") or ("CRITICAL" if row["threat_score"] >= 85 else "HIGH" if row["threat_score"] >= 60 else "MEDIUM" if row["threat_score"] >= 30 else "LOW")
            process_name = html.escape(str(row.get("process_name") or "Unknown"))
            cells.append(
                "<tr>"
                f"<td><strong>{process_name}</strong>{'<small class=\"subtag\">Statistical outlier</small>' if row['anomaly'] else ''}</td>"
                f"<td class='mono'>{html.escape(str(row.get('pid', '')))}</td>"
                f"<td class='muted'>{html.escape(str(row.get('timestamp', '')))}</td>"
                f"<td>{row['cpu_usage']:.1f}%</td><td>{row['memory_usage']:.1f} MB</td>"
                f"<td><span class='pill status'>{status}</span></td>"
                f"<td><span class='pill {str(severity).lower()}'>{row['threat_score']} · {html.escape(str(severity))}</span></td></tr>"
            )
        return f"<div class='table-wrap'><table><thead><tr>{head}</tr></thead><tbody>{''.join(cells) or '<tr><td colspan=7 class=empty>No records match these filters.</td></tr>'}</tbody></table></div>"

    recent = list(reversed(activity[-200:]))
    recent_flagged = sorted(flagged, key=lambda row: row["threat_score"], reverse=True)[:8]
    scanned_at = html.escape(str(activity[-1].get("timestamp", "—"))) if activity else "—"
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<meta http-equiv='refresh' content='15'><title>Process Sentinel</title><style>
:root{{--bg:#0b1018;--panel:#111a26;--panel2:#151f2d;--line:#243244;--text:#e7edf5;--muted:#8a9aaf;--mint:#5ae0ad;--blue:#7bb6ff;--red:#ff7185;--amber:#ffc46b}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(ellipse at 12% -10%,#16322e 0,transparent 33%),var(--bg);color:var(--text);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}}.shell{{max-width:1440px;margin:auto;padding:30px 34px 50px}}.topbar{{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:30px}}.brand{{display:flex;gap:13px;align-items:center}}.logo{{width:44px;height:44px;border:1px solid #2a6758;border-radius:14px;background:#123129;display:grid;place-items:center;font-size:21px}}h1{{font-size:20px;margin:0;letter-spacing:-.4px}}.subtitle{{color:var(--muted);font-size:12px;margin-top:2px}}.actions{{display:flex;align-items:center;gap:12px}}.live{{color:var(--mint);font-size:12px;display:flex;gap:7px;align-items:center}}.dot{{width:7px;height:7px;background:var(--mint);border-radius:50%;box-shadow:0 0 12px #5ae0ad88}}.button{{text-decoration:none;color:#092118;background:var(--mint);font-weight:700;padding:9px 14px;border-radius:9px}}.button.secondary{{color:var(--text);background:#1b2939;border:1px solid var(--line)}}.eyebrow{{font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);font-weight:700;margin:0 0 12px}}.overview{{display:grid;grid-template-columns:1.3fr repeat(3,1fr);gap:13px}}.card,.panel{{border:1px solid var(--line);background:linear-gradient(145deg,#141e2b,#101721);border-radius:14px}}.card{{padding:17px 19px;min-height:112px}}.risk-card{{display:flex;justify-content:space-between;align-items:center}}.risk-title{{color:var(--muted);font-size:12px}}.risk-value{{font-size:26px;font-weight:750;letter-spacing:-1px;margin-top:4px}}.risk-low{{color:var(--mint)}}.risk-medium{{color:var(--amber)}}.risk-high,.risk-critical{{color:var(--red)}}.risk-state{{font-size:11px;border:1px solid currentColor;border-radius:20px;padding:4px 8px;color:var(--mint)}}.metric{{font-size:25px;font-weight:700;letter-spacing:-.8px;margin-top:6px}}.metric-label{{font-size:12px;color:var(--muted)}}.metric-foot{{font-size:11px;color:#71839a;margin-top:7px}}.section{{margin-top:25px}}.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}.panel{{padding:18px 20px}}.panel-head{{display:flex;justify-content:space-between;align-items:center;margin-bottom:17px}}h2{{font-size:14px;margin:0;letter-spacing:-.1px}}.meta{{font-size:11px;color:var(--muted)}}.bar-row{{display:grid;grid-template-columns:100px 1fr 38px;gap:12px;align-items:center;margin:13px 0;font-size:12px;color:#b5c1d0}}.bar-track{{height:7px;background:#263243;border-radius:8px;overflow:hidden}}.bar-track i{{height:100%;display:block;border-radius:8px}}.bar-row b{{text-align:right;color:var(--text);font-size:11px}}.risk-meter{{height:9px;background:#253242;border-radius:9px;overflow:hidden;margin:14px 0 10px}}.risk-meter i{{display:block;height:100%;width:{min(max(avg, 0), 100):.1f}%;background:linear-gradient(90deg,var(--mint),var(--amber),var(--red));border-radius:9px}}.risk-scale{{display:flex;justify-content:space-between;color:#708198;font-size:10px}}.flag-head{{display:flex;justify-content:space-between;align-items:center;margin:28px 0 12px}}.flag-count{{font-size:11px;color:var(--red);background:#3b202b;padding:5px 9px;border-radius:20px}}.table-tools{{display:flex;gap:9px;align-items:center;margin:13px 0}}input,select{{background:#0c131d;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:9px 11px;font:inherit;font-size:12px;outline:none}}input:focus,select:focus{{border-color:#438c78}}input{{width:min(340px,60vw)}}.table-wrap{{overflow:auto;border:1px solid var(--line);border-radius:12px}}table{{width:100%;border-collapse:collapse;white-space:nowrap;font-size:12px}}th{{position:sticky;top:0;background:#172230;color:#94a4b8;text-transform:uppercase;letter-spacing:.7px;font-size:10px;text-align:left;padding:12px 14px}}td{{border-top:1px solid #202d3b;padding:11px 14px}}tbody tr:hover{{background:#172332}}.muted{{color:var(--muted)}}.mono{{font-family:ui-monospace,SFMono-Regular,monospace;color:#acbad0}}.pill{{border-radius:20px;padding:4px 8px;font-size:10px;font-weight:700;letter-spacing:.3px}}.pill.status{{background:#1d2b3b;color:#adbed2}}.pill.low{{background:#153529;color:#68dfaa}}.pill.medium{{background:#3c3020;color:#ffd077}}.pill.high,.pill.critical{{background:#42232d;color:#ff8c9d}}.subtag{{display:block;color:#c18bff;font-size:10px;margin-top:2px}}.empty{{color:var(--muted);padding:18px;text-align:center}}.footer{{border-top:1px solid var(--line);margin-top:26px;padding-top:15px;color:#718198;font-size:11px;display:flex;justify-content:space-between}}@media(max-width:850px){{.shell{{padding:20px 15px}}.overview{{grid-template-columns:1fr 1fr}}.risk-card{{grid-column:span 2}}.grid2{{grid-template-columns:1fr}}.topbar{{align-items:flex-start;flex-direction:column}}.actions{{width:100%;justify-content:space-between}}}}@media(max-width:480px){{.overview{{grid-template-columns:1fr 1fr;gap:8px}}.card{{padding:13px;min-height:95px}}.metric{{font-size:21px}}}}
</style></head><body><main class='shell'><header class='topbar'><div class='brand'><div class='logo'>🛡️</div><div><h1>Process Sentinel</h1><div class='subtitle'>Behavioral activity overview</div></div></div><div class='actions'><span class='live'><i class='dot'></i> LIVE · refreshes every 15s</span><a class='button secondary' href='/'>Refresh</a><a class='button' href='/analyze'>Run analysis</a></div></header>
<p class='eyebrow'>Security overview</p><div class='overview'><article class='card risk-card'><div><div class='risk-title'>Average risk score</div><div class='risk-value risk-{risk_class}'>{avg:.1f}<span style='font-size:13px;color:#8091a6'> / 100</span></div></div><span class='risk-state'>{risk_label}</span></article><article class='card'><div class='metric-label'>Process records</div><div class='metric'>{len(activity):,}</div><div class='metric-foot'>Across captured snapshots</div></article><article class='card'><div class='metric-label'>Flagged records</div><div class='metric' style='color:var(--red)'>{len(flagged):,}</div><div class='metric-foot'>Rule matches or outliers</div></article><article class='card'><div class='metric-label'>Statistical outliers</div><div class='metric' style='color:#c18bff'>{sum(r['anomaly'] for r in activity):,}</div><div class='metric-foot'>From latest analysis</div></article></div>
<section class='section grid2'><article class='panel'><div class='panel-head'><h2>Activity status</h2><span class='meta'>{len(statuses)} categories</span></div>{status_bars}</article><article class='panel'><div class='panel-head'><h2>System risk</h2><span class='meta'>{risk_label}</span></div><div class='risk-meter'><i></i></div><div class='risk-scale'><span>Low</span><span>Moderate</span><span>High</span><span>Critical</span></div><div class='metric-foot' style='margin-top:18px'>Latest snapshot: {scanned_at}</div><div class='metric-foot'>Safe records: {safe_count:,} of {len(activity):,}</div></article></section>
<section><div class='flag-head'><div><h2>Flagged activity</h2><div class='subtitle'>Highest risk records that may need review</div></div><span class='flag-count'>{len(flagged):,} flagged</span></div>{table(recent_flagged)}</section>
<section class='section'><div class='panel-head'><div><h2>Process activity</h2><div class='subtitle'>Search and filter captured process records</div></div><span class='meta'>{len(activity):,} total</span></div><div class='table-tools'><input id='search' type='search' placeholder='Search name, PID, or status…' oninput='filterRows()'><select id='statusFilter' onchange='filterRows()'><option value=''>All statuses</option>{''.join(f'<option>{html.escape(name)}</option>' for name in sorted(statuses))}<option value='OUTLIER'>Statistical outliers</option></select><span class='meta' id='shown'></span></div><div class='table-wrap'><table id='activity'><thead><tr><th>Process</th><th>PID</th><th>Last seen</th><th>CPU</th><th>Memory</th><th>Status</th><th>Risk</th></tr></thead><tbody>{''.join(f"<tr data-search='{html.escape((str(r.get('process_name',''))+' '+str(r.get('pid',''))+' '+str(r.get('status',''))).lower(), quote=True)}' data-status='{html.escape(str(r.get('status','')))}' data-outlier='{str(r['anomaly']).lower()}'><td><strong>{html.escape(str(r.get('process_name') or 'Unknown'))}</strong>{'<small class=\"subtag\">Statistical outlier</small>' if r['anomaly'] else ''}</td><td class='mono'>{html.escape(str(r.get('pid','')))}</td><td class='muted'>{html.escape(str(r.get('timestamp','')))}</td><td>{r['cpu_usage']:.1f}%</td><td>{r['memory_usage']:.1f} MB</td><td><span class='pill status'>{html.escape(str(r.get('status','UNKNOWN')))}</span></td><td><span class='pill {('critical' if r['threat_score'] >= 85 else 'high' if r['threat_score'] >= 60 else 'medium' if r['threat_score'] >= 30 else 'low')}'>{r['threat_score']} · {('CRITICAL' if r['threat_score'] >= 85 else 'HIGH' if r['threat_score'] >= 60 else 'MEDIUM' if r['threat_score'] >= 30 else 'LOW')}</span></td></tr>" for r in recent)}</tbody></table></div></section>
<footer class='footer'><span>Process Sentinel · Local analysis dashboard</span><span>Last log entry {scanned_at} · auto refresh 15 sec</span></footer></main><script>function filterRows(){{const q=document.getElementById('search').value.toLowerCase(),s=document.getElementById('statusFilter').value;let shown=0;document.querySelectorAll('#activity tbody tr').forEach(r=>{{const matchText=r.dataset.search.includes(q),matchStatus=!s||(s==='OUTLIER'?r.dataset.outlier==='true':r.dataset.status===s);r.hidden=!(matchText&&matchStatus);if(!r.hidden)shown++}});document.getElementById('shown').textContent=shown+' shown'}}filterRows();</script></body></html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if urlparse(self.path).path == "/analyze":
            try:
                analyze_activity()
                message = "Analysis complete."
            except (OSError, ValueError) as error:
                message = f"Analysis failed: {error}"
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
            print(message)
            return
        content = dashboard_html().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), DashboardHandler)
    print(f"Dashboard running at http://{HOST}:{PORT} — press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()
