"""Report generators: HTML (self-contained), PDF (ReportLab), JSON, CSV.
Every SSID is attacker-controlled input, so it is always escaped."""
from __future__ import annotations

import csv
import datetime
import html
import io
import json
import os
from xml.sax.saxutils import escape as xesc

from . import __version__
from .config import fix_owner

FORMATS = ("html", "pdf", "json", "csv")
WEB = {"SECURE": "#7ed957", "VULNERABLE": "#ff9f1c", "HIGH RISK": "#ff4d4f", "ROGUE AP": "#ff2d6f"}
PRINT = {"SECURE": "#14833b", "VULNERABLE": "#c76a00", "HIGH RISK": "#c62828", "ROGUE AP": "#a3124a"}
SEV = {"critical": "#ff2d6f", "high": "#ff4d4f", "medium": "#ff9f1c", "low": "#4aa3ff", "info": "#8a97ad"}
DISCLAIMER = ("Passive assessment of broadcast Wi-Fi beacons only. Results reflect what was observable "
              "at scan time; verify findings before acting. Use only on networks you own or are "
              "authorised to assess.")


def _wps(n):
    return "-" if n.wps is None else ("Yes" if n.wps else "No")


def _sig(n):
    return "-" if n.signal is None else f"{n.signal} dBm"


# =========================================================================== #
# HTML
# =========================================================================== #
_CSS = """
:root{--bg:#0a1020;--panel:#101a30;--line:#1d2b4a;--tx:#e8eefc;--mut:#8a97ad;--ac:#4aa3ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:28px 20px 60px}
h1{margin:0 0 4px;font-size:26px}h2{font-size:17px;margin:34px 0 12px;color:var(--ac);letter-spacing:.04em;text-transform:uppercase}
.meta{color:var(--mut);margin-bottom:22px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.tile small{color:var(--mut);text-transform:uppercase;letter-spacing:.06em;font-size:11px}
.tile b{display:block;font-size:34px;line-height:1.15}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);background:#0d1630}
tr:last-child td{border-bottom:0}.scroll{overflow-x:auto}
.badge{font-weight:700;font-size:12px;letter-spacing:.04em}
.bar{display:inline-block;height:6px;border-radius:3px;vertical-align:middle;margin-right:6px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin-bottom:14px}
.card h3{margin:0 0 8px;font-size:16px}.card .sub{color:var(--mut);font-size:12px;margin-bottom:10px}
.f{border-left:3px solid;padding:4px 0 4px 12px;margin:10px 0}.f b{display:block}.f span{color:var(--mut)}
.f i{display:block;color:#bcd2f5;font-style:normal;margin-top:2px}
.chip{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11px;font-weight:700;color:#0a1020;margin-right:6px;text-transform:uppercase}
.ch{display:flex;align-items:flex-end;gap:6px;height:90px;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:10px 14px}
.ch div{flex:1;text-align:center;font-size:10px;color:var(--mut)}.ch div i{display:block;background:var(--ac);border-radius:3px 3px 0 0;margin:0 auto;width:70%}
.foot{margin-top:40px;color:var(--mut);font-size:12px;border-top:1px solid var(--line);padding-top:14px}
@media print{body{background:#fff;color:#000}}
"""


def render_html(meta, nets, summ, diff=None):
    e = html.escape
    tile = lambda label, val, color="": (
        f'<div class="tile"><small>{e(label)}</small><b style="color:{color}">{val}</b></div>')
    out = [f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Wi-Fi Audit Report</title>'
           f'<meta name="viewport" content="width=device-width,initial-scale=1"><style>{_CSS}</style></head>'
           f'<body><div class="wrap"><h1>&#128225; Wi-Fi Security Audit Report</h1>'
           f'<div class="meta">Scan #{e(str(meta.get("id", "-")))} &middot; {e(str(meta.get("ts", "")))} '
           f'&middot; backend: {e(str(meta.get("backend", "")))} '
           f'{("&middot; " + e(meta["label"])) if meta.get("label") else ""}</div>']
    out.append('<div class="tiles">' + tile("Networks found", summ["total"]) +
               tile("Secure", summ["secure"], WEB["SECURE"]) +
               tile("Vulnerable", summ["vulnerable"], WEB["VULNERABLE"]) +
               tile("Rogue APs", summ["rogue"], WEB["ROGUE AP"]) +
               tile("Avg. score", f'{summ["avg_score"]}/100') +
               tile("WPS enabled", summ["wps_enabled"]) + '</div>')

    out.append('<h2>Networks</h2><div class="scroll"><table><tr><th>SSID</th><th>BSSID</th><th>Ch</th>'
               '<th>Signal</th><th>Encryption</th><th>WPS</th><th>Score</th><th>Security level</th></tr>')
    for n in nets:
        c = WEB[n.display_level]
        out.append(f'<tr><td>{e(n.name)}</td><td>{e(n.bssid)}<br><small style="color:var(--mut)">'
                   f'{e(n.vendor)}</small></td><td>{n.channel or "-"}</td><td>{_sig(n)}</td>'
                   f'<td>{e(n.encryption)}</td><td>{_wps(n)}</td>'
                   f'<td><span class="bar" style="width:{n.score * 0.6}px;background:{c}"></span>{n.score}</td>'
                   f'<td class="badge" style="color:{c}">{e(n.display_level)}</td></tr>')
    out.append('</table></div>')

    bad = [n for n in nets if n.rogue or n.level != "SECURE" or n.rogue_score >= 30]
    if bad:
        out.append('<h2>Detailed findings</h2>')
        for n in bad:
            c = WEB[n.display_level]
            out.append(f'<div class="card"><h3>{e(n.name)} <span class="badge" style="color:{c}">'
                       f'{e(n.display_level)}</span></h3><div class="sub">{e(n.bssid)} &middot; '
                       f'{e(n.vendor or "unknown vendor")} &middot; ch {n.channel or "-"} &middot; '
                       f'{e(n.encryption)} &middot; score {n.score}</div>')
            for f in n.findings:
                if f["sev"] == "info":
                    continue
                out.append(f'<div class="f" style="border-color:{SEV[f["sev"]]}"><b><span class="chip" '
                           f'style="background:{SEV[f["sev"]]}">{f["sev"]}</span>{e(f["title"])}</b>'
                           f'<span>{e(f["detail"])}</span><i>Fix: {e(f["fix"])}</i></div>')
            out.append('</div>')

    if summ["top_fixes"]:
        out.append('<h2>Top recommendations</h2><div class="card"><ol>')
        for t in summ["top_fixes"]:
            out.append(f'<li><b>{e(t["title"])}</b> ({t["count"]}x) &mdash; {e(t["fix"])}</li>')
        out.append('</ol></div>')

    if summ["channels"]:
        mx = max(summ["channels"].values())
        out.append(f'<h2>Channel utilisation</h2><div class="ch">' + "".join(
            f'<div><i style="height:{max(6, 70 * v // mx)}px"></i>{k}</div>'
            for k, v in summ["channels"].items()) +
            f'</div><p class="meta">Least-congested 2.4 GHz channel: <b>{summ["recommended_channel"]}</b></p>')

    if diff and (diff["new"] or diff["gone"] or diff["changed"]):
        out.append('<h2>Changes since previous scan</h2><div class="card">')
        for x in diff["new"]:
            out.append(f'<p>&#10133; New: <b>{e(x.name)}</b> ({e(x.bssid)}) &mdash; {e(x.display_level)}</p>')
        for x in diff["gone"]:
            out.append(f'<p>&#10134; Gone: <b>{e(x.name)}</b> ({e(x.bssid)})</p>')
        for c in diff["changed"]:
            out.append(f'<p>&#9888; <b>{e(c["ssid"])}</b>: {e(c["field"])} {e(str(c["old"]))} &rarr; '
                       f'{e(str(c["new"]))}</p>')
        out.append('</div>')

    out.append(f'<div class="foot">{e(DISCLAIMER)}<br>Generated by Wi-Fi Security Auditor v{__version__} '
               f'on {datetime.datetime.now():%Y-%m-%d %H:%M}</div></div></body></html>')
    return "".join(out)


# =========================================================================== #
# JSON / CSV
# =========================================================================== #
def render_json(meta, nets, summ, diff=None):
    return json.dumps({"meta": meta, "summary": summ, "networks": [n.to_dict() for n in nets]},
                      indent=2, default=str)


def render_csv(meta, nets, summ, diff=None):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ssid", "bssid", "vendor", "channel", "band", "signal_dbm", "encryption", "cipher",
                "auth", "wps", "pmf", "score", "level", "rogue_score", "findings"])
    for n in nets:
        # Prefix cells that start with = + - @ to prevent spreadsheet formula injection from SSIDs.
        ss = n.ssid if not n.ssid[:1] in ("=", "+", "-", "@") else "'" + n.ssid
        w.writerow([ss, n.bssid, n.vendor, n.channel, n.band, n.signal, n.encryption, n.cipher, n.auth,
                    _wps(n), n.pmf or "", n.score, n.display_level, n.rogue_score,
                    " | ".join(f["title"] for f in n.findings if f["sev"] != "info")])
    return buf.getvalue()


# =========================================================================== #
# PDF
# =========================================================================== #
def render_pdf(path, meta, nets, summ, diff=None):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table,
                                    TableStyle)

    C = colors.HexColor
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("s", parent=body, fontSize=8, textColor=C("#5b6577"))
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=13, textColor=C("#1f4fa3"),
                        spaceBefore=14, spaceAfter=6, keepWithNext=1)
    page_w = landscape(A4)[0] - 24 * mm

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(C("#5b6577"))
        canvas.drawString(12 * mm, 8 * mm, "Wi-Fi Security Auditor - passive assessment; use only on networks you own or are authorised to test.")
        canvas.drawRightString(landscape(A4)[0] - 12 * mm, 8 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(path, pagesize=landscape(A4), leftMargin=12 * mm, rightMargin=12 * mm,
                            topMargin=12 * mm, bottomMargin=16 * mm, title="Wi-Fi Security Audit Report",
                            author="Wi-Fi Security Auditor")
    st = []

    banner = Table([[Paragraph('<font color="white" size="18"><b>Wi-Fi Security Audit Report</b></font>', body),
                     Paragraph(f'<font color="#c9d6f2">Scan #{xesc(str(meta.get("id", "-")))} | '
                               f'{xesc(str(meta.get("ts", "")))}<br/>backend: {xesc(str(meta.get("backend", "")))}'
                               f'{(" | " + xesc(meta["label"])) if meta.get("label") else ""}</font>', body)]],
                   colWidths=[page_w * 0.6, page_w * 0.4])
    banner.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), C("#0f1a30")),
                                ("TOPPADDING", (0, 0), (-1, -1), 12), ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                                ("LEFTPADDING", (0, 0), (-1, -1), 14), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    st += [banner, Spacer(1, 8)]

    tiles = [("NETWORKS FOUND", summ["total"], "#0f1a30"), ("SECURE", summ["secure"], PRINT["SECURE"]),
             ("VULNERABLE", summ["vulnerable"], PRINT["VULNERABLE"]), ("ROGUE APs", summ["rogue"], PRINT["ROGUE AP"]),
             ("AVG SCORE", f'{summ["avg_score"]}', "#1f4fa3"), ("WPS ENABLED", summ["wps_enabled"], "#1f4fa3")]
    lab = ParagraphStyle("lab", parent=body, fontSize=7, leading=9, textColor=C("#5b6577"))
    cells = []
    for a, b, col in tiles:
        val = ParagraphStyle("v", parent=body, fontSize=24, leading=30, textColor=C(col), fontName="Helvetica-Bold")
        cells.append([Paragraph(a, lab), Paragraph(str(b), val)])
    t = Table([cells], colWidths=[page_w / len(tiles)] * len(tiles))
    t.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, C("#c8d0e0")), ("INNERGRID", (0, 0), (-1, -1), 0.5, C("#c8d0e0")),
                           ("BACKGROUND", (0, 0), (-1, -1), C("#f4f7fc")), ("TOPPADDING", (0, 0), (-1, -1), 8),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    st.append(t)

    st.append(Paragraph("Discovered networks", h2))
    data = [["SSID", "BSSID / Vendor", "Ch", "Signal", "Encryption", "WPS", "Score", "Security level"]]
    style = [("BACKGROUND", (0, 0), (-1, 0), C("#0f1a30")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
             ("FONTSIZE", (0, 0), (-1, -1), 8), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
             ("GRID", (0, 0), (-1, -1), 0.25, C("#c8d0e0")), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
             ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C("#f4f7fc")])]
    for i, n in enumerate(nets, 1):
        data.append([n.name[:32], f"{n.bssid}  {n.vendor}"[:40], n.channel or "-", _sig(n), n.encryption, _wps(n),
                     n.score, n.display_level])
        style += [("TEXTCOLOR", (7, i), (7, i), C(PRINT[n.display_level])), ("FONTNAME", (7, i), (7, i), "Helvetica-Bold")]
    nt = Table(data, repeatRows=1, colWidths=[page_w * x for x in (.19, .24, .05, .09, .13, .06, .07, .17)])
    nt.setStyle(TableStyle(style))
    st.append(nt)

    bad = [n for n in nets if n.rogue or n.level != "SECURE" or n.rogue_score >= 30]
    if bad:
        st.append(Paragraph("Detailed findings", h2))
        for n in bad:
            block = [Paragraph(f'<b>{xesc(n.name)}</b> &nbsp;<font color="{PRINT[n.display_level]}"><b>'
                               f'{xesc(n.display_level)}</b></font> &nbsp;<font size="8" color="#5b6577">'
                               f'{xesc(n.bssid)} | ch {n.channel or "-"} | {xesc(n.encryption)} | score {n.score}</font>',
                               body)]
            for f in n.findings:
                if f["sev"] == "info":
                    continue
                block.append(Paragraph(
                    f'<font color="{SEV[f["sev"]]}"><b>[{f["sev"].upper()}]</b></font> <b>{xesc(f["title"])}</b> '
                    f'- {xesc(f["detail"])}<br/><font color="#1f4fa3">Fix:</font> {xesc(f["fix"])}',
                    ParagraphStyle("f", parent=body, leftIndent=12, spaceBefore=3)))
            block.append(Spacer(1, 7))
            st.append(KeepTogether(block))

    if summ["top_fixes"]:
        st.append(Paragraph("Top recommendations", h2))
        for i, tf in enumerate(summ["top_fixes"], 1):
            st.append(Paragraph(f'{i}. <b>{xesc(tf["title"])}</b> ({tf["count"]}x) - {xesc(tf["fix"])}', body))

    if summ["channels"]:
        st.append(Paragraph("Channel utilisation", h2))
        ch = summ["channels"]
        ct = Table([["Channel"] + [str(k) for k in ch], ["Networks"] + [str(v) for v in ch.values()]])
        ct.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 8), ("GRID", (0, 0), (-1, -1), 0.25, C("#c8d0e0")),
                                ("BACKGROUND", (0, 0), (0, -1), C("#f4f7fc")), ("ALIGN", (1, 0), (-1, -1), "CENTER")]))
        st += [ct, Spacer(1, 4), Paragraph(f'Least-congested 2.4 GHz channel: <b>{summ["recommended_channel"]}</b>', small)]

    if diff and (diff["new"] or diff["gone"] or diff["changed"]):
        st.append(Paragraph("Changes since previous scan", h2))
        for x in diff["new"]:
            st.append(Paragraph(f'+ New: <b>{xesc(x.name)}</b> ({xesc(x.bssid)}) - {xesc(x.display_level)}', body))
        for x in diff["gone"]:
            st.append(Paragraph(f'- Gone: <b>{xesc(x.name)}</b> ({xesc(x.bssid)})', body))
        for c in diff["changed"]:
            st.append(Paragraph(f'! <b>{xesc(c["ssid"])}</b>: {xesc(c["field"])} {xesc(str(c["old"]))} -> {xesc(str(c["new"]))}', body))

    st += [Spacer(1, 12), Paragraph(xesc(DISCLAIMER), small)]
    doc.build(st, onFirstPage=footer, onLaterPages=footer)


# =========================================================================== #
def render_remediation_pdf(path, plan, title="Remediation plan"):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer

    C = colors.HexColor
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=10, leading=14)
    small = ParagraphStyle("s", parent=body, fontSize=8, textColor=C("#5b6577"))
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontSize=20, textColor=C("#1f4fa3"))
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=12, textColor=C("#1f4fa3"), spaceBefore=12, keepWithNext=1)
    sevcol = {"critical": "#a3124a", "high": "#c62828", "medium": "#c76a00", "low": "#1f4fa3", "info": "#5b6577"}

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(C("#5b6577"))
        canvas.drawString(12 * mm, 8 * mm, "Wi-Fi Security Auditor - remediation plan")
        canvas.drawRightString(A4[0] - 12 * mm, 8 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm,
                            bottomMargin=16 * mm, title=title)
    st = [Paragraph(xesc(title), h1), Spacer(1, 6),
          Paragraph(f"{len(plan)} item" + ("s" if len(plan) != 1 else "") + ", most important first.", small), Spacer(1, 10)]
    if not plan:
        st.append(Paragraph("Nothing to fix - this scan looks clean.", body))
    for i, it in enumerate(plan, 1):
        block = [Paragraph(f'<font color="{sevcol.get(it["sev"], "#5b6577")}"><b>[{it["sev"].upper()}]</b></font> '
                           f'{i}. {xesc(it["heading"])}', h2)]
        for s_ in it["steps"]:
            block.append(Paragraph("&bull;&nbsp; " + xesc(s_), ParagraphStyle("st", parent=body, leftIndent=14, spaceAfter=3)))
        block.append(Spacer(1, 4))
        st.append(KeepTogether(block))
    st += [Spacer(1, 14), Paragraph(xesc(DISCLAIMER), small)]
    doc.build(st, onFirstPage=footer, onLaterPages=footer)


def generate(fmt, out_dir, meta, nets, summ, diff=None):
    """Write a report and return its path."""
    if fmt not in FORMATS:
        raise ValueError(f"format must be one of {FORMATS}")
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out_dir, f"wifi_audit_{meta.get('id', 'x')}_{stamp}.{fmt}")
    if fmt == "pdf":
        render_pdf(path, meta, nets, summ, diff)
    else:
        text = {"html": render_html, "json": render_json, "csv": render_csv}[fmt](meta, nets, summ, diff)
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)
    fix_owner(out_dir)
    fix_owner(path)
    return path
