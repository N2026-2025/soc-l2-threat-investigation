import io
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for PDF generation
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from xml.sax.saxutils import escape as esc
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.utils import ImageReader


def _header(m, rep, h, P, top):
    S = [Paragraph("Informe completo de investigación de incidente SOC Nivel 2", ss["Title"] if False else None),
          P(f"Eventos: {m['total']} · Hosts: {m['hosts']} · Usuarios: {m['users']} · Rango: {m['range'][0]} → {m['range'][1]} · {m['timezone']} · Redacción: {rep.get('motor','local')}")]
    if top:
        S.append(P(f"Riesgo global: {top['risk']} ({top['score']}/100)", h))
    return S


def build(kind, result, rep, summary):
    ss = getSampleStyleSheet(); h = ParagraphStyle("h", parent=ss["Heading2"], textColor=colors.HexColor("#14213d"))
    b = ParagraphStyle("b", parent=ss["BodyText"], leading=14)
    buf = io.BytesIO(); doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40)
    P = lambda t, s=b: Paragraph(esc(t).replace("\n", "<br/>"), s)
    
    m = result["metrics"]; top = result["incidents"][0] if result["incidents"] else None
    S = [Paragraph("Informe " + ("ejecutivo" if kind == "ejecutivo" else "técnico") + " de investigación de incidente", ss["Title"]),
          P(f"Eventos: {m['total']} · Hosts: {m['hosts']} · Usuarios: {m['users']} · Rango: {m['range'][0]} → {m['range'][1]} · {m['timezone']} · Redacción: {rep.get('motor','local')}"), Spacer(1, 10)]
    if top:
        S.append(P(f"Riesgo global: {top['risk']} ({top['score']}/100)", h))
    if kind == "ejecutivo":
        S += [P("Resumen ejecutivo", h), P(rep["resumen_ejecutivo"]), P("Decisiones y recomendaciones", h)] + [P("• " + r) for r in rep["recomendaciones"]]
    else:
        S += [P("Resumen técnico", h), P(rep["resumen_tecnico"]), P("Razonamiento (Chain-of-Thought)", h)] + [P("• " + r) for r in rep["razonamiento"]]
    
    # 1. KPI Cards
    kpi_rows = [
        ["Eventos", m["total"]],
        ["Hosts", m["hosts"]],
        ["Usuarios", m["users"]],
        ["Rango", f"{m['range'][0]} → {m['range'][1]}"],
        ["Zona", m.get("timezone", "Zona no indicada")]
    ]
    kpi_col_widths = [120, 80, 80, 100, 100]
    kpi_t = Table(kpi_rows, colWidths=kpi_col_widths, repeatRows=1)
    kpi_t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14213d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), .3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 10)
    ]))
    S += [P("KPIs", h), kpi_t]
    
# 2. Risk by Finding (Pie Chart)
    risk_by_finding = {f["id"]: f["score"] for f in result["findings"]}
    if risk_by_finding:
        labels = list(risk_by_finding.keys())
        sizes = [risk_by_finding[l] for l in labels]
        colors_risk = ["#d73027" if v >= 80 else "#f46d43" if v >= 50 else "#1a9463" for v in sizes]
        fig, ax = plt.subplots(figsize=(6, 6))
        ax.pie(sizes, labels=labels, colors=colors_risk, autopct="%1.1f%%", startangle=90)
        ax.set_title("Riesgo por Hallazgo", fontsize=14, fontweight="bold")

        # Save matplotlib figure to buffer
        chart_buf = io.BytesIO()
        fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
        chart_buf.seek(0)

        # Add chart to PDF document
        S.append(Image(chart_buf, width=400, height=400))
        plt.close(fig)
    
    # IPs with Most Failures (Bar Chart)
    top_ips = result.get("top_ips", {})
    if top_ips:
        ip_list = list(top_ips.keys())
        ip_scores = list(top_ips.values())
        fig, ax = plt.subplots(figsize=(10, 6))
        bars = ax.bar(ip_list, ip_scores, color=["#d73027" if s >= 50 else "#f46d43" if s >= 20 else "#1a9463" for s in ip_scores])
        ax.set_xlabel("IP Address")
        ax.set_ylabel("Número de Fallos")
        ax.set_title("IPs con Mayor Número de Fallos", fontsize=14, fontweight="bold")
        # Add value labels on bars
        for bar, score in zip(bars, ip_scores):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, str(score), ha="center", va="bottom", fontsize=9)

        # Save matplotlib figure to buffer
        chart_buf = io.BytesIO()
        fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
        chart_buf.seek(0)

        # Add chart to PDF document
        S.append(Image(chart_buf, width=500, height=300))
        plt.close(fig)
    
    # Events by Hour (Line Chart)
    hourly_events = result.get("hourly_events", {})
    if hourly_events:
        hours = list(hourly_events.keys())
        counts = list(hourly_events.values())
        fig, ax = plt.subplots(figsize=(12, 5))
        ax.plot(hours, counts, marker='o', linewidth=2, markersize=6, color='#14213d')
        ax.set_xlabel("Hora")
        ax.set_ylabel("Número de Eventos")
        ax.set_title("Eventos por Hora", fontsize=14, fontweight="bold")
        ax.grid(True, alpha=0.3)

        # Save matplotlib figure to buffer
        chart_buf = io.BytesIO()
        fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
        chart_buf.seek(0)

        # Add chart to PDF document
        S.append(Image(chart_buf, width=600, height=250))
        plt.close(fig)
    
    # Timeline of Findings
    timeline = result.get("timeline", [])
    if timeline:
        fig, ax = plt.subplots(figsize=(14, 5))
        for i, finding in enumerate(timeline):
            x = i * 1.5
            y = 5 - i * 1.5
            ax.text(x, y, f"F-{finding['id']}", fontsize=9, ha="center")
        ax.set_xlim(0, len(timeline) * 1.5)
        ax.set_ylim(0, 6)
        ax.axis("off")

        # Save matplotlib figure to buffer
        chart_buf = io.BytesIO()
        fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
        chart_buf.seek(0)

        # Add chart to PDF document
        S.append(Image(chart_buf, width=700, height=250))
        plt.close(fig)
    
    # Containment/Eradication/Recovery Box
    ce_content = result.get("containment_eradication_recovery", [])
    if ce_content:
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.axis("off")
        ax.text(0.1, 0.5, "Estrategia de Contención/Eradicación/Recuperación", fontsize=12, fontweight="bold", color="#14213d")
        for i, item in enumerate(ce_content):
            ax.text(0.1, 0.4 - i*0.15, item, fontsize=9, color="#d73027" if "Containment" in item else "#f46d43" if "Eradication" in item else "#1a9463")

        # Save matplotlib figure to buffer
        chart_buf = io.BytesIO()
        fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
        chart_buf.seek(0)

        # Add chart to PDF document
        S.append(Image(chart_buf, width=400, height=200))
        plt.close(fig)
    
    # Chain-of-Thought Flow
    cot_content = result.get("chain_of_thought", [])
    if cot_content:
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.axis("off")
        for i, step in enumerate(cot_content):
            ax.text(i * 1.2, 5 - i * 0.8, f"{step['step']}\n{step['description']}", fontsize=9, color="#14213d")

        # Save matplotlib figure to buffer
        chart_buf = io.BytesIO()
        fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
        chart_buf.seek(0)

        # Add chart to PDF document
        S.append(Image(chart_buf, width=500, height=250))
        plt.close(fig)
    
    doc.build(S); return buf.getvalue()


def build_combined(result, rep, summary):
    """Un solo PDF con informe ejecutivo + técnico (botón combinado)."""
    ss = getSampleStyleSheet()
    h = ParagraphStyle("h", parent=ss["Heading2"], textColor=colors.HexColor("#14213d"))
    h1 = ParagraphStyle("h1", parent=ss["Title"], textColor=colors.HexColor("#14213d"))
    b = ParagraphStyle("b", parent=ss["BodyText"], leading=14)
    buf = io.BytesIO(); doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40)
    P = lambda t, s=b: Paragraph(esc(t).replace("\n", "<br/>"), s)
    
    m = result["metrics"]; top = result["incidents"][0] if result["incidents"] else None
    S = [Paragraph("Informe completo de investigación de incidente SOC Nivel 2", h1),
          P(f"Eventos: {m['total']} · Hosts: {m['hosts']} · Usuarios: {m['users']} · Rango: {m['range'][0]} → {m['range'][1]} · {m['timezone']} · Redacción: {rep.get('motor','local')}"), Spacer(1, 12)]
    if top:
        S.append(P(f"Riesgo global: {top['risk']} ({top['score']}/100)", h))
    # Reordered for better visual flow: Executive → Chain-of-Thought → Technical Summary
    S += [
        Paragraph("1. Resumen ejecutivo", ss["Heading1"]), 
        P(rep["resumen_ejecutivo"]),
        Paragraph("2. Razonamiento (Chain-of-Thought)", ss["Heading1"]),
    ]
    # Add chain-of-thought items individually
    S.extend([P("• " + r) for r in rep["razonamiento"]])
    S += [
        Paragraph("3. Resumen técnico", ss["Heading1"]), 
        P(rep["resumen_tecnico"])
    ]
    
    # KPI Cards
    kpi_rows = [
        ["Eventos", m["total"]],
        ["Hosts", m["hosts"]],
        ["Usuarios", m["users"]],
        ["Rango", f"{m['range'][0]} → {m['range'][1]}"],
        ["Zona", m.get("timezone", "Zona no indicada")]
    ]
    kpi_col_widths = [120, 80, 80, 100, 100]
    kpi_t = Table(kpi_rows, colWidths=kpi_col_widths, repeatRows=1)
    kpi_t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14213d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), .3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 10)
    ]))
    # KPI Cards
    kpi_rows = [
        ["Eventos", m["total"]],
        ["Hosts", m["hosts"]],
        ["Usuarios", m["users"]],
        ["Rango", f"{m['range'][0]} → {m['range'][1]}"],
        ["Zona", m.get("timezone", "Zona no indicada")]
    ]
    kpi_col_widths = [120, 80, 80, 100, 100]
    kpi_t = Table(kpi_rows, colWidths=kpi_col_widths, repeatRows=1)
    kpi_t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14213d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), .3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 10)
    ]))
    S += [P("KPIs", h), kpi_t]
    
    # Risk by Finding (Pie Chart)
    risk_by_finding = {f["id"]: f["score"] for f in result["findings"]}
    if risk_by_finding:
        labels = list(risk_by_finding.keys())
        sizes = [risk_by_finding[l] for l in labels]
        colors_risk = ["#d73027" if v >= 80 else "#f46d43" if v >= 50 else "#1a9463" for v in sizes]
        fig, ax = plt.subplots(figsize=(6, 6))
        ax.pie(sizes, labels=labels, colors=colors_risk, autopct="%1.1f%%", startangle=90)
        ax.set_title("Riesgo por Hallazgo", fontsize=14, fontweight="bold")
        
        # Save matplotlib figure to buffer
        chart_buf = io.BytesIO()
        fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
        chart_buf.seek(0)
        
        # Add chart to PDF document
        S.append(Image(chart_buf, width=400, height=400))
        plt.close(fig)
    
    # IPs with Most Failures (Bar Chart)
    top_ips = result.get("top_ips", {})
    if top_ips:
        ip_list = list(top_ips.keys())
        ip_scores = list(top_ips.values())
        fig, ax = plt.subplots(figsize=(10, 6))
        bars = ax.bar(ip_list, ip_scores, color=["#d73027" if s >= 50 else "#f46d43" if s >= 20 else "#1a9463" for s in ip_scores])
        ax.set_xlabel("IP Address")
        ax.set_ylabel("Número de Fallos")
        ax.set_title("IPs con Mayor Número de Fallos", fontsize=14, fontweight="bold")
        for bar, score in zip(bars, ip_scores):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, str(score), ha="center", va="bottom", fontsize=9)
        
        # Save matplotlib figure to buffer
        chart_buf = io.BytesIO()
        fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
        chart_buf.seek(0)
        
        # Add chart to PDF document
        S.append(Image(chart_buf, width=500, height=300))
        plt.close(fig)
    
    # Events by Hour (Line Chart)
    hourly_events = result.get("hourly_events", {})
    if hourly_events:
        hours = list(hourly_events.keys())
        counts = list(hourly_events.values())
        fig, ax = plt.subplots(figsize=(12, 5))
        ax.plot(hours, counts, marker='o', linewidth=2, markersize=6, color='#14213d')
        ax.set_xlabel("Hora")
        ax.set_ylabel("Número de Eventos")
        ax.set_title("Eventos por Hora", fontsize=14, fontweight="bold")
        ax.grid(True, alpha=0.3)
        
        # Save matplotlib figure to buffer
        chart_buf = io.BytesIO()
        fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
        chart_buf.seek(0)
        
        # Add chart to PDF document
        S.append(Image(chart_buf, width=550, height=250))
        plt.close(fig)
    
    # Timeline
    timeline = result.get("timeline", [])
    if timeline:
        fig, ax = plt.subplots(figsize=(14, 5))
        for i, finding in enumerate(timeline):
            x = i * 1.5
            y = 5 - i * 1.5
            ax.text(x, y, f"F-{finding['id']}", fontsize=9, ha="center")
        ax.set_xlim(0, len(timeline) * 1.5)
        ax.set_ylim(0, 6)
        ax.axis("off")
        
        # Save matplotlib figure to buffer
        chart_buf = io.BytesIO()
        fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
        chart_buf.seek(0)
        
        # Add chart to PDF document
        S.append(Image(chart_buf, width=500, height=200))
        plt.close(fig)
    
    # Containment/Eradication/Recovery
    ce_content = result.get("containment_eradication_recovery", [])
    if ce_content:
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.axis("off")
        for i, item in enumerate(ce_content):
            ax.text(0.1, 0.5 - i*0.15, item, fontsize=9, color="#d73027" if "Containment" in item else "#f46d43" if "Eradication" in item else "#1a9463")
        
        # Save matplotlib figure to buffer
        chart_buf = io.BytesIO()
        fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
        chart_buf.seek(0)
        
        # Add chart to PDF document
        S.append(Image(chart_buf, width=400, height=200))
        plt.close(fig)
    
    # Chain-of-Thought
    cot_content = result.get("chain_of_thought", [])
    if cot_content:
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.axis("off")
        for i, step in enumerate(cot_content):
            ax.text(i * 1.2, 5 - i*0.8, f"{step['step']}\n{step['description']}", fontsize=9, color="#14213d")
        
        # Save matplotlib figure to buffer
        chart_buf = io.BytesIO()
        fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
        chart_buf.seek(0)
        
        # Add chart to PDF document
        S.append(Image(chart_buf, width=500, height=200))
        plt.close(fig)
    
    # Recommendations
    rec_content = result.get("recommendations", [])
    if rec_content:
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.axis("off")
        for i, rec in enumerate(rec_content):
            ax.text(0.1, 0.5 - i*0.15, rec, fontsize=9, color="#14213d")
        
        # Save matplotlib figure to buffer
        chart_buf = io.BytesIO()
        fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
        chart_buf.seek(0)
        
        # Add chart to PDF document
        S.append(Image(chart_buf, width=400, height=200))
        plt.close(fig)
    
    # Limitations
    lim_content = result.get("limitations", [])
    if lim_content:
        fig, ax = plt.subplots(figsize=(6, 2))
        ax.axis("off")
        for i, lim in enumerate(lim_content):
            ax.text(0.1, 0.5 - i*0.15, f"• {lim}", fontsize=8, color="#666666")
        
        # Save matplotlib figure to buffer
        chart_buf = io.BytesIO()
        fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
        chart_buf.seek(0)
        
        # Add chart to PDF document
        S.append(Image(chart_buf, width=350, height=150))
        plt.close(fig)
    
    # Hallazgos y evidencia (Findings and Evidence) - Missing section
    rows = [["ID", "Riesgo", "Hallazgo", "MITRE", "Evidencia (Log_ID)"]] + \
           [[f["id"], f["risk"], Paragraph(esc(f["title"]), ss["BodyText"]), f["mitre"], Paragraph(esc(", ".join(f["evidence"][:8])), ss["BodyText"])] for f in result["findings"]]
    t = Table(rows, colWidths=[40, 50, 200, 55, 160], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14213d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), .3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 8)]))
    S += [Paragraph("4. Hallazgos y evidencia", ss["Heading1"]), t]
    
    doc.build(S); return buf.getvalue()
