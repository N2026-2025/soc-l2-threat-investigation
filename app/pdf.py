import io
import datetime
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from xml.sax.saxutils import escape as esc
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak, KeepTogether


# ---------------------------------------------------------------- helpers

def _styles():
    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Title"], textColor=colors.HexColor("#14213d"), fontSize=16, spaceAfter=6)
    h = ParagraphStyle("h", parent=ss["Heading2"], textColor=colors.HexColor("#14213d"), fontSize=12, spaceBefore=10, spaceAfter=4)
    b = ParagraphStyle("b", parent=ss["BodyText"], leading=14, fontSize=9.5)
    cell = ParagraphStyle("cell", parent=ss["BodyText"], leading=11, fontSize=8, textColor=colors.HexColor("#212121"))
    return ss, h1, h, b, cell


def _header_block(rep, kind_label, h1, P):
    ahora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    return [
        Paragraph(f"Informe {kind_label} de investigación de incidente SOC Nivel 2", h1),
        P(f"Fecha: {ahora} · Clasificación: Confidencial – Interno · Preparador: {rep.get('motor','local')}"),
        Spacer(1, 12),
    ]


def _wrap_list(items, sep=" · "):
    """Une una lista con saltos de línea para que no se desborde en celdas estrechas."""
    if not items:
        return "n/d"
    return "<br/>".join(esc(x) for x in items)


def _safe_p():
    """Create P lambda that handles <br/> tags correctly."""
    def P(t, s=None):
        if s is None:
            s = b
        # Escape HTML, then restore any <br/> tags, then convert \n to <br/>
        t = esc(t)
        t = t.replace("&lt;br/&gt;", "<br/>")
        t = t.replace("\n", "<br/>")
        return Paragraph(t, s)
    return P


def _incident_summary_block(result, P, h, cell):
    """Tabla con SEVERIDAD, CONFIDENCE, ESTADO, ACTIVO, ACCIÓN."""
    top = result["incidents"][0] if result["incidents"] else None
    if not top:
        return [P("No se detectaron incidentes con las reglas actuales.")]
    score = top["score"]
    conf = "Alta" if score >= 70 else "Media" if score >= 40 else "Baja"
    estado = "Activo – requiere contención" if score >= 60 else "En revisión"
    activos = _wrap_list(top.get("hosts", []))
    accion = ("Contención inmediata y escalar a IR/T3" if score >= 80
              else "Contención y validación por SOC L2")
    rows = [
        [Paragraph("SEVERIDAD", cell), Paragraph("CONFIDENCE", cell), Paragraph("ESTADO", cell),
         Paragraph("ACTIVO", cell), Paragraph("ACCIÓN", cell)],
        [Paragraph(top["risk"], cell), Paragraph(conf, cell), Paragraph(estado, cell),
         Paragraph(activos, cell), Paragraph(esc(accion), cell)],
    ]
    t = Table(rows, colWidths=[62, 66, 86, 136, 130], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), .3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("LEADING", (0, 0), (-1, -1), 10),
    ]))
    return [Paragraph("Estado del incidente", h), t, Spacer(1, 10)]


def _kpi_table(result, P, h, cell):
    m = result["metrics"]
    rows = [
        [Paragraph("Eventos", cell), Paragraph(str(m["total"]), cell)],
        [Paragraph("Hosts", cell), Paragraph(str(m["hosts"]), cell)],
        [Paragraph("Usuarios", cell), Paragraph(str(m["users"]), cell)],
        [Paragraph("Rango", cell), Paragraph(f"{m['range'][0]} → {m['range'][1]}", cell)],
        [Paragraph("Zona", cell), Paragraph(m.get("timezone", "Zona no indicada"), cell)],
    ]
    t = Table(rows, colWidths=[110, 120, 110, 120, 120], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), .3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    return [P("KPIs", h), t]


def _findings_table(result, P, cell):
    """Tabla Hallazgos y evidencia: ID, Riesgo, Hallazgo, MITRE, Evidencia (Log_ID)."""
    ss = getSampleStyleSheet()
    rows = [[Paragraph("ID", cell), Paragraph("Riesgo", cell), Paragraph("Hallazgo", cell),
             Paragraph("MITRE", cell), Paragraph("Evidencia (Log_ID)", cell)]]
    for f in result["findings"]:
        rows.append([
            Paragraph(f["id"], cell), Paragraph(f["risk"], cell),
            Paragraph(esc(f["title"]), cell),
            Paragraph(f["mitre"], cell),
            Paragraph(_wrap_list(f["evidence"][:8], sep="<br/>"), cell),
        ])
    t = Table(rows, colWidths=[38, 46, 190, 52, 154], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), .3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("LEADING", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
        ("BACKGROUND", (0, 2), (-1, -1), colors.HexColor("#f1f5f9")),
        ("BACKGROUND", (0, 3), (-1, -1), colors.HexColor("#f8fafc")),
    ]))
    return [Paragraph("Hallazgos y evidencia", ss["Heading2"]), t]


def _chart_risk_pie(result):
    risk_by_finding = {f["id"]: f["score"] for f in result["findings"]}
    if not risk_by_finding:
        return None
    labels = list(risk_by_finding.keys())
    sizes = [risk_by_finding[l] for l in labels]
    colors_risk = ["#dc2626" if v >= 80 else "#f97316" if v >= 50 else "#059669" for v in sizes]
    fig, ax = plt.subplots(figsize=(6, 6))
    ax.pie(sizes, labels=labels, colors=colors_risk, autopct="%1.1f%%", startangle=90)
    ax.set_title("Distribución de Riesgo por Hallazgo", fontsize=14, fontweight="bold")
    chart_buf = io.BytesIO()
    fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
    chart_buf.seek(0)
    img = Image(chart_buf, width=400, height=400)
    plt.close(fig)
    return img


def _chart_top_ips(result):
    top_ips = result.get("top_ips", {})
    if not top_ips:
        return None
    ip_list = list(top_ips.keys())
    ip_scores = list(top_ips.values())
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(ip_list, ip_scores, color=["#dc2626" if s >= 50 else "#f97316" if s >= 20 else "#059669" for s in ip_scores])
    ax.set_xlabel("Dirección IP")
    ax.set_ylabel("Número de Fallos")
    ax.set_title("IPs con Mayor Número de Fallos", fontsize=14, fontweight="bold")
    for bar, score in zip(bars, ip_scores):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, str(score), ha="center", va="bottom", fontsize=9)
    chart_buf = io.BytesIO()
    fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
    chart_buf.seek(0)
    img = Image(chart_buf, width=500, height=300)
    plt.close(fig)
    return img


def _chart_hourly(result):
    hourly_events = result.get("hourly_events", {})
    if not hourly_events:
        return None
    hours = list(hourly_events.keys())
    counts = list(hourly_events.values())
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.plot(hours, counts, marker='o', linewidth=2, markersize=6, color='#1e3a8a')
    ax.set_xlabel("Hora")
    ax.set_ylabel("Número de Eventos")
    ax.set_title("Eventos por Hora", fontsize=14, fontweight="bold")
    ax.grid(True, alpha=0.3)
    chart_buf = io.BytesIO()
    fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
    chart_buf.seek(0)
    img = Image(chart_buf, width=600, height=250)
    plt.close(fig)
    return img


def _chart_timeline(result):
    timeline = result.get("timeline", [])
    if not timeline:
        return None
    fig, ax = plt.subplots(figsize=(14, 5))
    for i, finding in enumerate(timeline):
        x = i * 1.5
        y = 5 - i * 1.5
        ax.text(x, y, f"F-{finding['id']}", fontsize=9, ha="center")
    ax.set_xlim(0, len(timeline) * 1.5)
    ax.set_ylim(0, 6)
    ax.axis("off")
    chart_buf = io.BytesIO()
    fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
    chart_buf.seek(0)
    img = Image(chart_buf, width=700, height=250)
    plt.close(fig)
    return img


def _chart_ce(result):
    ce_content = result.get("containment_eradication_recovery", [])
    if not ce_content:
        return None
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.axis("off")
    ax.text(0.1, 0.5, "Estrategia de Contención/Eradicación/Recuperación", fontsize=12,
            fontweight="bold", color="#1e3a8a")
    for i, item in enumerate(ce_content):
        ax.text(0.1, 0.4 - i*0.15, item, fontsize=9,
                color="#dc2626" if "Contención" in item else "#f97316" if "Eradicación" in item else "#059669")
    chart_buf = io.BytesIO()
    fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
    chart_buf.seek(0)
    img = Image(chart_buf, width=400, height=200)
    plt.close(fig)
    return img


def _chart_cot(result):
    cot_content = result.get("chain_of_thought", [])
    if not cot_content:
        return None
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.axis("off")
    for i, step in enumerate(cot_content):
        ax.text(i * 1.2, 5 - i * 0.8, f"{step['step']}\n{step['description']}", fontsize=9,
                color="#1e3a8a")
    chart_buf = io.BytesIO()
    fig.savefig(chart_buf, format='png', dpi=150, bbox_inches='tight')
    chart_buf.seek(0)
    img = Image(chart_buf, width=500, height=250)
    plt.close(fig)
    return img


# ---------------------------------------------------------------- report builders

def _section(title, flowables, h):
    """Agrupa título + contenido para que no se rompa entre páginas."""
    return KeepTogether([Paragraph(title, h)] + flowables)


def build(kind, result, rep, summary):
    ss, h1, h, b, cell = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=40, rightMargin=40,
                            topMargin=40, bottomMargin=40)
    
    # Create safe P function
    P = lambda t, s=b: Paragraph(esc(t).replace("&lt;br/&gt;", "<br/>").replace("\n", "<br/>"), s)

    m = result["metrics"]
    top = result["incidents"][0] if result["incidents"] else None

    S = []
    S += _header_block(rep, "ejecutivo" if kind == "ejecutivo" else "técnico", h1, P)
    S += _incident_summary_block(result, P, h, cell)

    if kind == "ejecutivo":
        S.append(_section("Resumen ejecutivo", [P(rep["resumen_ejecutivo"])], h))
        if top:
            scope_flow = [P(f"Hosts afectados: {_wrap_list(top.get('hosts', []), sep=' · ')}"),
                          P(f"Usuarios: {_wrap_list(top.get('users', []), sep=' · ')}"),
                          P(f"IPs: {_wrap_list(top.get('ips', []), sep=' · ')}"),
                          P(f"Tácticas MITRE: {_wrap_list(top.get('tactics', []), sep=' · ')}")]
            S.append(_section("Scope / impacto conocido", scope_flow, h))
        recs = rep.get("recomendaciones", [])[:5]
        rec_flow = [P("• " + r) for r in recs]
        S.append(_section("Acciones recomendadas", rec_flow, h))
        lims = rep.get("limitaciones", [])
        lim_flow = [P("• " + l) for l in lims]
        S.append(_section("Gaps y siguientes pasos", lim_flow, h))
        S += _kpi_table(result, P, h, cell)
        img = _chart_risk_pie(result)
        if img:
            S.append(_section("Distribución de riesgo", [img], h))
    else:
        S.append(_section("Resumen técnico", [P(rep["resumen_tecnico"])], h))
        if top:
            conf = "Alta" if top["score"] >= 70 else "Media" if top["score"] >= 40 else "Baja"
            S.append(_section("Assessment técnico y confianza",
                              [P(f"Nivel de certeza del analista: {conf} "
                                 f"(riesgo {top['risk']}, {top['score']}/100).")], h))
        S.append(_section("Timeline de eventos",
                          [P(f"Rango: {m['range'][0]} → {m['range'][1]} · {m['timezone']}")], h))
        img = _chart_timeline(result)
        if img:
            S += [img]
        S.append(Spacer(1, 6))
        hall_flow = []
        for f in result["findings"]:
            ents = f.get("entities", {})
            iocs = _wrap_list(ents.get("ip", []) or [], sep=" · ") or "n/d"
            hall_flow.append(P(f"{f['id']} [{f['risk']}] {f['title']} — MITRE {f['mitre']} "
                               f"({f['tactic']}) · IOCs: {iocs} · Evidencia: {_wrap_list(f['evidence'][:6], sep=', ')}"))
        S.append(_section("Hallazgos (IOCs, IOAs, TTPs MITRE ATT&CK)", hall_flow, h))
        S += _findings_table(result, P, cell)
        S.append(Spacer(1, 6))
        recs = rep.get("recomendaciones", [])
        rec_flow = [P("• " + r) for r in recs]
        S.append(_section("Acciones ejecutadas / recomendadas", rec_flow, h))
        lims = rep.get("limitaciones", [])
        lim_flow = [P("• " + l) for l in lims]
        S.append(_section("Gaps y preguntas pendientes", lim_flow, h))
        S.append(_section("Riesgos de continuar / no continuar",
                          [P("Continuar sin contención puede permitir movimiento lateral y exfiltración de datos. "
                             "No actuar incrementa el riesgo de compromiso persistente.")], h))
        S += _kpi_table(result, P, h, cell)
        for img in [_chart_risk_pie(result), _chart_top_ips(result), _chart_hourly(result),
                     _chart_ce(result), _chart_cot(result)]:
            if img:
                S += [img]
    doc.build(S)
    return buf.getvalue()


def build_combined(result, rep, summary):
    ss, h1, h, b, cell = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=40, rightMargin=40,
                            topMargin=40, bottomMargin=40)
    
    P = lambda t, s=b: Paragraph(esc(t).replace("&lt;br/&gt;", "<br/>").replace("\n", "<br/>"), s)

    m = result["metrics"]
    top = result["incidents"][0] if result["incidents"] else None
    S = []
    S += _header_block(rep, "ejecutivo", h1, P)
    S += _incident_summary_block(result, P, h, cell)
    S.append(_section("Resumen ejecutivo", [P(rep["resumen_ejecutivo"])], h))
    if top:
        scope_flow = [P(f"Hosts afectados: {_wrap_list(top.get('hosts', []), sep=' · ')}"),
                      P(f"Usuarios: {_wrap_list(top.get('users', []), sep=' · ')}"),
                      P(f"IPs: {_wrap_list(top.get('ips', []), sep=' · ')}"),
                      P(f"Tácticas MITRE: {_wrap_list(top.get('tactics', []), sep=' · ')}")]
        S.append(_section("Scope / impacto conocido", scope_flow, h))
    recs = rep.get("recomendaciones", [])[:5]
    rec_flow = [P("• " + r) for r in recs]
    S.append(_section("Acciones recomendadas", rec_flow, h))
    lims = rep.get("limitaciones", [])
    lim_flow = [P("• " + l) for l in lims]
    S.append(_section("Gaps y siguientes pasos", lim_flow, h))
    S.append(PageBreak())
    S += _header_block(rep, "técnico", h1, P)
    S.append(_section("Resumen técnico", [P(rep["resumen_tecnico"])], h))
    if top:
        conf = "Alta" if top["score"] >= 70 else "Media" if top["score"] >= 40 else "Baja"
        S.append(_section("Assessment técnico y confianza",
                          [P(f"Nivel de certeza del analista: {conf} "
                             f"(riesgo {top['risk']}, {top['score']}/100).")], h))
    S.append(_section("Timeline de eventos",
                      [P(f"Rango: {m['range'][0]} → {m['range'][1]} · {m['timezone']}")], h))
    img = _chart_timeline(result)
    if img:
        S += [img]
    S.append(Spacer(1, 6))
    hall_flow = []
    for f in result["findings"]:
        ents = f.get("entities", {})
        iocs = _wrap_list(ents.get("ip", []) or [], sep=" · ") or "n/d"
        hall_flow.append(P(f"{f['id']} [{f['risk']}] {f['title']} — MITRE {f['mitre']} "
                           f"({f['tactic']}) · IOCs: {iocs} · Evidencia: {_wrap_list(f['evidence'][:6], sep=', ')}"))
    S.append(_section("Hallazgos (IOCs, IOAs, TTPs MITRE ATT&CK)", hall_flow, h))
    S += _findings_table(result, P, cell)
    S.append(Spacer(1, 6))
    recs = rep.get("recomendaciones", [])
    rec_flow = [P("• " + r) for r in recs]
    S.append(_section("Acciones ejecutadas / recomendadas", rec_flow, h))
    lims = rep.get("limitaciones", [])
    lim_flow = [P("• " + l) for l in lims]
    S.append(_section("Gaps y preguntas pendientes", lim_flow, h))
    S.append(_section("Riesgos de continuar / no continuar",
                      [P("Continuar sin contención puede permitir movimiento lateral y exfiltración de datos. "
                         "No actuar incrementa el riesgo de compromiso persistente.")], h))
    S += _kpi_table(result, P, h, cell)
    for img in [_chart_risk_pie(result), _chart_top_ips(result), _chart_hourly(result),
                 _chart_ce(result), _chart_cot(result)]:
        if img:
            S += [img]
    doc.build(S)
    return buf.getvalue()
