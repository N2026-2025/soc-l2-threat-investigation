import io
from xml.sax.saxutils import escape as esc
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

def build(kind, result, rep, summary):
    ss = getSampleStyleSheet(); h = ParagraphStyle("h", parent=ss["Heading2"], textColor=colors.HexColor("#14213d"))
    b = ParagraphStyle("b", parent=ss["BodyText"], leading=14)
    buf = io.BytesIO(); doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40)
    P = lambda t, s=b: Paragraph(esc(t).replace("\n", "<br/>"), s)
    m = result["metrics"]; top = result["incidents"][0] if result["incidents"] else None
    S = [Paragraph("Informe " + ("ejecutivo" if kind == "ejecutivo" else "técnico") + " de investigación de incidente", ss["Title"]),
         P(f"Eventos: {m['total']} · Hosts: {m['hosts']} · Usuarios: {m['users']} · Rango: {m['range'][0]} → {m['range'][1]} · {m['timezone']} · Redacción: {rep.get('motor','local')}"), Spacer(1, 10)]
    if top: S.append(P(f"Riesgo global: {top['risk']} ({top['score']}/100)", h))
    if kind == "ejecutivo":
        S += [P("Resumen ejecutivo", h), P(rep["resumen_ejecutivo"]), P("Decisiones y recomendaciones", h)] + [P("• " + r) for r in rep["recomendaciones"]]
    else:
        S += [P("Resumen técnico", h), P(rep["resumen_tecnico"]), P("Razonamiento (CoT)", h)] + [P("• " + r) for r in rep["razonamiento"]]
        rows = [["ID", "Riesgo", "Hallazgo", "MITRE", "Evidencia (Log_ID)"]] + [[f["id"], f["risk"], Paragraph(esc(f["title"]), ss["BodyText"]), f["mitre"], Paragraph(esc(", ".join(f["evidence"][:8])), ss["BodyText"])] for f in result["findings"]]
        t = Table(rows, colWidths=[40, 50, 200, 55, 160], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14213d")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                               ("GRID", (0, 0), (-1, -1), .3, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTSIZE", (0, 0), (-1, -1), 8)]))
        S += [P("Hallazgos y evidencia", h), t, P("Recomendaciones (NIST SP 800-61)", h)] + [P("• " + r) for r in rep["recomendaciones"]]
    S += [P("Limitaciones", h)] + [P("• " + x) for x in rep["limitaciones"]]
    doc.build(S); return buf.getvalue()
