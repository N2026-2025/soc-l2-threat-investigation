import json
from pathlib import Path
from starlette.applications import Starlette
from starlette.responses import JSONResponse, FileResponse, Response
from starlette.routing import Route
from . import analysis, llm, pdf

ROOT = Path(__file__).resolve().parent.parent
STATE = {}

async def health(r): return JSONResponse({"status": "ok"})

async def upload(r):
    f = (await r.form()).get("file")
    if f is None or not f.filename.lower().endswith((".csv", ".xlsx")):
        return JSONResponse({"error": "Sube un archivo .csv o .xlsx"}, 400)
    try: df = analysis.load(f.filename, await f.read())
    except Exception as e: return JSONResponse({"error": f"No se pudo leer el archivo: {e}"}, 400)
    STATE.clear(); STATE.update(df=df, result=analysis.analyze(df), report=None)
    return JSONResponse({"result": STATE["result"], "preview": json.loads(df.drop(columns="_ts").head(200).to_json(orient="records"))})

async def report(r):
    if "df" not in STATE: return JSONResponse({"error": "Primero importa un archivo"}, 409)
    STATE["summary"] = analysis.llm_summary(STATE["df"], STATE["result"])
    STATE["report"] = llm.generate(STATE["summary"]); return JSONResponse(STATE["report"])

async def pdf_dl(r):
    kind = r.path_params["kind"]
    if STATE.get("report") is None or kind not in ("ejecutivo", "tecnico", "completo"): return JSONResponse({"error": "Genera el informe primero"}, 409)
    if kind == "completo":
        body = pdf.build_combined(STATE["result"], STATE["report"], STATE["summary"])
        fname = "informe_completo.pdf"
    else:
        body = pdf.build(kind, STATE["result"], STATE["report"], STATE["summary"])
        fname = f"informe_{kind}.pdf"
    return Response(body, media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})

async def sample(r): return FileResponse(ROOT / "samples" / "sample_logs.csv")

async def index(r): return FileResponse(ROOT / "static" / "index.html")

app = Starlette(routes=[Route("/", index), Route("/api/health", health), Route("/sample", sample), Route("/api/upload", upload, methods=["POST"]),
    Route("/api/report", report, methods=["POST"]), Route("/api/report/{kind}.pdf", pdf_dl)])
