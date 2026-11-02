# SOC L2 | Threat Investigation Platform
Plataforma académica de investigación SOC Nivel 2 (Reto final · Bootcamp Analista SOC Nivel 2). Importa logs del SIEM (CSV/XLSX), detecta, correlaciona, clasifica riesgo y genera informes PDF ejecutivo y técnico en español con IA generativa. Una alerta no es un incidente confirmado: requiere validación humana.

## Las 6 funcionalidades
| # | Funcionalidad | Dónde |
|---|---|---|
| 1 | Carga de archivos | `POST /api/upload`, `analysis.load` |
| 2 | Análisis de seguridad | `analysis.analyze` (fuerza bruta/spraying, éxito tras fallos, PowerShell/descarga/credenciales/cuentas, movimiento lateral) |
| 3 | Dashboard | `static/index.html` (Chart.js) |
| 4 | Clasificación de riesgos | Crítico/Alto/Medio/Bajo + justificación (CoT) + MITRE |
| 5 | Informe técnico | `app/llm.py` (CoT, RAG MITRE/NIST, negative prompting, few-shot, JSON mode) |
| 6 | Exportación PDF | `app/pdf.py` (ReportLab) |

## Arquitectura
Navegador → Starlette (`app/main.py`) → Pandas (`analysis.py`) → LLM opcional (`llm.py`) → ReportLab. Estado en memoria; nada se guarda en disco.

## Ejecutar
```
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000   # http://127.0.0.1:8000
```
Windows: `.\run.ps1` · Linux/Mac: `./run.sh`. Opcional: `OPENROUTER_API_KEY` (recomendado) u `OPENAI_API_KEY`, y `OPENROUTER_MODEL`/`OPENAI_MODEL`.
Variables en `.env` (cargado automáticamente con python-dotenv). Sin clave: redactor local determinista.

## Columnas esperadas
`Log_ID, Timestamp, Hostname, Event_ID, User, Source_IP, Destination, Log_Source, Event_Description, Process_CommandLine, Result, Severity` (los nombres se normalizan; los faltantes quedan vacíos).

## Limitaciones
Reglas y umbrales fijos; ausencia de alertas no prueba ausencia de amenazas. Timestamps sin zona: «Zona no indicada». Sin autenticación (uso local). Los comandos de los logs nunca se ejecutan ni decodifican. Ver `docs/PROMPTS.md`, `docs/ENTREGABLES.md`, `AGENTS.md`.

## Próximos pasos
Más reglas (port scan, horario inusual), enriquecimiento TI, persistencia SQLite, migrar UI a React/Vite como el repo de referencia, gráficos en el PDF.
