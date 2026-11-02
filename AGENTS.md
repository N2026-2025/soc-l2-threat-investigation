# AGENTS.md
- Los hallazgos salen SOLO de `app/analysis.py` (reglas deterministas). La IA (`app/llm.py`) redacta; nunca detecta.
- Nunca enviar el Excel completo al LLM: usar `analysis.llm_summary` (agregados + filas de evidencia).
- Salida del LLM siempre JSON + `llm.validate` (borra IPs no presentes en los datos).
- Timestamps sin zona: no convertir a UTC; declarar «Zona no indicada».
- No ejecutar ni decodificar comandos de los logs. Pruebas: `python -m unittest discover -s tests -q`.
