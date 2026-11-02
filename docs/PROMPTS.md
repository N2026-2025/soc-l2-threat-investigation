# Ingeniería de prompts (ver `app/llm.py`)
| Técnica | Dónde | Efecto |
|---|---|---|
| Chain-of-Thought | `SYSTEM` (5 pasos: IP interna/externa → volumen → ofuscación → correlación → riesgo) | El riesgo no es arbitrario; queda en `razonamiento` |
| RAG | `MITRE_RAG` + `NIST` inyectados en el prompt | Técnicas citadas del marco, no de memoria |
| Negative prompting | bloque `PROHIBIDO` | No inventa IPs/usuarios/hosts; usa «Información no disponible en el log» |
| Few-shot | bloque `EJEMPLO` | Fija el patrón de salida |
| JSON mode | `response_format={"type":"json_object"}` | Salida parseable para dashboard/PDF |
| Token optimization | `analysis.llm_summary` | Pandas agrega; la IA solo ve resumen + ≤25 filas de evidencia |
| Anti-alucinación (código) | `llm.validate` | Reemplaza IPs ausentes del archivo |
Variables: `OPENAI_API_KEY`, `OPENAI_MODEL` (por defecto gpt-4o-mini). Sin clave: redactor local determinista.
