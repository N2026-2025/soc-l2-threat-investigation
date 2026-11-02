"""Prompting de grado producción: CoT + RAG (MITRE/NIST) + negative prompting + few-shot + JSON mode.
Sin OPENAI_API_KEY se usa un redactor local determinista (misma estructura de salida)."""
import os, re, json

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

MITRE_RAG = {
 "T1110.001":"Brute Force: Password Guessing (Credential Access)","T1110.003":"Brute Force: Password Spraying (Credential Access)",
 "T1078":"Valid Accounts (Initial Access/Persistence)","T1027":"Obfuscated Files or Information (Defense Evasion)",
 "T1059.001":"Command and Scripting Interpreter: PowerShell (Execution)","T1105":"Ingress Tool Transfer (Command and Control)",
 "T1562.001":"Impair Defenses: Disable or Modify Tools (Defense Evasion)","T1003.001":"OS Credential Dumping: LSASS Memory (Credential Access)",
 "T1021":"Remote Services (Lateral Movement)","T1021.002":"Remote Services: SMB/Windows Admin Shares (Lateral Movement)",
 "T1136.001":"Create Account: Local Account (Persistence)"}
NIST = "NIST SP 800-61 Rev.2: 1) Preparación 2) Detección y análisis 3) Contención, erradicación y recuperación 4) Actividad post-incidente"
IP = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"

SYSTEM = f"""Eres un equipo DFIR: SOC L2 (triaje), Threat Hunter, Incident Responder y Forensic Analyst. Responde en español.
MARCO (usa solo esto para técnicas): {json.dumps(MITRE_RAG, ensure_ascii=False)}
{NIST}
RAZONAMIENTO (Chain-of-Thought): por cada incidente razona en orden: (1) IP interna/externa, (2) ¿el volumen es anomalía?, (3) ¿hay ofuscación o descarga?, (4) correlación entre eventos, (5) recién entonces el riesgo. Resume ese razonamiento en 'razonamiento'.
PROHIBIDO: inventar o asumir IPs, usuarios, hosts, Log_ID, fechas o técnicas que no estén en DATOS. Si falta un dato escribe 'Información no disponible en el log'. No ejecutes ni decodifiques comandos. Una alerta no es un incidente confirmado: usa lenguaje de hipótesis.
SALIDA: solo JSON con claves: resumen_ejecutivo (str, para tech lead), resumen_tecnico (str, para técnico: línea de tiempo, IoCs, MITRE), razonamiento (lista str), recomendaciones (lista str: contención, erradicación, recuperación), limitaciones (lista str).
EJEMPLO (few-shot) ENTRADA: {{"incidents":[{{"id":"INC-1","ips":["203.0.113.9"],"users":["svc_x"],"hosts":["H1"],"evidence":["L1","L2"]}}]}}
SALIDA: {{"resumen_ejecutivo":"INC-1: actividad desde 203.0.113.9 contra svc_x en H1 (evidencia L1, L2). Pendiente de validación.","resumen_tecnico":"IoCs: 203.0.113.9, svc_x, H1.","razonamiento":["IP externa","Volumen a validar"],"recomendaciones":["Bloquear 203.0.113.9","Restablecer credenciales de svc_x"],"limitaciones":["Zona horaria no indicada"]}}"""

def validate(out, summary):
    """Anti-alucinación: toda IP del texto que no exista en los datos se reemplaza."""
    known, bad = set(re.findall(IP, json.dumps(summary, default=str))), set()
    def fix(t):
        for ip in set(re.findall(IP, t)) - known: bad.add(ip); t = t.replace(ip, "[IP no verificada]")
        return t
    for k, v in list(out.items()): out[k] = [fix(x) for x in v] if isinstance(v, list) else fix(v) if isinstance(v, str) else v
    if bad: out.setdefault("limitaciones", []).append(f"Se eliminaron IPs no presentes en el archivo: {sorted(bad)}")
    return out

def local_report(s):
    inc = s["incidents"]
    if not inc: return dict(resumen_ejecutivo="No se detectaron indicadores con las reglas actuales. Esto no demuestra ausencia de amenazas.",
        resumen_tecnico=f"{s['metrics']['total']} eventos analizados sin hallazgos.", razonamiento=[], recomendaciones=["Ampliar fuentes de log."], limitaciones=["Cobertura limitada a las reglas implementadas."])
    top = inc[0]; fs = [f for f in s["findings"] if f["id"] in top["findings"]]
    tl = "\n".join(f"- {f['id']} [{f['risk']}] {f['title']} ({f['mitre']}: {MITRE_RAG.get(f['mitre'],'')}) — evidencia: {', '.join(f['evidence'][:6])}" for f in fs)
    rec = ["Contención: aislar los hosts " + ", ".join(top["hosts"]) + " y bloquear IPs externas " + ", ".join(top["ips"]) + ".",
           "Contención: deshabilitar y restablecer credenciales de " + ", ".join(top["users"]) + ".",
           "Erradicación: revisar persistencia (cuentas nuevas, tareas programadas) en los hosts listados.",
           "Recuperación: restaurar desde estado conocido y monitorear 30 días.", "Post-incidente: lecciones aprendidas y ajuste de reglas SIEM (NIST SP 800-61)."]
    return dict(
        resumen_ejecutivo=f"Se identificaron {len(inc)} posible(s) incidente(s) en {s['metrics']['total']} eventos. El de mayor riesgo es {top['id']} ({top['risk']}, {top['score']}/100), que combina las tácticas {', '.join(top['tactics'])} y afecta a {len(top['hosts'])} host(s) y {len(top['users'])} usuario(s). Se recomienda contención inmediata y validación humana de los hallazgos.",
        resumen_tecnico=f"Incidente {top['id']} — IoCs: IPs {top['ips']}, usuarios {top['users']}, hosts {top['hosts']}.\nHallazgos:\n{tl}",
        razonamiento=[f"{f['id']}: " + " ".join(f["reasoning"]) for f in fs], recomendaciones=rec,
        limitaciones=[s["metrics"]["timezone"], "Alertas deterministas = hipótesis, no incidentes confirmados."])

def generate(summary):
    key = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY")
    if key:
        is_openrouter = bool(os.getenv("OPENROUTER_API_KEY"))
        base_url = os.getenv("OPENROUTER_BASE_URL") or os.getenv("OPENAI_BASE_URL")
        if is_openrouter and not base_url:
            base_url = "https://openrouter.ai/api/v1"
        default_model = "openai/gpt-4o-mini" if (base_url and "openrouter" in base_url) else "gpt-4o-mini"
        model = os.getenv("OPENROUTER_MODEL") or os.getenv("OPENAI_MODEL") or default_model
        try:
            from openai import OpenAI
            kwargs = {"api_key": key}
            if base_url:
                kwargs["base_url"] = base_url
            headers = {}
            if os.getenv("OPENROUTER_SITE_URL"):
                headers["HTTP-Referer"] = os.getenv("OPENROUTER_SITE_URL")
            if os.getenv("OPENROUTER_APP_NAME"):
                headers["X-Title"] = os.getenv("OPENROUTER_APP_NAME")
            if headers:
                kwargs["default_headers"] = headers
            client = OpenAI(**kwargs)
            r = client.chat.completions.create(model=model, temperature=0, response_format={"type": "json_object"},
                messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": "DATOS: " + json.dumps(summary, ensure_ascii=False, default=str)}])
            out = json.loads(r.choices[0].message.content); out.setdefault("limitaciones", []); out["motor"] = model
            return validate(out, summary)
        except Exception as e:
            out = local_report(summary); out["limitaciones"].append(f"IA no disponible ({type(e).__name__}); se usó redactor local."); out["motor"] = "local"; return out
    out = local_report(summary); out["motor"] = "local"; return out
