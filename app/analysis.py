"""Motor determinista: normaliza logs, aplica reglas, correlaciona y puntúa riesgo.
Los hallazgos son SIEMPRE derivados de filas reales (Log_ID); la IA solo redacta sobre este resumen."""
import io, re, ipaddress
import pandas as pd

COLS = ["Log_ID","Timestamp","Hostname","Event_ID","User","Source_IP","Destination","Log_Source",
        "Event_Description","Process_CommandLine","Result","Severity"]
NA = "Información no disponible en el log"
SUSP = [  # regex, etiqueta, técnica MITRE, táctica, puntos
 (r"-enc\b|-encodedcommand|frombase64string","Comando ofuscado (Base64)","T1027","Defense Evasion",30),
 (r"downloadstring|invoke-webrequest|\biwr\b|certutil.*-urlcache|bitsadmin|curl .*http","Descarga de payload","T1105","Command and Control",30),
 (r"\biex\b|invoke-expression","Ejecución dinámica de código","T1059.001","Execution",25),
 (r"-nop\b|bypass|-w(indowstyle)? hidden","Evasión de controles PowerShell","T1562.001","Defense Evasion",20),
 (r"mimikatz|sekurlsa|lsass","Volcado de credenciales","T1003.001","Credential Access",45),
 (r"psexec|wmic.*process call|winrs|schtasks.*/s ","Ejecución remota / mov. lateral","T1021.002","Lateral Movement",40),
 (r"net user .*/add|net localgroup administrators","Creación/escalada de cuenta","T1136.001","Persistence",40),
]

def load(name: str, raw: bytes) -> pd.DataFrame:
    df = pd.read_csv(io.BytesIO(raw), dtype=str, keep_default_na=False) if name.lower().endswith(".csv") \
        else pd.read_excel(io.BytesIO(raw), dtype=str).fillna("")
    norm = lambda s: re.sub(r"[^a-z0-9]", "", s.lower())
    m = {norm(c): c for c in COLS}
    df = df.rename(columns={c: m[norm(c)] for c in df.columns if norm(c) in m})
    for c in COLS:
        if c not in df: df[c] = ""
    df = df[COLS].apply(lambda s: s.str.strip())
    df["_ts"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    blank = df["Log_ID"] == ""
    df.loc[blank, "Log_ID"] = ["ROW-%d" % (i + 2) for i in df.index[blank]]
    return df.drop_duplicates("Log_ID").reset_index(drop=True)

def is_internal(ip):
    try: return ipaddress.ip_address(ip).is_private
    except ValueError: return None

def is_fail(r): return bool(re.search(r"fail|denied|4625|invalid|blocked", f"{r.Result} {r.Event_ID}", re.I))
def is_ok(r): return bool(re.search(r"succe|allow|4624", f"{r.Result} {r.Event_ID}", re.I)) and not is_fail(r)

def burst(ts, minutes, n):
    ts = sorted(ts)
    return any(ts[i + n - 1] - ts[i] <= pd.Timedelta(minutes=minutes) for i in range(len(ts) - n + 1))

def level(score): return "Crítico" if score >= 80 else "Alto" if score >= 60 else "Medio" if score >= 35 else "Bajo"

def analyze(df: pd.DataFrame) -> dict:
    F = []
    failmask = df.apply(is_fail, axis=1) if len(df) else pd.Series([], dtype=bool)
    okmask = df.apply(is_ok, axis=1) if len(df) else pd.Series([], dtype=bool)
    fails = df[failmask]
    def add(rule, title, mitre, tactic, pts, ev, ents, steps):
        ext = [e for e in ents.get("ip", []) if is_internal(e) is False]
        score = min(100, pts + (15 if ext else 0))
        F.append(dict(id=f"F-{len(F)+1:02d}", rule=rule, title=title, mitre=mitre, tactic=tactic, score=score,
                      risk=level(score), evidence=list(ev), entities=ents, reasoning=steps))
    for ip, g in fails[fails.Source_IP != ""].groupby("Source_IP"):
        ts = g._ts.dropna(); ext = is_internal(ip)
        if len(ts) >= 5 and burst(ts, 10, 5):
            users = sorted(set(g.User)); hosts = sorted(set(g.Hostname))
            spray = len(users) >= 5
            add("AUTH-001", f"{'Password spraying' if spray else 'Fuerza bruta'} desde {ip}", "T1110.003" if spray else "T1110.001",
                "Credential Access", 55 + min(len(g), 20), g.Log_ID, dict(ip=[ip], user=users, host=hosts),
                [f"1) Origen {ip}: {'interna' if ext else 'externa' if ext is False else 'no clasificable'}.",
                 f"2) {len(g)} fallos contra {len(users)} usuario(s); ≥5 en ≤10 min => anomalía de volumen.",
                 "3) Sin ofuscación aplicable. 4) Riesgo por volumen + exposición del origen."])
            oks = df[(df.Source_IP == ip) & okmask & (df._ts >= ts.min())]
            for _, o in oks.iterrows():
                add("AUTH-002", f"Inicio de sesión exitoso tras {len(g)} fallos ({ip} → {o.User}@{o.Hostname})", "T1078", "Initial Access",
                    80, list(g.Log_ID.head(5)) + [o.Log_ID], dict(ip=[ip], user=[o.User], host=[o.Hostname]),
                    [f"1) Éxito de {o.User} desde {ip} posterior a la ráfaga de fallos.", "2) Patrón consistente con credencial adivinada.",
                     "3) Requiere validar si el usuario reconoce la sesión."])
    for _, r in df[df.Process_CommandLine != ""].iterrows():
        hits = [s for s in SUSP if re.search(s[0], r.Process_CommandLine, re.I)]
        if hits:
            add("EXEC-001", f"{' + '.join(h[1] for h in hits)} en {r.Hostname}", hits[0][2], hits[0][3],
                min(95, max(h[4] for h in hits) + 15 * (len(hits) - 1) + 25), [r.Log_ID],
                dict(ip=[r.Source_IP] if r.Source_IP else [], user=[r.User], host=[r.Hostname]),
                ["1) Se inspecciona Process_CommandLine sin ejecutarlo ni decodificarlo.",
                 f"2) Indicadores: {', '.join(h[1] for h in hits)}.", "3) Ofuscación/descarga => alta probabilidad de abuso."])
    for u, g in df[okmask & (df.User != "")].groupby("User"):
        g = g.dropna(subset=["_ts"]).sort_values("_ts")
        for i in range(len(g)):
            w = g[(g._ts >= g._ts.iloc[i]) & (g._ts <= g._ts.iloc[i] + pd.Timedelta(minutes=30))]
            if w.Hostname.nunique() >= 3:
                add("LAT-001", f"Posible movimiento lateral de {u} ({w.Hostname.nunique()} hosts en 30 min)", "T1021", "Lateral Movement",
                    70, w.Log_ID, dict(ip=sorted(set(w.Source_IP) - {""}), user=[u], host=sorted(set(w.Hostname))),
                    ["1) Mismo usuario autentica en varios hosts.", "2) ≥3 hosts en 30 min no es normal para un usuario humano.",
                     "3) Verificar si es una cuenta de servicio."]); break
    parent = list(range(len(F)))
    def find(x):
        while parent[x] != x: x = parent[x]
        return x
    for i in range(len(F)):
        for j in range(i):
            if any(set(F[i]["entities"][k]) & set(F[j]["entities"][k]) for k in ("ip", "user", "host")): parent[find(i)] = find(j)
    groups = {}
    for i, f in enumerate(F): groups.setdefault(find(i), []).append(f)
    inc = []
    for n, fs in enumerate(sorted(groups.values(), key=lambda x: -max(f["score"] for f in x)), 1):
        tactics = sorted({f["tactic"] for f in fs}); sc = min(100, max(f["score"] for f in fs) + 5 * (len(tactics) - 1))
        inc.append(dict(id=f"INC-{n}", score=sc, risk=level(sc), tactics=tactics, findings=[f["id"] for f in fs],
                        mitre=sorted({f["mitre"] for f in fs}), ips=sorted({x for f in fs for x in f["entities"]["ip"]}),
                        users=sorted({x for f in fs for x in f["entities"]["user"]}), hosts=sorted({x for f in fs for x in f["entities"]["host"]}),
                        evidence=sorted({e for f in fs for e in f["evidence"]})))
    return dict(findings=F, incidents=inc, metrics=metrics(df, failmask))

def metrics(df, failmask):
    d = df.dropna(subset=["_ts"])
    return dict(total=len(df), hosts=int(df.Hostname.nunique()), users=int(df.User.nunique()),
        range=[str(d._ts.min()), str(d._ts.max())] if len(d) else [NA, NA],
        timezone="Zona no indicada (timestamps sin offset)",
        by_severity=df.Severity.replace("", NA).value_counts().to_dict(),
        by_source=df.Log_Source.replace("", NA).value_counts().head(8).to_dict(),
        top_ips=df[df.Source_IP != ""].Source_IP.value_counts().head(8).to_dict(),
        failed_by_ip=df[failmask & (df.Source_IP != "")].Source_IP.value_counts().head(8).to_dict(),
        by_hour=d.groupby(d._ts.dt.strftime("%m-%d %H:00")).size().to_dict())

def llm_summary(df, result, max_rows=25):
    """Optimización de tokens: solo agregados + filas de evidencia (nunca el Excel completo)."""
    ev = sorted({e for f in result["findings"] for e in f["evidence"]})[:max_rows]
    return dict(metrics=result["metrics"], incidents=result["incidents"], findings=result["findings"],
                evidence_rows=df[df.Log_ID.isin(ev)][COLS].to_dict("records"))
