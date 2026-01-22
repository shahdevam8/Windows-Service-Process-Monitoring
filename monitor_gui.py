import psutil
import win32service
import datetime
import threading
import time
import tkinter as tk
from tkinter.scrolledtext import ScrolledText

LOG_FILE = "monitor.log"
RUNNING = False

SUSPICIOUS_PARENTS = {
    "winword.exe": ["cmd.exe", "powershell.exe"],
    "excel.exe": ["cmd.exe", "powershell.exe"],
}

SUSPICIOUS_PATHS = [
    "\\temp\\",
    "\\appdata\\",
    "\\users\\public\\"
]

WHITELIST = [
    "explorer.exe",
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "wininit.exe"
]


# --------------------------------------------------
# LOGGING
# --------------------------------------------------
def log(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

    gui_log.insert(tk.END, line + "\n")
    gui_log.see(tk.END)


# --------------------------------------------------
# PROCESS MONITOR
# --------------------------------------------------
def monitor_processes():
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe"]):
        try:
            name = proc.info["name"].lower()
            ppid = proc.info["ppid"]
            parent = psutil.Process(ppid).name().lower() if ppid else "unknown"

            if parent in SUSPICIOUS_PARENTS:
                if name in SUSPICIOUS_PARENTS[parent]:
                    log(f"[ALERT] Suspicious parent-child: {parent} → {name}")

            if name not in WHITELIST:
                path = (proc.info["exe"] or "").lower()
                for bad in SUSPICIOUS_PATHS:
                    if bad in path:
                        log(f"[ALERT] Unauthorized process: {name} ({path})")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


# --------------------------------------------------
# SERVICE AUDIT
# --------------------------------------------------
def audit_services():
    scm = win32service.OpenSCManager(
        None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE
    )

    try:
        services = win32service.EnumServicesStatus(
            scm,
            win32service.SERVICE_WIN32,
            win32service.SERVICE_STATE_ALL
        )

        for service in services:
            name = service[0]

            try:
                svc = win32service.OpenService(
                    scm, name, win32service.SERVICE_QUERY_CONFIG
                )

                config = win32service.QueryServiceConfig(svc)
                path = config[3]

                if path:
                    for bad in SUSPICIOUS_PATHS:
                        if bad in path.lower():
                            log(f"[ALERT] Suspicious service path: {name} → {path}")

                win32service.CloseServiceHandle(svc)

            except Exception:
                continue

    finally:
        win32service.CloseServiceHandle(scm)


# --------------------------------------------------
# REAL-TIME LOOP
# --------------------------------------------------
def monitoring_loop():
    log("=== REAL-TIME MONITORING STARTED ===")

    while RUNNING:
        monitor_processes()
        audit_services()
        time.sleep(10)

    log("=== MONITORING STOPPED ===")


# --------------------------------------------------
# GUI CONTROLS
# --------------------------------------------------
def start_monitoring():
    global RUNNING
    if not RUNNING:
        RUNNING = True
        threading.Thread(target=monitoring_loop, daemon=True).start()


def stop_monitoring():
    global RUNNING
    RUNNING = False


# --------------------------------------------------
# GUI
# --------------------------------------------------
root = tk.Tk()
root.title("Windows Service & Process Monitoring Agent")
root.geometry("850x500")

tk.Label(root, text="Real-Time Security Monitoring Dashboard",
         font=("Segoe UI", 14, "bold")).pack(pady=10)

btn_frame = tk.Frame(root)
btn_frame.pack()

tk.Button(btn_frame, text="▶ Start Monitoring",
          width=20, command=start_monitoring).pack(side=tk.LEFT, padx=10)

tk.Button(btn_frame, text="■ Stop Monitoring",
          width=20, command=stop_monitoring).pack(side=tk.LEFT, padx=10)

gui_log = ScrolledText(root, height=22, width=100)
gui_log.pack(padx=10, pady=10)

root.mainloop()
