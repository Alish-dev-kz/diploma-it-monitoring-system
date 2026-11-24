"""Агент: метрикаларды жинайды, серверге жібереді, ақ тізімдегі командаларды орындайды."""
import os, sys, time, socket, platform, threading, subprocess
import psutil, requests

SERVER = os.environ.get("ITMON_SERVER", "http://127.0.0.1:8000")
ENROLL_KEY = os.environ.get("ITMON_ENROLL_KEY", "enroll-dev")
INTERVAL = int(os.environ.get("ITMON_INTERVAL", "5"))
TOKEN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".agent_token")
H = {}


def enroll():
    """Первый запуск: регистрируемся на сервере и сохраняем личный токен."""
    if os.path.exists(TOKEN_FILE):
        return open(TOKEN_FILE).read().strip()
    r = requests.post(f"{SERVER}/api/agent/enroll", json={"hostname": socket.gethostname(),
                      "os": f"{platform.system()} {platform.release()}"},
                      headers={"X-Enroll-Key": ENROLL_KEY}, timeout=10)
    r.raise_for_status()
    token = r.json()["token"]
    open(TOKEN_FILE, "w").write(token)
    return token


def cpu_temp():
    try:
        t = psutil.sensors_temperatures()
        for entries in t.values():
            if entries:
                return entries[0].current
    except Exception:
        pass
    return None


def collect():
    n = psutil.net_io_counters()
    return {"hostname": socket.gethostname(), "os": f"{platform.system()} {platform.release()}",
            "cpu": psutil.cpu_percent(interval=1), "ram": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage(os.path.abspath(os.sep)).percent, "temp": cpu_temp(),
            "net_sent": n.bytes_sent, "net_recv": n.bytes_recv}


# --- Команды (только белый список, произвольный shell не выполняется) ---
def cmd_top_processes():
    ps = sorted(psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]),
                key=lambda p: p.info["memory_percent"] or 0, reverse=True)[:8]
    return "\n".join(f"{p.info['pid']:>7}  {p.info['name'][:28]:<28} mem {p.info['memory_percent'] or 0:5.1f}%" for p in ps)


def cmd_disk_usage():
    out = []
    for p in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(p.mountpoint)
            out.append(f"{p.mountpoint:<20} {u.percent:5.1f}%  {u.used // 2**30}/{u.total // 2**30} GB")
        except Exception:
            pass
    return "\n".join(out)


def cmd_uptime():
    s = int(time.time() - psutil.boot_time())
    return f"{s // 86400} күн {s % 86400 // 3600} сағ {s % 3600 // 60} мин"


def cmd_ping_test():
    host = "8.8.8.8"
    flag = "-n" if platform.system() == "Windows" else "-c"
    try:
        # Windows console tools print in the OEM code page (cp866), not UTF-8
        enc = "oem" if platform.system() == "Windows" else None
        r = subprocess.run(["ping", flag, "2", host], capture_output=True, text=True, timeout=10,
                           encoding=enc, errors="replace")
        return (r.stdout or r.stderr)[-400:]
    except Exception as e:
        return f"қате: {e}"


COMMANDS = {"top_processes": cmd_top_processes, "disk_usage": cmd_disk_usage,
            "uptime": cmd_uptime, "ping_test": cmd_ping_test}


def command_loop():
    while True:
        try:
            for c in requests.get(f"{SERVER}/api/agent/pending", headers=H, timeout=5).json():
                fn = COMMANDS.get(c["name"])
                res = fn() if fn else "белгісіз команда"
                requests.post(f"{SERVER}/api/agent/commands/{c['id']}/result", json={"result": res}, headers=H, timeout=5)
        except Exception as e:
            print("cmd loop:", e, file=sys.stderr)
        time.sleep(2)


def main():
    while True:  # ждём, пока сервер станет доступен для регистрации
        try:
            token = enroll()
            break
        except Exception as e:
            print("enroll failed, retry in 5s:", e, file=sys.stderr)
            time.sleep(5)
    H["X-Agent-Token"] = token
    print(f"agent enrolled -> {SERVER}")
    threading.Thread(target=command_loop, daemon=True).start()
    while True:
        try:
            r = requests.post(f"{SERVER}/api/agent/metrics", json=collect(), headers=H, timeout=5)
            if r.status_code == 401:
                print("Токен кері қайтарылған немесе жарамсыз. .agent_token файлын жойып, агентті қайта іске қосыңыз.", file=sys.stderr)
            r.raise_for_status()
        except Exception as e:
            print("send failed:", e, file=sys.stderr)
        time.sleep(max(1, INTERVAL - 1))


if __name__ == "__main__":
    main()
