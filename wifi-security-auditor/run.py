#!/usr/bin/env python3
"""
One-command launcher for the Wi-Fi Security Auditor.

    python run.py                 -> installs what is missing (first run only), starts the
                                     dashboard on a free port and opens your browser
    python run.py --no-browser    -> same, without opening a browser
    python run.py --port 8080
    python run.py scan -b demo -f pdf     -> any CLI command works too (see auditor.py -h)

Raw Wi-Fi capture (scapy / airodump backends) needs Linux + root:   sudo python3 run.py
"""
import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser

ROOT = os.path.dirname(os.path.abspath(__file__))
VENV = os.path.join(ROOT, ".venv")
STAMP = os.path.join(VENV, ".deps_ok")
CORE = ["flask>=2.2", "reportlab>=4.0"]
OPTIONAL = ["scapy>=2.5"]
IS_WIN = os.name == "nt"
if IS_WIN:
    os.system("")                      # enable ANSI colours in cmd.exe / PowerShell


def say(msg, code="96"):
    print(f"\033[{code}m{msg}\033[0m" if sys.stdout.isatty() else msg, flush=True)


def venv_python():
    return os.path.join(VENV, "Scripts", "python.exe") if IS_WIN else os.path.join(VENV, "bin", "python")


def have_core():
    try:
        import flask  # noqa: F401
        import reportlab  # noqa: F401
        return True
    except ImportError:
        return False


def pip(py, pkgs, extra=()):
    return subprocess.call([py, "-m", "pip", "install", "--disable-pip-version-check", "-q", *extra, *pkgs])


def relaunch(py):
    env = dict(os.environ, WIFIAUDIT_BOOT="1")
    sys.exit(subprocess.call([py, os.path.abspath(__file__)] + sys.argv[1:], env=env))


def bootstrap():
    if os.environ.get("WIFIAUDIT_BOOT") == "1":
        say("Could not load Flask/ReportLab even after installing. Try:  pip install flask reportlab", "91")
        sys.exit(1)
    # Already prepared a venv on an earlier run? Use it.
    if os.path.exists(venv_python()) and os.path.exists(STAMP) and os.path.abspath(sys.executable) != os.path.abspath(venv_python()):
        relaunch(venv_python())
    say("First run: installing dependencies (one-time, ~30 seconds)...")
    try:
        import venv
        if not os.path.exists(venv_python()):
            venv.create(VENV, with_pip=True)
        if pip(venv_python(), CORE) == 0:
            if pip(venv_python(), OPTIONAL) != 0:
                say("  (scapy could not be installed - raw monitor-mode scanning will be unavailable)", "93")
            open(STAMP, "w").write("ok")
            relaunch(venv_python())
    except Exception as e:                                     # venv/ensurepip missing on some Linux distros
        say(f"  virtualenv unavailable ({e}); installing for the current user instead", "93")
    for extra in (["--user"], ["--user", "--break-system-packages"]):
        if pip(sys.executable, CORE, extra) == 0:
            pip(sys.executable, OPTIONAL, extra)
            relaunch(sys.executable)
    say("Automatic install failed. Please run:  pip install flask reportlab scapy", "91")
    sys.exit(1)


def free_port(preferred):
    for p in range(preferred, preferred + 30):
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if s.connect_ex(("127.0.0.1", p)) != 0:             # nothing listening -> free
                return p
    return preferred


def open_browser_when_ready(url, port):
    for _ in range(80):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                break
        time.sleep(0.25)
    try:
        webbrowser.open(url)
    except Exception:
        pass


def main():
    if sys.version_info < (3, 8):
        say("Python 3.8 or newer is required.", "91")
        sys.exit(1)
    # If a prepared venv exists and we are not inside it, hop into it (also makes `sudo python3 run.py` work).
    if (os.path.exists(venv_python()) and os.path.exists(STAMP)
            and os.path.abspath(sys.executable) != os.path.abspath(venv_python())
            and os.environ.get("WIFIAUDIT_BOOT") != "1"):
        relaunch(venv_python())
    if not have_core():
        bootstrap()

    sys.path.insert(0, ROOT)
    args = sys.argv[1:]
    if args and not args[0].startswith("-"):                    # CLI pass-through: python run.py scan ...
        import auditor
        sys.exit(auditor.main())

    import argparse
    ap = argparse.ArgumentParser(description="Start the Wi-Fi Security Auditor dashboard")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args(args)

    import logging
    import flask.cli
    flask.cli.show_server_banner = lambda *a, **k: None      # hide the scary dev-server banner
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    from wifiaudit.engine import scheduled_report
    from wifiaudit.scanner import capabilities
    from wifiaudit.web import create_app
    import auditor

    caps = capabilities()
    port = free_port(a.port)
    url = f"http://{'127.0.0.1' if a.host in ('0.0.0.0', '') else a.host}:{port}"
    app = create_app(auditor.DB_PATH, auditor.CFG_PATH, auditor.OUT_DIR)

    def scheduler_loop():
        from wifiaudit.database import Database
        sdb = Database(auditor.DB_PATH)
        while True:
            time.sleep(60)
            try:
                scheduled_report(sdb, auditor.CFG_PATH, auditor.OUT_DIR)
            except Exception:
                pass                                        # a missed scheduled run is not fatal; it will retry next minute

    threading.Thread(target=scheduler_loop, daemon=True).start()

    say("\n  Wi-Fi Security Auditor - passive scanning, authorised use only", "1")
    say(f"  Dashboard : {url}")
    if port != a.port:
        say(f"  (port {a.port} was busy, using {port})", "93")
    ready = [b for b in ("deep", "system", "scapy", "airodump") if caps[b]["available"]]
    names = {"deep": "deep scan", "system": "OS scan", "scapy": "monitor mode (scapy)", "airodump": "airodump-ng"}
    if ready:
        say(f"  Scanning  : {', '.join(names[b] for b in ready)}")
    else:
        say(f"  Scanning  : not ready - {caps['deep']['reason']}. {caps['deep']['hint']}", "93")
    if caps["platform"] == "Linux" and not caps["root"]:
        say("  Tip       : sudo python3 run.py  gives fresher scans and unlocks monitor mode", "93")
    say("  Stop with Ctrl+C\n")
    if not a.no_browser:
        threading.Thread(target=open_browser_when_ready, args=(url, port), daemon=True).start()
    try:
        app.run(host=a.host, port=port, debug=False, threaded=True)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
