#!/usr/bin/env python3
"""
Serveur web pour visualiser les logs de monitor.log en temps réel.
Utilise Flask + Server-Sent Events (SSE) pour les notifications live.
"""

import os
import json
import logging
import time
from datetime import datetime
import queue
import threading
import urllib.error
import urllib.request
from flask import (
    Flask,
    Response,
    render_template,
    jsonify,
    request as flask_request,
    session,
    redirect,
    url_for,
)
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_WEB_SECRET_FILE = os.path.join(_BASE_DIR, ".web_secret_key")

from utils.auth import (
    AUTH_ERROR_MESSAGE,
    canonical_username_for_session,
    load_users_db,
    verify_user_password,
)


def _get_secret_key() -> str:
    env = os.environ.get("WEB_SECRET_KEY", "").strip()
    if env:
        return env
    if os.path.exists(_WEB_SECRET_FILE):
        with open(_WEB_SECRET_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    key = os.urandom(32).hex()
    with open(_WEB_SECRET_FILE, "w", encoding="utf-8") as f:
        f.write(key)
    try:
        os.chmod(_WEB_SECRET_FILE, 0o600)
    except OSError:
        pass
    return key


app = Flask(__name__)
app.secret_key = _get_secret_key()
# Cookie de session uniquement : fermer le navigateur invalide la session (pas de persistance 8h).
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Werkzeug : ne pas journaliser chaque GET /api/control/status 200 (poll onglet config) — au plus une ligne / h.
_werkzeug_status_200_last_log: float = 0.0


class _WerkzeugThrottleControlStatus200Filter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        global _werkzeug_status_200_last_log
        try:
            msg = record.getMessage()
        except Exception:
            return True
        if "GET /api/control/status" not in msg or " 200" not in msg:
            return True
        now = time.time()
        if now - _werkzeug_status_200_last_log < 3600.0:
            return False
        _werkzeug_status_200_last_log = now
        return True


logging.getLogger("werkzeug").addFilter(_WerkzeugThrottleControlStatus200Filter())

LOG_FILE          = os.path.join(_BASE_DIR, "logs", "monitor.log")
DISCORD_CFG_FILE  = os.path.join(_BASE_DIR, "discord_config.json")
DEFAULT_PANEL_URL = "http://192.168.1.68:5000"

# Liste des queues — une par client SSE connecté
_subscribers: list[queue.Queue] = []
_subscribers_lock = threading.Lock()
_tail_thread_lock = threading.Lock()
_tail_thread_started = False
_discord_periodic_started = False
_control_lock = threading.Lock()


# ── Discord config ────────────────────────────────────────────────────────────

def load_discord_config() -> dict:
    if not os.path.exists(DISCORD_CFG_FILE):
        return {"webhook_url": "", "panel_url": DEFAULT_PANEL_URL}
    try:
        with open(DISCORD_CFG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"webhook_url": "", "panel_url": DEFAULT_PANEL_URL}


def save_discord_config(data: dict) -> None:
    with open(DISCORD_CFG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def _truncate_discord_text(text: str, limit: int) -> str:
    """Respecte les limites Discord tout en gardant un message lisible."""
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


# Discord : un message au plus toutes les 3 h, sans lien avec les alertes fichiers (SSE / journal).
DISCORD_PERIODIC_INTERVAL_SEC = 3 * 60 * 60
# Avertissement « webhook absent » : au plus une fois / 3 h, uniquement depuis le thread periodique (pas les requetes HTTP).
DISCORD_MISSING_WEBHOOK_LOG_INTERVAL_SEC = DISCORD_PERIODIC_INTERVAL_SEC
_discord_missing_webhook_last_log: float = 0.0


def _post_discord_webhook(webhook_url: str, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/135.0.0.0 Safari/537.36"
            ),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if getattr(response, "status", 200) >= 400:
                app.logger.error("Discord webhook HTTP %s", response.status)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        app.logger.error("Discord webhook refuse la requete (%s): %s", exc.code, body)
    except Exception as exc:
        app.logger.exception("Echec envoi Discord: %s", exc)


def send_discord_periodic_heartbeat() -> None:
    """Message periodique (lien panel uniquement), independant des modifications surveillees."""
    cfg = load_discord_config()
    webhook_url = cfg.get("webhook_url", "").strip()
    panel_url = cfg.get("panel_url", DEFAULT_PANEL_URL).strip()
    if not webhook_url:
        return

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    desc = (
        "Rappel automatique : le service de surveillance est en cours d'execution.\n"
        "Les modifications de fichiers ne declenchent pas ce message.\n\n"
        f"**[Ouvrir le panel]({panel_url})**"
    )
    payload = {
        "embeds": [
            {
                "title": _truncate_discord_text("Surveillance fichiers — rappel", 250),
                "description": _truncate_discord_text(desc, 4000),
                "color": 0x7C3AED,
                "footer": {
                    "text": _truncate_discord_text(f"File System Monitor — {now_str}", 200)
                },
            }
        ]
    }
    _post_discord_webhook(webhook_url, payload)


def _log_discord_webhook_missing_if_due() -> None:
    """Journalise l'absence de webhook au plus une fois toutes les 3 h (evite le bruit sur chaque action)."""
    global _discord_missing_webhook_last_log

    cfg = load_discord_config()
    if cfg.get("webhook_url", "").strip():
        return
    now = time.monotonic()
    if _discord_missing_webhook_last_log > 0 and (
        now - _discord_missing_webhook_last_log
    ) < DISCORD_MISSING_WEBHOOK_LOG_INTERVAL_SEC:
        return
    _discord_missing_webhook_last_log = now
    app.logger.warning("Discord non configure: webhook absent")


def discord_periodic_loop() -> None:
    try:
        _log_discord_webhook_missing_if_due()
    except Exception:
        pass
    while True:
        time.sleep(DISCORD_PERIODIC_INTERVAL_SEC)
        try:
            send_discord_periodic_heartbeat()
            _log_discord_webhook_missing_if_due()
        except Exception:
            pass


# ── Log parsing & grouping ────────────────────────────────────────────────────

def parse_log_line(line: str) -> dict | None:
    """
    Parse une ligne du fichier log au format :
        2024-01-15 10:30:45,123 - LEVEL - message

    Returns:
        dict avec timestamp, level, message, raw, is_detail — ou None si vide.
    """
    line = line.strip()
    if not line:
        return None

    parts = line.split(" - ", 2)
    if len(parts) == 3:
        timestamp, level, raw_msg = parts
        is_detail = raw_msg.startswith(" - ") or raw_msg.startswith("  - ")
        return {
            "timestamp": timestamp.strip(),
            "level":     level.strip().upper(),
            "message":   raw_msg.strip(),
            "raw":       line,
            "is_detail": is_detail,
        }
    return {"timestamp": "", "level": "INFO", "message": line, "raw": line, "is_detail": False}


def _is_detail_line(parsed: dict) -> bool:
    return parsed.get("is_detail", False)


def group_logs(parsed_lines: list) -> list:
    """
    Regroupe les lignes [ALERTE] avec leurs lignes de détail suivantes.
    Les entrées groupées ont un champ 'details' (liste de strings).
    """
    groups = []
    i = 0
    while i < len(parsed_lines):
        line = parsed_lines[i]
        msg  = line.get("message", "")

        if "[ALERTE]" in msg or "[CRITIQUE]" in msg:
            details = []
            j = i + 1
            while j < len(parsed_lines):
                if _is_detail_line(parsed_lines[j]):
                    details.append(parsed_lines[j]["message"])
                    j += 1
                else:
                    break
            entry = dict(line)
            if details:
                entry["details"] = details
            groups.append(entry)
            i = j

        elif _is_detail_line(line):
            # Sinon la ligne serait jetée : arrive souvent en 2e lecture du tail
            # (détails écrits après l’en-tête [ALERTE]) et disparaît du flux / JSON.
            groups.append(line)
            i += 1

        else:
            groups.append(line)
            i += 1

    return groups


def _dedupe_alert_broadcasts(groups: list) -> list:
    """
    Une même modification peut produire deux lignes [ALERTE] quasi identiques dans le journal.
    On ne diffuse qu'une seule entrée par (horodatage à la seconde, message d'alerte).
    """
    seen = set()
    out = []
    for g in groups:
        msg = g.get("message") or ""
        if "[ALERTE]" not in msg and "[CRITIQUE]" not in msg:
            out.append(g)
            continue
        ts = (g.get("timestamp") or "").split(",")[0].strip()
        key = (ts, msg.strip())
        if key in seen:
            continue
        seen.add(key)
        out.append(g)
    return out


# ── SSE broadcast ─────────────────────────────────────────────────────────────

def _broadcast(data: str) -> None:
    with _subscribers_lock:
        dead = []
        for q in _subscribers:
            try:
                q.put_nowait(data)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _subscribers.remove(q)


# ── Log tailer ────────────────────────────────────────────────────────────────

def tail_log() -> None:
    """
    Thread daemon : surveille monitor.log, groupe les alertes,
    diffuse en SSE (Discord : fil separe, message toutes les 3 h).
    """
    last_size = 0

    while True:
        try:
            if os.path.exists(LOG_FILE):
                current_size = os.path.getsize(LOG_FILE)
                if current_size > last_size:
                    with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                        f.seek(last_size)
                        new_lines = f.readlines()

                    chunk_end = current_size
                    parsed = [p for line in new_lines if (p := parse_log_line(line))]
                    read_end = chunk_end

                    # Si une alerte est détectée, attendre que toutes les lignes
                    # de détail soient écrites avant de grouper
                    if any(
                        "[ALERTE]" in p.get("message", "") or "[CRITIQUE]" in p.get("message", "")
                        for p in parsed
                    ):
                        time.sleep(0.2)
                        current_size2 = os.path.getsize(LOG_FILE)
                        if current_size2 > read_end:
                            with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                                f.seek(read_end)
                                more = f.readlines()
                            read_end = current_size2
                            parsed += [p for line in more if (p := parse_log_line(line))]

                    last_size = read_end

                    for entry in _dedupe_alert_broadcasts(group_logs(parsed)):
                        _broadcast(json.dumps(entry))

                elif current_size < last_size:
                    last_size = 0

        except Exception:
            pass

        time.sleep(0.4)


def ensure_tail_thread_started() -> None:
    """Demarre le thread de surveillance des logs et le rappel Discord periodique."""
    global _tail_thread_started, _discord_periodic_started
    if _tail_thread_started and _discord_periodic_started:
        return

    with _tail_thread_lock:
        if not _tail_thread_started:
            threading.Thread(target=tail_log, daemon=True).start()
            _tail_thread_started = True
        if not _discord_periodic_started:
            threading.Thread(target=discord_periodic_loop, daemon=True).start()
            _discord_periodic_started = True


# ── Authentification ───────────────────────────────────────────────────────────

@app.before_request
def _require_login():
    if flask_request.endpoint in ("login", "static"):
        return
    if session.get("authenticated"):
        return
    if flask_request.path.startswith("/api"):
        return jsonify({"error": "Unauthorized", "login": "/login"}), 401
    return redirect(url_for("login", next=flask_request.path))


@app.route("/login", methods=["GET", "POST"])
def login():
    load_users_db()
    if session.get("authenticated"):
        return redirect(url_for("index"))

    error = None
    if flask_request.method == "POST":
        name = flask_request.form.get("username", "").strip()
        password = (flask_request.form.get("password") or "").strip()
        if verify_user_password(name, password):
            session["authenticated"] = True
            session["username"] = canonical_username_for_session(name) or name.strip()
            nxt = flask_request.args.get("next") or flask_request.form.get("next")
            if nxt and nxt.startswith("/"):
                return redirect(nxt)
            return redirect(url_for("index"))
        error = AUTH_ERROR_MESSAGE

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    resp = redirect(url_for("login"))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.after_request
def _no_store_sensitive_pages(response):
    """Évite de mettre en cache le panel et les réponses API (données sensibles)."""
    ep = flask_request.endpoint
    path = flask_request.path
    if ep in ("index", "login") or path.startswith("/api"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
    return response


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    ensure_tail_thread_started()
    return render_template("index.html")


@app.route("/api/logs")
def get_logs():
    """Retourne tout l'historique groupé en JSON."""
    ensure_tail_thread_started()
    raw = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parsed = parse_log_line(line)
                if parsed:
                    raw.append(parsed)
    return jsonify(group_logs(raw))


@app.route("/api/stats")
def get_stats():
    ensure_tail_thread_started()
    counts = {"INFO": 0, "WARNING": 0, "ERROR": 0, "TOTAL": 0}
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parsed = parse_log_line(line)
                if parsed and not _is_detail_line(parsed):
                    counts["TOTAL"] += 1
                    lvl = parsed["level"]
                    if lvl in counts:
                        counts[lvl] += 1
    return jsonify(counts)


@app.route("/api/stream")
def stream():
    ensure_tail_thread_started()
    q: queue.Queue = queue.Queue(maxsize=200)
    with _subscribers_lock:
        _subscribers.append(q)

    def generate():
        try:
            while True:
                try:
                    data = q.get(timeout=25)
                    yield f"data: {data}\n\n"
                except queue.Empty:
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            with _subscribers_lock:
                if q in _subscribers:
                    _subscribers.remove(q)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@app.route("/api/discord-config", methods=["GET"])
def get_discord_config():
    ensure_tail_thread_started()
    return jsonify(load_discord_config())


@app.route("/api/discord-config", methods=["POST"])
def set_discord_config():
    ensure_tail_thread_started()
    data = flask_request.get_json(force=True)
    save_discord_config({
        "webhook_url": data.get("webhook_url", ""),
        "panel_url":   data.get("panel_url",   DEFAULT_PANEL_URL),
    })
    return jsonify({"ok": True})


def _resolve_chmod_target(filename: str):
    """Retourne le chemin absolu d'un fichier surveillé à partir du nom (menu 7)."""
    from utils.metadata import normalize_path as np

    import monitor

    name = (filename or "").strip()
    if not name:
        return None
    for p in monitor.get_monitored_file_paths():
        if os.path.basename(p) == name or np(p) == np(name):
            return p
    return None


# Import différé : monitor
@app.route("/api/control/status", methods=["GET"])
def control_status():
    """État de la configuration (équivalent menu 6)."""
    if not session.get("authenticated"):
        return jsonify({"error": "Unauthorized"}), 401
    import monitor

    with _control_lock:
        snap = monitor.get_watch_snapshot()
    return jsonify(snap)


@app.route("/api/control/setup-all", methods=["POST"])
def control_setup_all():
    if not session.get("authenticated"):
        return jsonify({"error": "Unauthorized"}), 401
    data = flask_request.get_json(force=True, silent=True) or {}
    directory = (data.get("directory") or "").strip()
    if not directory:
        return jsonify({"ok": False, "error": "Dossier requis"}), 400
    import monitor

    with _control_lock:
        ok = monitor.setup_watch_all(directory)
        snap = monitor.get_watch_snapshot()
    if not ok:
        return jsonify({"ok": False, "error": "Échec : dossier introuvable ou erreur (voir monitor.log)", "snapshot": snap}), 400
    return jsonify({"ok": True, "snapshot": snap})


@app.route("/api/control/setup-file", methods=["POST"])
def control_setup_file():
    if not session.get("authenticated"):
        return jsonify({"error": "Unauthorized"}), 401
    data = flask_request.get_json(force=True, silent=True) or {}
    path = (data.get("path") or "").strip()
    if not path:
        return jsonify({"ok": False, "error": "Chemin complet du fichier requis"}), 400
    import monitor

    with _control_lock:
        ok = monitor.setup_watch_file(path)
        snap = monitor.get_watch_snapshot()
    if not ok:
        return jsonify(
            {"ok": False, "error": "Échec : chemin absolu requis ou dossier invalide (voir monitor.log)", "snapshot": snap}
        ), 400
    return jsonify({"ok": True, "snapshot": snap})


@app.route("/api/control/add-file", methods=["POST"])
def control_add_file():
    if not session.get("authenticated"):
        return jsonify({"error": "Unauthorized"}), 401
    data = flask_request.get_json(force=True, silent=True) or {}
    filename = (data.get("filename") or "").strip()
    if not filename:
        return jsonify({"ok": False, "error": "Nom de fichier requis"}), 400
    import monitor

    with _control_lock:
        ok = monitor.add_file(filename)
        snap = monitor.get_watch_snapshot()
    if not ok:
        return jsonify({"ok": False, "error": "Impossible : configurez d'abord un dossier (menu 1 ou 2)", "snapshot": snap}), 400
    return jsonify({"ok": True, "snapshot": snap})


@app.route("/api/control/remove-file", methods=["POST"])
def control_remove_file():
    if not session.get("authenticated"):
        return jsonify({"error": "Unauthorized"}), 401
    data = flask_request.get_json(force=True, silent=True) or {}
    filename = (data.get("filename") or "").strip()
    if not filename:
        return jsonify({"ok": False, "error": "Nom de fichier requis"}), 400
    import monitor

    with _control_lock:
        ok = monitor.remove_file(filename)
        snap = monitor.get_watch_snapshot()
    if not ok:
        return jsonify({"ok": False, "error": "Impossible de retirer le fichier", "snapshot": snap}), 400
    return jsonify({"ok": True, "snapshot": snap})


@app.route("/api/control/remove-watch", methods=["POST"])
def control_remove_watch():
    if not session.get("authenticated"):
        return jsonify({"error": "Unauthorized"}), 401
    import monitor

    with _control_lock:
        monitor.remove_watch()
        snap = monitor.get_watch_snapshot()
    return jsonify({"ok": True, "snapshot": snap})


@app.route("/api/control/chmod", methods=["POST"])
def control_chmod():
    if not session.get("authenticated"):
        return jsonify({"error": "Unauthorized"}), 401
    data = flask_request.get_json(force=True, silent=True) or {}
    filename = (data.get("filename") or "").strip()
    mode = (data.get("mode") or "").strip()
    if not filename or not mode:
        return jsonify({"ok": False, "error": "Fichier et mode (ex. 644) requis"}), 400
    import monitor

    with _control_lock:
        target = _resolve_chmod_target(filename)
        if not target:
            snap = monitor.get_watch_snapshot()
            return jsonify({"ok": False, "error": "Fichier inconnu dans la surveillance actuelle", "snapshot": snap}), 400
        ok = monitor.chmod_file(target, mode)
        snap = monitor.get_watch_snapshot()
    if not ok:
        return jsonify({"ok": False, "error": "chmod refusé ou mode invalide (voir monitor.log)", "snapshot": snap}), 400
    return jsonify({"ok": True, "snapshot": snap})


@app.route("/api/control/start-monitor", methods=["POST"])
def control_start_monitor():
    """Lance start_monitor dans un thread daemon (équivalent menu 8)."""
    if not session.get("authenticated"):
        return jsonify({"error": "Unauthorized"}), 401
    data = flask_request.get_json(force=True, silent=True) or {}
    try:
        interval = int(data.get("interval", 1))
    except (TypeError, ValueError):
        interval = 1
    interval = max(1, min(interval, 3600))

    def _worker():
        import monitor

        monitor.start_monitor(scan_interval=interval)

    threading.Thread(target=_worker, daemon=True, name="FSMMonitorPanel").start()
    return jsonify(
        {
            "ok": True,
            "message": "Surveillance démarrée en arrière-plan. Si une instance tourne déjà (ex. lancement web), les alertes peuvent être dupliquées.",
        }
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def run_web(
    host="0.0.0.0",
    port=5000,
    debug=False,
    start_surveillance=True,
    scan_interval=1,
):
    """Lance le serveur Flask (interface web authentifiée).

    Par défaut, démarre aussi la surveillance des fichiers (``monitor.start_monitor``)
    dans un thread daemon. Utilisez ``start_surveillance=False`` ou la CLI
    ``--no-monitor`` pour n'ouvrir que le panel (ex. surveillance déjà lancée ailleurs).
    """
    load_users_db()
    if start_surveillance:
        def _monitor_worker():
            try:
                import monitor

                monitor.start_monitor(scan_interval=scan_interval)
            except Exception:
                app.logger.exception("Erreur dans le thread de surveillance")

        threading.Thread(target=_monitor_worker, daemon=True, name="FSMMonitor").start()
        print(
            f"\n  Surveillance : thread démarré (intervalle {scan_interval}s). "
            "Sans config valide, configurez via « setup » puis relancez."
        )
        print(
            "  Pour le panel seul : relancez avec --no-monitor si une autre instance "
            "« monitor » tourne déjà (évite les doublons d'alertes).\n"
        )
    ensure_tail_thread_started()
    print("\n  File System Monitor — Interface Web")
    print(f"  ➜  http://localhost:{port}")
    print("  Connexion : utilisateurs autorisés (voir users_db.json)\n")
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    run_web()
