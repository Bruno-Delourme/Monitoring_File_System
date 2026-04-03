#!/usr/bin/env python3
"""
Serveur web pour visualiser les logs de monitor.log en temps réel.
Utilise Flask + Server-Sent Events (SSE) pour les notifications live.
"""

import os
import json
import ast
import time
import queue
import threading
import urllib.error
import urllib.request
from datetime import timedelta

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
app.permanent_session_lifetime = timedelta(hours=8)

LOG_FILE          = os.path.join(_BASE_DIR, "logs", "monitor.log")
DISCORD_CFG_FILE  = os.path.join(_BASE_DIR, "discord_config.json")
DEFAULT_PANEL_URL = "http://192.168.1.68:5000"

# Liste des queues — une par client SSE connecté
_subscribers: list[queue.Queue] = []
_subscribers_lock = threading.Lock()
_tail_thread_lock = threading.Lock()
_tail_thread_started = False


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


def _describe_octal_mode(mode: str) -> str:
    """Traduit un mode octal Unix en description lisible en francais."""
    raw = str(mode).strip()
    digits = raw.replace("0o", "").replace("0O", "")
    if not digits.isdigit() or len(digits) < 3:
        return raw

    rights_map = {
        0: "aucun droit",
        1: "execution uniquement",
        2: "droit d'ecriture",
        3: "droits d'ecriture et d'execution",
        4: "droit de lecture",
        5: "droits de lecture et d'execution",
        6: "droits de lecture et d'ecriture",
        7: "tous les droits standards : lecture, ecriture et execution",
    }

    perm_digits = digits[-3:]
    owner = rights_map.get(int(perm_digits[0]), raw)
    group = rights_map.get(int(perm_digits[1]), raw)
    others = rights_map.get(int(perm_digits[2]), raw)

    parts = [
        f"proprietaire : {owner}",
        f"groupe : {group}",
        f"autres : {others}",
    ]

    if len(digits) == 4:
        special = int(digits[0])
        special_parts = []
        if special & 4:
            special_parts.append("setuid actif")
        if special & 2:
            special_parts.append("setgid actif")
        if special & 1:
            special_parts.append("sticky bit actif")
        if special_parts:
            parts.append(", ".join(special_parts))

    return f"{raw} ({' ; '.join(parts)})"


def _translate_detail_for_discord(detail: str) -> str:
    """Rend les lignes de detail plus lisibles dans Discord."""
    text = str(detail).lstrip()
    if text.startswith("- "):
        text = text[2:].strip()

    if text.startswith("Permissions modifiees : ") or text.startswith("Permissions modifiées : "):
        _, _, values = text.partition(": ")
        old_mode, _, new_mode = values.partition(" -> ")
        if old_mode and new_mode:
            return (
                "Permissions modifiees : "
                f"{_describe_octal_mode(old_mode)} -> {_describe_octal_mode(new_mode)}"
            )

    if text.startswith(" - "):
        text = text[3:]

    if text.lower().startswith("ancien etat :") or text.lower().startswith("ancien état :") \
       or text.lower().startswith("nouvel etat :") or text.lower().startswith("nouvel état :"):
        label, _, payload = text.partition(": ")
        try:
            state = ast.literal_eval(payload)
        except Exception:
            return text

        if isinstance(state, dict) and "mode" in state:
            state = dict(state)
            state["mode"] = _describe_octal_mode(state["mode"])
            return f"{label}: {state}"

    return text


def send_discord_alert(entry: dict) -> None:
    """Envoie une notification Discord pour une alerte groupee."""
    cfg = load_discord_config()
    webhook_url = cfg.get("webhook_url", "").strip()
    panel_url   = cfg.get("panel_url", DEFAULT_PANEL_URL).strip()

    if not webhook_url:
        app.logger.warning("Discord non configure: webhook absent")
        return

    msg       = entry.get("message", "")
    details   = entry.get("details", [])
    timestamp = entry.get("timestamp", "")

    path_part = msg.split(":")[-1].strip() if ":" in msg else ""
    filename  = os.path.basename(path_part) if path_part else "fichier"

    safe_msg = _truncate_discord_text(msg, 800)
    desc_lines = [f"```{safe_msg}```"]
    for detail in details:
        desc_lines.append(f"- {_truncate_discord_text(_translate_detail_for_discord(detail), 900)}")
    desc_lines.append(f"\n**[Voir le panel de surveillance]({panel_url})**")

    payload = {
        "embeds": [{
            "title": _truncate_discord_text(
                f"Nouvelle alerte : modification detectee sur `{filename}`",
                250,
            ),
            "description": _truncate_discord_text("\n".join(desc_lines), 4000),
            "color": 0xDC2626,
            "footer": {
                "text": _truncate_discord_text(f"File System Monitor - {timestamp}", 200)
            },
        }]
    }

    data = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
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

        if "[ALERTE]" in msg:
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
            i += 1  # déjà consommée par un groupe précédent

        else:
            groups.append(line)
            i += 1

    return groups


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
    diffuse en SSE et notifie Discord.
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
                    last_size = current_size

                    parsed = [p for line in new_lines if (p := parse_log_line(line))]

                    # Si une alerte est détectée, attendre que toutes les lignes
                    # de détail soient écrites avant de grouper
                    if any("[ALERTE]" in p.get("message", "") for p in parsed):
                        time.sleep(0.2)
                        current_size2 = os.path.getsize(LOG_FILE)
                        if current_size2 > last_size:
                            with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                                f.seek(last_size)
                                more = f.readlines()
                            last_size = current_size2
                            parsed += [p for line in more if (p := parse_log_line(line))]

                    for entry in group_logs(parsed):
                        _broadcast(json.dumps(entry))
                        if "[ALERTE]" in entry.get("message", ""):
                            threading.Thread(
                                target=send_discord_alert, args=(entry,), daemon=True
                            ).start()

                elif current_size < last_size:
                    last_size = 0

        except Exception:
            pass

        time.sleep(0.4)


def ensure_tail_thread_started() -> None:
    """Demarre le thread de surveillance des logs une seule fois."""
    global _tail_thread_started
    if _tail_thread_started:
        return

    with _tail_thread_lock:
        if _tail_thread_started:
            return
        threading.Thread(target=tail_log, daemon=True).start()
        _tail_thread_started = True


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
            session.permanent = True
            nxt = flask_request.args.get("next") or flask_request.form.get("next")
            if nxt and nxt.startswith("/"):
                return redirect(nxt)
            return redirect(url_for("index"))
        error = AUTH_ERROR_MESSAGE

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


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


# ── Main ──────────────────────────────────────────────────────────────────────

def run_web(host="0.0.0.0", port=5000, debug=False):
    """Lance le serveur Flask (interface web authentifiée)."""
    load_users_db()
    ensure_tail_thread_started()
    print("\n  File System Monitor — Interface Web")
    print(f"  ➜  http://localhost:{port}")
    print("  Connexion : utilisateurs autorisés (voir users_db.json)\n")
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    run_web()
