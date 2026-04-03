"""
Authentification centralisée : liste d'utilisateurs autorisés + mot de passe partagé (haché).
Utilisé par le CLI (session locale) et l'interface web (session Flask).
"""
import os
import json
import sys
import time
import getpass
from typing import Optional

from werkzeug.security import check_password_hash, generate_password_hash

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERS_DB_FILE = os.path.join(_PROJECT_ROOT, "users_db.json")
CLI_SESSION_FILE = os.path.join(_PROJECT_ROOT, ".fsm_cli_session")

# Utilisateurs autorisés (identifiants exacts, sensibles à la casse)
ALLOWED_USERNAMES = ["Laurent", "Tessa", "Tim", "Bruno", "Ntumba", "Killian"]
# Mot de passe partagé (officiel). Ancienne variante acceptée pour compatibilité : lemotdepasse123!!
SHARED_PASSWORD_PLAINTEXT = "motdepasse123!!"
_LEGACY_PASSWORD_PLAINTEXT = "lemotdepasse123!!"

AUTH_ERROR_MESSAGE = "Identifiant ou mot de passe incorrect."

SESSION_TTL_SECONDS = 8 * 3600
MAX_LOGIN_ATTEMPTS = 5


def _ensure_users_db_file() -> dict:
    """
    Crée users_db.json si absent avec les utilisateurs du projet et le mot de passe haché.
    Si le fichier existe déjà, ajoute tout nom manquant par rapport à ALLOWED_USERNAMES
    (mise à jour sans écraser le hash du mot de passe).
    """
    if not os.path.exists(USERS_DB_FILE):
        data = {
            "usernames": list(ALLOWED_USERNAMES),
            "password_hash": generate_password_hash(SHARED_PASSWORD_PLAINTEXT),
        }
        with open(USERS_DB_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return data

    with open(USERS_DB_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    current = list(data.get("usernames") or [])
    # Ordre canonique : d'abord tous les admins référencés dans le code, puis anciens comptes éventuels
    merged: list[str] = []
    seen: set[str] = set()
    for u in ALLOWED_USERNAMES + current:
        if u and u not in seen:
            seen.add(u)
            merged.append(u)

    changed = merged != current
    if changed:
        data["usernames"] = merged

    # Hash manquant ou fichier corrompu : régénérer le mot de passe officiel
    h = data.get("password_hash")
    if not h or not isinstance(h, str) or not h.startswith("pbkdf2:"):
        data["password_hash"] = generate_password_hash(SHARED_PASSWORD_PLAINTEXT)
        changed = True

    if changed:
        with open(USERS_DB_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    return data


def load_users_db() -> dict:
    """Charge la base utilisateurs (fichier JSON)."""
    return _ensure_users_db_file()


def _canonical_username(names: list, username: str) -> Optional[str]:
    """Retourne le nom exact tel qu'en base (ex: bruno -> Bruno)."""
    u = (username or "").strip()
    if not u:
        return None
    for n in names:
        if isinstance(n, str) and n.casefold() == u.casefold():
            return n
    return None


def _password_matches_hash(h: str, password: str) -> bool:
    """Vérifie le mot de passe contre le hash (officiel, ancien mot de passe, espaces en trop)."""
    if not h or not password:
        return False
    pwd = password.strip()
    if check_password_hash(h, pwd):
        return True
    # Base créée avec lemotdepasse123!! — accepter motdepasse123!! et l'inverse
    if pwd == SHARED_PASSWORD_PLAINTEXT and check_password_hash(h, _LEGACY_PASSWORD_PLAINTEXT):
        return True
    if pwd == _LEGACY_PASSWORD_PLAINTEXT and check_password_hash(h, SHARED_PASSWORD_PLAINTEXT):
        return True
    return False


def verify_user_password(username: str, password: str) -> bool:
    """True si l'utilisateur est dans la liste et le mot de passe correspond."""
    data = load_users_db()
    names = data.get("usernames") or []
    canon = _canonical_username(names, username)
    if not canon:
        return False
    h = data.get("password_hash") or ""
    return _password_matches_hash(h, password)


def canonical_username_for_session(username: str) -> Optional[str]:
    """Nom d'utilisateur canonique à enregistrer en session (même casse que users_db.json)."""
    data = load_users_db()
    return _canonical_username(data.get("usernames") or [], username)


def _cli_session_load() -> Optional[dict]:
    if not os.path.exists(CLI_SESSION_FILE):
        return None
    try:
        with open(CLI_SESSION_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def cli_session_valid() -> bool:
    s = _cli_session_load()
    if not s:
        return False
    if time.time() > float(s.get("expires", 0)):
        return False
    data = load_users_db()
    names = data.get("usernames") or []
    if _canonical_username(names, s.get("username", "")) is None:
        return False
    return True


def save_cli_session(username: str) -> None:
    payload = {
        "username": username,
        "expires": time.time() + SESSION_TTL_SECONDS,
    }
    with open(CLI_SESSION_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    try:
        os.chmod(CLI_SESSION_FILE, 0o600)
    except OSError:
        pass


def clear_cli_session() -> None:
    try:
        os.remove(CLI_SESSION_FILE)
    except OSError:
        pass


def ensure_cli_authenticated() -> None:
    """
    Autorise l'exécution du CLI uniquement pour un utilisateur référencé.
    - Session fichier .fsm_cli_session si encore valide
    - Sinon variables d'environnement FSM_USERNAME + FSM_PASSWORD
    - Sinon invite interactive (stdin TTY)
    """
    if cli_session_valid():
        return

    env_user = os.environ.get("FSM_USERNAME", "").strip()
    env_pass = os.environ.get("FSM_PASSWORD")
    if env_user and env_pass is not None:
        if verify_user_password(env_user, env_pass):
            canon = canonical_username_for_session(env_user) or env_user.strip()
            save_cli_session(canon)
            return
        print(AUTH_ERROR_MESSAGE, file=sys.stderr)
        sys.exit(1)

    if not sys.stdin.isatty():
        print(
            "Authentification requise. Utilisez un terminal interactif ou "
            "définissez FSM_USERNAME et FSM_PASSWORD (même couple que l'interface web).",
            file=sys.stderr,
        )
        sys.exit(1)

    for attempt in range(MAX_LOGIN_ATTEMPTS):
        user = input("Identifiant : ").strip()
        pwd = getpass.getpass("Mot de passe : ")
        if verify_user_password(user, pwd):
            canon = canonical_username_for_session(user) or user.strip()
            save_cli_session(canon)
            return
        print(AUTH_ERROR_MESSAGE)
    print("Trop de tentatives échouées.", file=sys.stderr)
    sys.exit(1)
