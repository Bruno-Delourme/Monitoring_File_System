#!/usr/bin/env python3
"""
Script de surveillance de fichiers système.
Surveille un fichier spécifique dans un dossier donné et alerte en cas de modification.
"""

# Imports standard
import os
import sys
import json
import time
import argparse
import subprocess

# Imports watchdog pour la surveillance du système de fichiers
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Imports locaux pour les utilitaires
from utils.metadata import normalize_path, get_file_metadata
from utils.logger import (
    log_and_print,
    COLOR_RED,
    COLOR_GREEN,
    COLOR_YELLOW,
    COLOR_CYAN
)

# Fichier de configuration JSON pour stocker les paramètres de surveillance
CONFIG_FILE = "config.json"

# Si True, aucune alerte n'est émise quand le contenu du fichier change
# (mtime / sha256). Les changements de "droits" (mode/uid/gid) restent actifs.
IGNORE_CONTENT_CHANGES = True

# Intervalle (en secondes) entre deux vérifications d'accès (0 = désactivé)
DEFAULT_PROBE_INTERVAL = 0


_UID_TO_NAME = None
_GID_TO_NAME = None


def _load_uid_gid_maps():
    """
    Charge une correspondance UID->nom ( /etc/passwd ) et GID->nom ( /etc/group ).
    Retourne des dicts vides si les fichiers sont indisponibles.
    """
    global _UID_TO_NAME, _GID_TO_NAME
    if _UID_TO_NAME is not None and _GID_TO_NAME is not None:
        return _UID_TO_NAME, _GID_TO_NAME

    uid_map = {}
    gid_map = {}

    try:
        with open("/etc/passwd", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) >= 4:
                    name = parts[0]
                    uid = parts[2]
                    try:
                        uid_int = int(uid)
                        uid_map[uid_int] = name
                    except ValueError:
                        pass
    except OSError:
        pass

    try:
        with open("/etc/group", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) >= 3:
                    name = parts[0]
                    gid = parts[2]
                    try:
                        gid_int = int(gid)
                        gid_map[gid_int] = name
                    except ValueError:
                        pass
    except OSError:
        pass

    _UID_TO_NAME = uid_map
    _GID_TO_NAME = gid_map
    return _UID_TO_NAME, _GID_TO_NAME


def _resolve_uid(uid):
    uid_map, _ = _load_uid_gid_maps()
    try:
        return uid_map.get(int(uid), f"uid={uid}")
    except (TypeError, ValueError):
        return f"uid={uid}"


def _resolve_gid(gid):
    _, gid_map = _load_uid_gid_maps()
    try:
        return gid_map.get(int(gid), f"gid={gid}")
    except (TypeError, ValueError):
        return f"gid={gid}"


def _detect_privilege_escalation(old_meta, new_meta):
    """
    Détecte une élévation de privilèges basée sur l'appartenance à uid/gid=0.

    Cas visé : l'attaquant peut créer/altérer une entrée passwd du type
    'hacker:x:0:0:...' (uid=0, gid=0). Le script doit alors alerter
    même si le nom affiché n'est pas 'root'.
    """
    if not new_meta or not new_meta.get("exists"):
        return None

    old_uid = (old_meta or {}).get("uid")
    old_gid = (old_meta or {}).get("gid")
    new_uid = new_meta.get("uid")
    new_gid = new_meta.get("gid")

    reasons = []
    # Propriétaire root (uid=0)
    if new_uid == 0 and old_uid != 0:
        reasons.append(
            f"propriétaire -> uid=0 ({_resolve_uid(new_uid)})"
        )
    # Groupe root (gid=0)
    if new_gid == 0 and old_gid != 0:
        reasons.append(
            f"groupe -> gid=0 ({_resolve_gid(new_gid)})"
        )

    if reasons:
        return " | ".join(reasons)
    return None


def _describe_permissions(mode_str):
    """
    Rend les permissions compréhensibles pour les non-initiés.

    Exemple: "0o644" ->
      "0o644 | Utilisateur: rw- (lecture+écriture) | Groupe: r-- (lecture) | Autres: r-- (lecture)"
    """
    if not mode_str:
        return "N/A"

    try:
        # mode_str vient de utils.metadata.get_file_metadata(): oct(...) -> "0o644"
        mode_int = int(str(mode_str), 8)
    except ValueError:
        return str(mode_str)

    def triplet(n):
        return "".join(
            [
            "r" if (n & 4) else "-",
            "w" if (n & 2) else "-",
            "x" if (n & 1) else "-",
            ]
        )

    def triplet_words(s):
        rights = []
        if "r" in s:
            rights.append("lecture")
        if "w" in s:
            rights.append("écriture")
        if "x" in s:
            rights.append("exécution")
        return "+".join(rights) if rights else "aucun"

    u = (mode_int >> 6) & 0b111
    g = (mode_int >> 3) & 0b111
    o = mode_int & 0b111
    u_s = triplet(u)
    g_s = triplet(g)
    o_s = triplet(o)
    return (
        f"{mode_str} | "
        f"Utilisateur: {u_s} ({triplet_words(u_s)}) | "
        f"Groupe: {g_s} ({triplet_words(g_s)}) | "
        f"Autres: {o_s} ({triplet_words(o_s)})"
    )


def _describe_state(meta):
    """
    Rend un état de fichier lisible pour les non-initiés.

    meta est le dictionnaire produit par get_file_metadata().
    """
    if not meta:
        return "N/A"

    exists = meta.get("exists", False)
    mode_desc = _describe_permissions(meta.get("mode"))
    uid = meta.get("uid", "N/A")
    gid = meta.get("gid", "N/A")
    mtime = meta.get("mtime", "N/A")
    return f"exists={exists} | {mode_desc} | uid={uid} | gid={gid} | mtime={mtime}"


def _sudo_run_as(user, args):
    """
    Exécute une commande en tant qu'un autre utilisateur via sudo.
    Nécessite généralement d'exécuter l'outil avec un contexte sudoers adapté.

    - `-n` : non-interactif (échoue si un mot de passe est requis)
    """
    return subprocess.run(
        ["sudo", "-n", "-u", user, "--", *args],
        capture_output=True,
        text=True,
    )


def _probe_access(user, action, path):
    """
    Teste une tentative d'accès (read/write/exec) en tant que `user`.
    Retourne (ok:bool, detail:str).

    Note: write est non-destructif (open O_WRONLY|O_APPEND sans écrire).
    """
    if action == "read":
        # Lire 1 octet (suffisant pour provoquer EACCES si interdit)
        p = _sudo_run_as(user, ["python3", "-c", "import sys; open(sys.argv[1],'rb').read(1)", path])
    elif action == "write":
        # Ouverture en écriture (append) sans écrire.
        p = _sudo_run_as(
            user,
            [
                "python3",
                "-c",
                "import os,sys; fd=os.open(sys.argv[1], os.O_WRONLY|os.O_APPEND); os.close(fd)",
                path,
            ],
        )
    elif action == "exec":
        # Tester le droit d'exécution (pas de lancement)
        p = _sudo_run_as(user, ["test", "-x", path])
    else:
        return True, "action inconnue (ignorée)"

    if p.returncode == 0:
        return True, "OK"

    stderr = (p.stderr or "").strip()
    stdout = (p.stdout or "").strip()
    msg = stderr or stdout or f"code={p.returncode}"

    # sudo -n sans permission => pas un "refus sur fichier", mais un problème de sudo
    if "a password is required" in msg.lower() or "password is required" in msg.lower():
        return True, "probe impossible (sudo demande un mot de passe)"

    # Tentative non autorisée sur fichier : permission denied, operation not permitted, etc.
    low = msg.lower()
    if "permission denied" in low or "operation not permitted" in low:
        return False, msg

    # Par défaut, on signale en warning (peut être fichier absent, python manquant, etc.)
    return True, msg


def check_unauthorized_access_attempts():
    """
    Lance des probes de tentative d'accès sur les fichiers surveillés.
    Si une tentative est refusée (EACCES/EPERM), on émet une alerte.
    """
    config = load_config()
    watch_dir = config.get("watch_directory")
    if not watch_dir:
        return

    users = _ensure_list(config.get("probe_users"))
    actions = _ensure_list(config.get("probe_actions"))
    filenames = _ensure_list(config.get("filenames") or config.get("filename"))
    if not users or not actions or not filenames:
        return

    for name in filenames:
        path = normalize_path(os.path.join(watch_dir, name))
        if not os.path.exists(path):
            continue
        for user in users:
            for action in actions:
                ok, detail = _probe_access(user, action, path)
                if ok is False:
                    log_and_print(
                        f"[CRITIQUE] Tentative d'accès non autorisée: user='{user}' action='{action}' ressource='{path}' ({detail})",
                        level="error",
                        color=COLOR_RED,
                    )


def load_config():
    """
    Charge la configuration depuis le fichier JSON.
    
    Returns:
        dict: Dictionnaire contenant la configuration, ou dict vide si le fichier
              n'existe pas ou est invalide.
    """
    # Si le fichier de configuration n'existe pas, retourner un dict vide
    if not os.path.exists(CONFIG_FILE):
        return {}

    try:
        # Ouvrir et lire le fichier JSON avec encodage UTF-8
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # S'assurer que les données sont bien un dictionnaire
            return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        # En cas d'erreur de parsing JSON ou d'accès fichier, retourner un dict vide
        return {}


def save_config(data):
    """
    Sauvegarde la configuration dans le fichier JSON.
    
    Args:
        data (dict): Dictionnaire contenant la configuration à sauvegarder.
    """
    # Écrire la configuration dans le fichier JSON avec indentation pour lisibilité
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def _ensure_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def get_monitored_file_paths():
    """
    Construit et retourne les chemins complets des fichiers surveillés.
    
    Returns:
        list[str]: Liste de chemins absolus normalisés. Liste vide si config incomplète.
    """
    config = load_config()
    watch_dir = config.get("watch_directory")
    watch_all = bool(config.get("watch_all", False))
    filenames = _ensure_list(config.get("filenames") or config.get("filename"))
    
    # Vérifier que la configuration contient les informations nécessaires
    if not watch_dir:
        return []
    
    # Normaliser le chemin du dossier et construire le chemin complet
    watch_dir = normalize_path(watch_dir)

    # Mode: tout le dossier (non récursif)
    if watch_all:
        paths = []
        try:
            for entry in os.listdir(watch_dir):
                full = normalize_path(os.path.join(watch_dir, entry))
                if os.path.isfile(full):
                    paths.append(full)
        except OSError:
            return []
        paths.sort(key=lambda p: os.path.basename(p).lower())
        return paths

    # Mode: liste de fichiers ciblés
    if not filenames:
        return []
    paths = []
    for name in filenames:
        if not name:
            continue
        paths.append(normalize_path(os.path.join(watch_dir, name)))
    return paths


def setup_watch(watch_directory, filenames):
    """
    Configure la surveillance d'un ou plusieurs fichiers dans un dossier spécifique.
    Les fichiers seront surveillés dès qu'ils apparaissent dans le dossier.
    
    Args:
        watch_directory (str): Chemin du dossier à surveiller.
        filenames (list[str] | str): Noms des fichiers à détecter et surveiller.
    """
    # Normaliser le chemin du dossier
    watch_directory = normalize_path(watch_directory)
    config = load_config()
    filenames = [f for f in _ensure_list(filenames) if f]

    # Vérifier que le dossier existe
    if not os.path.isdir(watch_directory):
        log_and_print(
            f"[ERREUR] Le dossier n'existe pas : {watch_directory}",
            level="error",
            color=COLOR_RED
        )
        return False

    # Enregistrer la configuration de surveillance
    config["watch_directory"] = watch_directory
    config["watch_all"] = False
    config["single_file_target"] = False
    config["filenames"] = filenames
    # Dictionnaire des métadonnées par fichier (clé = filename)
    config["file_metadata"] = {}  # rempli au fur et à mesure
    # Configuration probes (tentatives d'accès)
    config.setdefault("probe_interval", DEFAULT_PROBE_INTERVAL)
    config.setdefault("probe_users", [])  # ex: ["www-data", "nobody"]
    config.setdefault("probe_actions", ["read"])  # read, write, exec
    save_config(config)

    log_and_print(
        f"[+] Surveillance configurée : dossier '{watch_directory}' pour {len(filenames)} fichier(s)",
        color=COLOR_GREEN
    )
    for name in filenames:
        log_and_print(f"    - {name}", color=COLOR_GREEN)
    
    # Si les fichiers existent déjà, capturer leurs métadonnées immédiatement
    changed = False
    for name in filenames:
        file_path = normalize_path(os.path.join(watch_directory, name))
        if os.path.exists(file_path):
            config["file_metadata"][name] = get_file_metadata(file_path)
            changed = True
            log_and_print(
                f"[INFO] Le fichier existe déjà et est maintenant surveillé : {file_path}",
                color=COLOR_CYAN
            )
    if changed:
        save_config(config)
    return True


def setup_watch_file(file_path):
    """
    Configure la surveillance d'un fichier unique à partir de son chemin complet.
    """
    if not file_path:
        log_and_print("[ERREUR] Chemin du fichier manquant.", level="error", color=COLOR_RED)
        return False

    file_path = normalize_path(file_path)
    if not os.path.isabs(file_path):
        log_and_print(
            f"[ERREUR] Le chemin doit être absolu (complet) : {file_path}",
            level="error",
            color=COLOR_RED,
        )
        return False

    watch_directory = normalize_path(os.path.dirname(file_path))
    filename = os.path.basename(file_path)
    if not watch_directory or not filename:
        log_and_print(
            f"[ERREUR] Chemin invalide : {file_path}",
            level="error",
            color=COLOR_RED,
        )
        return False

    if not setup_watch(watch_directory, [filename]):
        return False
    config = load_config()
    config["single_file_target"] = True
    save_config(config)
    return True


def setup_watch_all(watch_directory):
    """
    Configure la surveillance de tout le dossier (tous les fichiers qu'il contient).
    Non récursif.
    """
    watch_directory = normalize_path(watch_directory)
    config = load_config()

    if not os.path.isdir(watch_directory):
        log_and_print(
            f"[ERREUR] Le dossier n'existe pas : {watch_directory}",
            level="error",
            color=COLOR_RED,
        )
        return False

    config["watch_directory"] = watch_directory
    config["watch_all"] = True
    config["single_file_target"] = False
    config["filenames"] = []
    config.pop("filename", None)
    config["file_metadata"] = {}
    config.setdefault("probe_interval", DEFAULT_PROBE_INTERVAL)
    config.setdefault("probe_users", [])
    config.setdefault("probe_actions", ["read"])
    save_config(config)

    log_and_print(
        f"[+] Surveillance configurée : tous les fichiers du dossier '{watch_directory}'",
        color=COLOR_GREEN,
    )

    # Précharger les métadonnées des fichiers déjà présents
    meta_map = {}
    for p in get_monitored_file_paths():
        meta_map[os.path.basename(p)] = get_file_metadata(p)
    config["file_metadata"] = meta_map
    save_config(config)
    return True


def add_file(filename):
    """Ajoute un fichier à la liste surveillée (même dossier)."""
    if not (filename or "").strip():
        log_and_print("[ERREUR] Nom de fichier manquant.", level="error", color=COLOR_RED)
        return False
    filename = filename.strip()
    config = load_config()
    watch_dir = config.get("watch_directory")
    if not watch_dir:
        log_and_print("[ERREUR] Aucune surveillance configurée.", level="error", color=COLOR_RED)
        return False
    if config.get("watch_all"):
        # Basculer en mode "liste ciblée" si on veut cibler un fichier
        config["watch_all"] = False
    filenames = _ensure_list(config.get("filenames") or config.get("filename"))
    if filename in filenames:
        log_and_print(f"[INFO] Déjà surveillé : {filename}", color=COLOR_YELLOW)
        return True
    filenames.append(filename)
    config["filenames"] = filenames
    if len(filenames) > 1:
        config["single_file_target"] = False
    config.pop("filename", None)
    config.setdefault("file_metadata", {})
    save_config(config)
    log_and_print(f"[+] Ajouté à la surveillance : {filename}", color=COLOR_GREEN)
    return True


def remove_file(filename):
    """Supprime un fichier de la liste surveillée (même dossier)."""
    if not (filename or "").strip():
        log_and_print("[ERREUR] Nom de fichier manquant.", level="error", color=COLOR_RED)
        return False
    filename = filename.strip()
    config = load_config()
    filenames = _ensure_list(config.get("filenames") or config.get("filename"))
    if filename not in filenames:
        log_and_print(f"[INFO] Non surveillé : {filename}", color=COLOR_YELLOW)
        return True
    filenames = [f for f in filenames if f != filename]
    config["filenames"] = filenames
    if len(filenames) != 1:
        config["single_file_target"] = False
    config.pop("filename", None)
    meta = config.get("file_metadata")
    if isinstance(meta, dict):
        meta.pop(filename, None)
        config["file_metadata"] = meta
    save_config(config)
    log_and_print(f"[-] Retiré de la surveillance : {filename}", color=COLOR_GREEN)
    return True


def remove_watch():
    """
    Supprime complètement la configuration de surveillance.
    Réinitialise le fichier de configuration à un état vide.
    """
    config = load_config()

    # Vérifier qu'une configuration existe
    if "watch_directory" not in config:
        log_and_print("[INFO] Aucune surveillance configurée.", color=COLOR_YELLOW)
        return True

    # Sauvegarder les informations pour le message de confirmation
    watch_dir = config.get("watch_directory")
    filename = config.get("filename")
    
    # Réinitialiser la configuration
    config = {}
    save_config(config)
    log_and_print(
        f"[-] Surveillance supprimée : dossier '{watch_dir}' / fichier '{filename}'",
        color=COLOR_GREEN
    )
    return True


def _print_file_state_block(name, file_path):
    """Affiche l'état actuel d'un fichier (métadonnées lues sur disque)."""
    print(f"\n--- {name} ---")
    print(f"Chemin complet : {file_path}")
    if not os.path.exists(file_path):
        print("Statut : absent (en attente de l'apparition du fichier)")
        return
    meta = get_file_metadata(file_path)
    if meta.get("exists"):
        print("Statut : présent et surveillé")
        print(f"  - Permissions : {_describe_permissions(meta.get('mode'))}")
        print(f"  - Propriétaire : {meta.get('uid', 'N/A')}:{meta.get('gid', 'N/A')}")
        print(f"  - Dernière modification : {meta.get('mtime', 'N/A')}")
    else:
        print("Statut : présent (métadonnées indisponibles)")


def list_watch():
    """
    Affiche la configuration de surveillance actuelle et le statut des fichiers.

    - Mode dossier (watch_all) : état de **tous** les fichiers présents dans le dossier.
    - Mode fichier unique (un seul nom ciblé) : état de **ce fichier uniquement**.
    - Mode liste : état de chaque fichier ciblé.
    """
    config = load_config()

    # Vérifier qu'une configuration existe
    if "watch_directory" not in config:
        print("Aucune surveillance configurée.")
        return

    # Récupérer les informations de configuration
    watch_dir = normalize_path(config.get("watch_directory"))
    watch_all = bool(config.get("watch_all", False))
    filenames = [f for f in _ensure_list(config.get("filenames") or config.get("filename")) if f]
    single_file_target = bool(config.get("single_file_target", False))
    # Un seul fichier ciblé : même logique que le menu "commande 2" (fichier unique)
    single_file_mode = (not watch_all) and len(filenames) == 1

    # Afficher la configuration
    print("\n=== Configuration de surveillance ===")
    print(f"Dossier surveillé : {watch_dir}")
    if watch_all:
        print("Mode : dossier complet — tous les fichiers du dossier (non récursif)")
    elif single_file_target or single_file_mode:
        if single_file_target:
            print("Mode : fichier unique — ciblage par chemin complet (menu « fichier »)")
        else:
            print("Mode : un seul fichier ciblé dans la liste")
        print(f"  Fichier : {filenames[0]}")
    else:
        print(f"Mode : fichiers ciblés ({len(filenames)})")
        for name in filenames:
            print(f"  - {name}")

    # --- État actuel (lecture disque, pas seulement le cache config) ---
    if watch_all:
        paths = get_monitored_file_paths()
        print(f"\n--- État des fichiers dans le dossier ({len(paths)} fichier(s)) ---")
        if not paths:
            print("(Aucun fichier pour l'instant dans ce dossier.)")
        for file_path in paths:
            _print_file_state_block(os.path.basename(file_path), file_path)
        return

    if single_file_target or single_file_mode:
        name = filenames[0]
        file_path = normalize_path(os.path.join(watch_dir, name))
        print("\n--- État du fichier surveillé ---")
        _print_file_state_block(name, file_path)
        return

    print("\n--- État des fichiers surveillés ---")
    for name in filenames:
        file_path = normalize_path(os.path.join(watch_dir, name))
        _print_file_state_block(name, file_path)


def get_watch_snapshot():
    """
    État de la configuration et des fichiers pour l'API web (JSON).
    Reprend la logique de list_watch sans affichage console.
    """
    config = load_config()
    if "watch_directory" not in config:
        return {"configured": False}

    watch_dir = normalize_path(config.get("watch_directory"))
    watch_all = bool(config.get("watch_all", False))
    filenames = [f for f in _ensure_list(config.get("filenames") or config.get("filename")) if f]
    single_file_target = bool(config.get("single_file_target", False))
    single_file_mode = (not watch_all) and len(filenames) == 1

    if watch_all:
        mode_key = "watch_all"
        mode_description = "Dossier complet — tous les fichiers (non récursif)"
    elif single_file_target or single_file_mode:
        mode_key = "single_file"
        mode_description = (
            "Fichier unique (chemin complet)"
            if single_file_target
            else "Un seul fichier ciblé dans la liste"
        )
    else:
        mode_key = "targeted_list"
        mode_description = f"Fichiers ciblés ({len(filenames)})"

    def _file_entry(name, file_path):
        row = {"name": name, "path": file_path}
        if not os.path.exists(file_path):
            row["status"] = "absent"
            row["exists"] = False
            return row
        meta = get_file_metadata(file_path)
        row["exists"] = bool(meta.get("exists"))
        row["status"] = "present" if meta.get("exists") else "unknown"
        row["mode"] = meta.get("mode")
        row["permissions_text"] = (
            _describe_permissions(meta.get("mode")) if meta.get("mode") is not None else None
        )
        row["uid"] = meta.get("uid")
        row["gid"] = meta.get("gid")
        row["mtime"] = meta.get("mtime")
        return row

    files = []
    if watch_all:
        for file_path in get_monitored_file_paths():
            files.append(_file_entry(os.path.basename(file_path), file_path))
    else:
        for name in filenames:
            fp = normalize_path(os.path.join(watch_dir, name))
            files.append(_file_entry(name, fp))

    return {
        "configured": True,
        "watch_directory": watch_dir,
        "watch_all": watch_all,
        "filenames": filenames,
        "single_file_target": single_file_target,
        "mode_key": mode_key,
        "mode_description": mode_description,
        "files": files,
    }


def chmod_file(path, mode_str):
    """
    Modifie les permissions d'un fichier en utilisant la notation octale.
    
    Args:
        path (str): Chemin du fichier dont on veut modifier les permissions.
        mode_str (str): Mode octal (ex: "644", "600", "755").
    """
    path = normalize_path(path)

    # Vérifier que le fichier existe
    if not os.path.exists(path):
        log_and_print(f"[ERREUR] Fichier introuvable : {path}", level="error", color=COLOR_RED)
        return False

    try:
        # Convertir la chaîne octale en entier (base 8)
        mode = int(mode_str, 8)
        # Appliquer les nouvelles permissions
        os.chmod(path, mode)
        log_and_print(f"[ADMIN] Permissions modifiées : {path} -> {mode_str}", color=COLOR_CYAN)
        return True
    except ValueError:
        # Erreur si le format du mode est invalide
        log_and_print(
            "[ERREUR] Mode invalide. Utilise une valeur octale comme 644, 600, 755.",
            level="error",
            color=COLOR_RED
        )
        return False
    except PermissionError:
        # Erreur si l'utilisateur n'a pas les droits
        log_and_print(
            f"[ERREUR] Permission refusée pour modifier {path}. Essaie avec sudo.",
            level="error",
            color=COLOR_RED
        )
        return False
    except OSError as e:
        # Autre erreur système
        log_and_print(f"[ERREUR] chmod impossible : {e}", level="error", color=COLOR_RED)
        return False


class MonitorHandler(FileSystemEventHandler):
    """
    Gestionnaire d'événements pour la surveillance du système de fichiers.
    Hérite de FileSystemEventHandler pour intercepter les événements watchdog.
    """
    
    def __init__(self):
        """Initialise le handler et charge la configuration."""
        self.watch_directory = None  # Dossier surveillé
        self.watch_all = False
        self.filenames = []  # Noms des fichiers recherchés
        self.monitored_file_paths = set()  # Chemins complets surveillés
        self._load_config()

    def _load_config(self):
        """
        Charge la configuration de surveillance depuis le fichier JSON.
        Construit le chemin complet du fichier à surveiller.
        """
        config = load_config()
        self.watch_directory = normalize_path(config.get("watch_directory", ""))
        self.watch_all = bool(config.get("watch_all", False))
        self.filenames = _ensure_list(config.get("filenames") or config.get("filename"))
        
        self.monitored_file_paths = set()
        if self.watch_directory and (self.watch_all or self.filenames):
            for name in self.filenames:
                if not name:
                    continue
                self.monitored_file_paths.add(
                    normalize_path(os.path.join(self.watch_directory, name))
                )

    def _is_monitored_file(self, path):
        """
        Vérifie si le chemin correspond au fichier surveillé.
        
        Args:
            path (str): Chemin à vérifier.
            
        Returns:
            bool: True si le chemin correspond au fichier surveillé, False sinon.
        """
        if not self.watch_directory:
            return False

        p = normalize_path(path)
        # Mode: tout le dossier (fichiers uniquement, non récursif)
        if self.watch_all:
            try:
                return os.path.dirname(p) == self.watch_directory and os.path.isfile(p)
            except OSError:
                return False

        if not self.monitored_file_paths:
            return False
        return p in self.monitored_file_paths

    def _filename_from_path(self, path):
        try:
            return os.path.basename(normalize_path(path))
        except OSError:
            return os.path.basename(path)

    def compare_and_alert(self, path):
        """
        Compare les métadonnées actuelles avec celles enregistrées et alerte en cas de changement.
        
        Args:
            path (str): Chemin du fichier à comparer.
        """
        # Ignorer si ce n'est pas le fichier surveillé
        if not self._is_monitored_file(path):
            return

        # Charger la configuration et récupérer les métadonnées
        config = load_config()
        name = self._filename_from_path(path)
        meta_map = config.get("file_metadata") if isinstance(config.get("file_metadata"), dict) else {}
        old = meta_map.get(name)  # Métadonnées précédentes pour ce fichier
        new = get_file_metadata(path)  # Métadonnées actuelles
        changes = []  # Liste des changements détectés

        # Cas 1: Fichier vient d'apparaître (n'existait pas avant)
        if (not old or not old.get("exists")) and new.get("exists"):
            changes.append("Le fichier est apparu dans le dossier surveillé !")
            log_and_print(
                f"[DÉTECTION] Fichier détecté : {path}",
                level="warning",
                color=COLOR_GREEN
            )

        # Cas 2: Fichier a disparu (existait avant mais plus maintenant)
        elif old and old.get("exists") and not new.get("exists"):
            changes.append("Le fichier a disparu du dossier surveillé.")

        # Cas 3: Fichier existe et a été modifié
        elif old and old.get("exists") and new.get("exists"):
            # Vérifier les permissions (mode)
            if old.get("mode") != new.get("mode"):
                changes.append(
                    "Permissions modifiées : "
                    f"{_describe_permissions(old.get('mode'))} -> {_describe_permissions(new.get('mode'))}"
                )

            # Vérifier le propriétaire et le groupe (Unix seulement)
            if old.get("uid") != new.get("uid") or old.get("gid") != new.get("gid"):
                changes.append(
                    f"Propriétaire/groupe modifiés : "
                    f"{old.get('uid')}:{old.get('gid')} -> {new.get('uid')}:{new.get('gid')}"
                )

            # Option: on peut aussi alerter sur les changements de contenu.
            # Par défaut (IGNORE_CONTENT_CHANGES=True), on ignore mtime/sha256.
            if not IGNORE_CONTENT_CHANGES:
                # Vérifier la date de modification
                if old.get("mtime") != new.get("mtime"):
                    changes.append(
                        f"Date de modification changée : {old.get('mtime')} -> {new.get('mtime')}"
                    )

                # Vérifier l'intégrité via le hash SHA256
                if old.get("sha256") != new.get("sha256"):
                    changes.append(
                        f"Intégrité modifiée (SHA256) : {old.get('sha256')} -> {new.get('sha256')}"
                    )

        # Détection d'élévation de privilèges (uid/gid=0)
        privilege_reason = _detect_privilege_escalation(old, new)
        if privilege_reason:
            changes.insert(0, f"ÉLEVATION DE PRIVILÈGES suspecte: {privilege_reason}")

        # Si des changements ont été détectés, alerter et mettre à jour la config
        if changes:
            is_critical = bool(privilege_reason)
            log_and_print(
                f"[{'CRITIQUE' if is_critical else 'ALERTE'}] Modification détectée sur : {path}",
                level="error" if is_critical else "warning",
                color=COLOR_RED
            )

            # Afficher chaque changement détecté
            for change in changes:
                log_and_print(f" - {change}", level="warning", color=COLOR_YELLOW)

            # Afficher l'ancien et le nouvel état sous forme lisible
            if old:
                log_and_print(f" - Etat précédent : {_describe_state(old)}", level="warning", color=COLOR_CYAN)
            else:
                log_and_print(f" - Etat précédent : N/A", level="warning", color=COLOR_CYAN)

            log_and_print(f" - Etat actuel : {_describe_state(new)}", level="warning", color=COLOR_CYAN)

            # Garder aussi les états bruts pour débogage (utile en dev)
            if old:
                log_and_print(f" - Ancien état (brut) : {old}", level="warning")
            log_and_print(f" - Nouvel état (brut) : {new}", level="warning")

            # Sauvegarder les nouvelles métadonnées
            meta_map[name] = new
            config["file_metadata"] = meta_map
            save_config(config)

    def on_modified(self, event):
        """
        Appelé quand un fichier est modifié dans le dossier surveillé.
        """
        # Ignorer les dossiers, ne traiter que les fichiers
        if not event.is_directory and self._is_monitored_file(event.src_path):
            self.compare_and_alert(event.src_path)

    def on_created(self, event):
        """
        Appelé quand un fichier est créé dans le dossier surveillé.
        C'est ici que le fichier surveillé sera détecté s'il apparaît.
        """
        # Ignorer les dossiers, ne traiter que les fichiers
        if not event.is_directory and self._is_monitored_file(event.src_path):
            self.compare_and_alert(event.src_path)

    def on_deleted(self, event):
        """
        Appelé quand un fichier est supprimé dans le dossier surveillé.
        """
        # Ignorer les dossiers, ne traiter que les fichiers
        if not event.is_directory and self._is_monitored_file(event.src_path):
            self.compare_and_alert(event.src_path)

    def on_moved(self, event):
        """
        Appelé quand un fichier est déplacé/renommé dans le dossier surveillé.
        Vérifie à la fois le chemin source et le chemin de destination.
        """
        # Ignorer les dossiers
        if event.is_directory:
            return

        # Vérifier si le fichier source est celui surveillé (déplacement depuis)
        if self._is_monitored_file(event.src_path):
            self.compare_and_alert(event.src_path)
        # Vérifier si le fichier de destination est celui surveillé (déplacement vers)
        if self._is_monitored_file(event.dest_path):
            self.compare_and_alert(event.dest_path)


def start_monitor(scan_interval=1):
    """
    Lance la surveillance active du dossier et du fichier configuré.
    Utilise watchdog pour la surveillance en temps réel et un scan périodique complémentaire.
    
    Args:
        scan_interval (int): Intervalle en secondes entre les scans périodiques (défaut: 1).
    """
    config = load_config()

    # Vérifier qu'une configuration existe
    if "watch_directory" not in config:
        log_and_print("Aucune surveillance configurée. Utilisez 'setup' pour configurer.", color=COLOR_YELLOW)
        return

    watch_directory = normalize_path(config.get("watch_directory"))
    watch_all = bool(config.get("watch_all", False))
    filenames = _ensure_list(config.get("filenames") or config.get("filename"))

    # Vérifier que le dossier existe
    if not os.path.isdir(watch_directory):
        log_and_print(
            f"[ERREUR] Le dossier surveillé n'existe pas : {watch_directory}",
            level="error",
            color=COLOR_RED
        )
        return

    # Créer le handler et l'observer watchdog
    handler = MonitorHandler()
    observer = Observer()

    # Programmer la surveillance du dossier (non récursive)
    observer.schedule(handler, watch_directory, recursive=False)
    log_and_print(
        f"[WATCH] Surveillance du dossier : {watch_directory}",
        color=COLOR_CYAN
    )
    log_and_print(
        (
            "[WATCH] Mode : tous les fichiers du dossier"
            if watch_all
            else f"[WATCH] Fichiers recherchés ({len(filenames)}) : {', '.join(filenames)}"
        ),
        color=COLOR_CYAN
    )

    # Démarrer l'observer
    observer.start()
    log_and_print("Surveillance en cours... Ctrl+C pour arrêter.", color=COLOR_GREEN)

    probe_interval = int(config.get("probe_interval") or 0)
    next_probe_at = time.time() + probe_interval if probe_interval > 0 else None

    try:
        # Boucle principale : scan périodique complémentaire
        while True:
            time.sleep(scan_interval)

            # Vérification périodique des fichiers (complémentaire à watchdog)
            for monitored_file_path in get_monitored_file_paths():
                if monitored_file_path and os.path.exists(monitored_file_path):
                    handler.compare_and_alert(monitored_file_path)

            # Probes: tentatives d'accès non autorisées (optionnel)
            if next_probe_at is not None and time.time() >= next_probe_at:
                check_unauthorized_access_attempts()
                next_probe_at = time.time() + probe_interval

    except KeyboardInterrupt:
        # Arrêt propre lors de Ctrl+C
        log_and_print("Arrêt de la surveillance...", color=COLOR_YELLOW)
        observer.stop()

    # Attendre que l'observer se termine proprement
    observer.join()


def _require_cli_auth():
    """Authentification terminal (utilisateurs autorisés dans users_db.json)."""
    from utils.auth import ensure_cli_authenticated

    ensure_cli_authenticated()


def interactive_menu():
    """
    Menu interactif pour configurer et utiliser la surveillance.
    Permet de configurer, lister, modifier et lancer la surveillance via une interface texte.
    """
    while True:
        # Afficher le menu principal
        print("\n=== FILE SYSTEM MONITOR ===")
        print("1. Cibler un dossier (surveiller tous les fichiers)")
        print("2. Cibler un fichier (chemin complet obligatoire)")
        print("3. Ajouter un fichier à surveiller (mode fichiers ciblés)")
        print("4. Retirer un fichier surveillé (mode fichiers ciblés)")
        print("5. Supprimer la configuration de surveillance")
        print("6. Afficher la configuration actuelle")
        print("7. Modifier les permissions d'un fichier surveillé")
        print("8. Lancer la surveillance")
        print("9. Lancer l'interface web (panel navigateur) — connexion dans le navigateur uniquement")
        print("10. Quitter")

        choice = input("Choix : ").strip()

        # 1) Cibler un dossier
        if choice == "1":
            _require_cli_auth()
            watch_dir = input("Dossier à surveiller : ").strip()
            setup_watch_all(watch_dir)

        # 2) Cibler un fichier (chemin complet)
        elif choice == "2":
            _require_cli_auth()
            file_path = input("Chemin complet du fichier (ex: /home/user/test.txt) : ").strip()
            setup_watch_file(file_path)

        # 3) Ajouter fichier (mode fichiers ciblés)
        elif choice == "3":
            _require_cli_auth()
            filename = input("Nom du fichier à ajouter (dans le dossier ciblé) : ").strip()
            if filename:
                add_file(filename)

        # 4) Retirer fichier
        elif choice == "4":
            _require_cli_auth()
            filename = input("Nom du fichier à retirer : ").strip()
            if filename:
                remove_file(filename)

        # 5) Supprimer config
        elif choice == "5":
            _require_cli_auth()
            remove_watch()

        # 6) Afficher config
        elif choice == "6":
            _require_cli_auth()
            list_watch()

        # 7) chmod
        elif choice == "7":
            _require_cli_auth()
            file_paths = get_monitored_file_paths()
            if not file_paths:
                log_and_print(
                    "[ERREUR] Aucune surveillance configurée.",
                    level="error",
                    color=COLOR_RED
                )
            else:
                config = load_config()
                filenames = _ensure_list(config.get("filenames") or config.get("filename"))
                if not filenames and config.get("watch_all"):
                    filenames = [os.path.basename(p) for p in file_paths]
                print("Fichiers surveillés :")
                for i, n in enumerate(filenames, start=1):
                    print(f"  {i}. {n}")
                idx_raw = input("Choisir un fichier (numéro, défaut 1) : ").strip()
                try:
                    idx = int(idx_raw) if idx_raw else 1
                except ValueError:
                    idx = 1
                idx = max(1, min(idx, len(filenames)))
                selected = filenames[idx - 1]
                selected_path = normalize_path(os.path.join(config.get("watch_directory"), selected))
                mode = input("Nouvelles permissions (ex: 644, 600, 755) : ").strip()
                chmod_file(selected_path, mode)

        # 8) monitor
        elif choice == "8":
            _require_cli_auth()
            interval_raw = input("Intervalle de scan en secondes (défaut 1) : ").strip()
            try:
                interval = int(interval_raw) if interval_raw else 1
            except ValueError:
                # Valeur par défaut si l'entrée est invalide
                interval = 1
            start_monitor(scan_interval=interval)

        # 9) interface web (Flask)
        elif choice == "9":
            import web_app

            host = input("Adresse d'écoute (Entrée = 0.0.0.0) : ").strip() or "0.0.0.0"
            port_raw = input("Port (Entrée = 5000) : ").strip() or "5000"
            try:
                port = int(port_raw)
            except ValueError:
                port = 5000
            interval_raw = input(
                "Intervalle de scan surveillance en arrière-plan, secondes (Entrée = 1) : "
            ).strip() or "1"
            try:
                scan_iv = int(interval_raw)
            except ValueError:
                scan_iv = 1
            nm = input("Lancer uniquement le panel sans surveillance ? o/N : ").strip().lower()
            no_monitor = nm in ("o", "oui", "y", "yes")
            log_and_print(
                f"[WEB] Ouverture du panel — http://127.0.0.1:{port} (Ctrl+C pour arrêter)"
                + ("" if no_monitor else " ; surveillance en arrière-plan activée"),
                color=COLOR_CYAN,
            )
            web_app.run_web(
                host=host,
                port=port,
                debug=False,
                start_surveillance=not no_monitor,
                scan_interval=scan_iv,
            )

        # 10) quitter
        elif choice == "10":
            print("Fermeture.")
            break

        # Choix invalide
        else:
            print("Choix invalide.")


def build_parser():
    """
    Construit le parser d'arguments en ligne de commande.
    
    Returns:
        argparse.ArgumentParser: Parser configuré avec toutes les sous-commandes.
    """
    parser = argparse.ArgumentParser(
        description="Outil de monitoring d'un fichier dans un dossier spécifique"
    )

    # Créer les sous-commandes
    subparsers = parser.add_subparsers(dest="command")

    # Commande setup: configurer la surveillance
    parser_setup = subparsers.add_parser(
        "setup",
        help="Configurer la surveillance (dossier complet ou fichier(s) ciblé(s))"
    )
    parser_setup.add_argument("directory", nargs="?", help="Dossier à surveiller (mode --all ou fichiers relatifs au dossier)")
    parser_setup.add_argument("filenames", nargs="*", help="Chemin(s) complet(s) de fichier(s) à surveiller (mode fichier)")
    mx = parser_setup.add_mutually_exclusive_group(required=True)
    mx.add_argument("--all", action="store_true", help="Cibler un dossier : surveiller tous les fichiers (non récursif)")
    mx.add_argument("--file", action="store_true", help="Cibler un fichier : chemin complet obligatoire")

    parser_add = subparsers.add_parser("add", help="Ajouter un fichier à surveiller")
    parser_add.add_argument("filename", help="Nom du fichier à ajouter")

    parser_rm = subparsers.add_parser("rm", help="Retirer un fichier surveillé")
    parser_rm.add_argument("filename", help="Nom du fichier à retirer")

    # Commande remove: supprimer la configuration
    subparsers.add_parser("remove", help="Supprimer la configuration de surveillance")

    # Commande list: afficher la configuration
    subparsers.add_parser("list", help="Afficher la configuration actuelle")

    # Commande chmod: modifier les permissions
    parser_chmod = subparsers.add_parser(
        "chmod",
        help="Modifier les permissions du fichier surveillé"
    )
    parser_chmod.add_argument("mode", help="Mode octal, ex: 644, 600, 755")
    parser_chmod.add_argument("--file", dest="filename", default=None, help="Nom du fichier (par défaut: le 1er)")

    # Commande monitor: lancer la surveillance
    parser_monitor = subparsers.add_parser("monitor", help="Lancer la surveillance")
    parser_monitor.add_argument(
        "--interval",
        type=int,
        default=1,
        help="Intervalle de scan complémentaire en secondes (défaut: 1)"
    )
    parser_monitor.add_argument(
        "--probe-interval",
        type=int,
        default=None,
        help="Intervalle (s) pour tester des tentatives d'accès via sudo -u (0 = désactivé). "
             "Si omis, utilise la valeur de config.",
    )

    # Commande menu: lancer le menu interactif
    subparsers.add_parser("menu", help="Lancer le menu interactif")

    # Interface web (Flask)
    parser_web = subparsers.add_parser(
        "web",
        help="Lancer l'interface web (logs en temps réel, authentification requise)",
    )
    parser_web.add_argument("--host", default="0.0.0.0", help="Adresse d'écoute (défaut: 0.0.0.0)")
    parser_web.add_argument("--port", type=int, default=5000, help="Port (défaut: 5000)")
    parser_web.add_argument("--debug", action="store_true", help="Mode debug Flask (déconseillé en prod)")
    parser_web.add_argument(
        "--no-monitor",
        action="store_true",
        help="Panel web uniquement, sans lancer la surveillance en arrière-plan",
    )
    parser_web.add_argument(
        "--scan-interval",
        type=int,
        default=1,
        metavar="SEC",
        help="Intervalle de scan (secondes) pour la surveillance lancée avec le panel (défaut: 1)",
    )

    return parser


def main():
    """
    Point d'entrée principal du programme.
    Parse les arguments de la ligne de commande et exécute la commande demandée.
    """
    parser = build_parser()
    args = parser.parse_args()

    # Auth terminal : obligatoire pour toutes les sous-commandes sauf menu / lancement nu / web
    # (l'interface web s'authentifie dans le navigateur).
    if "--help" not in sys.argv and "-h" not in sys.argv:
        if args.command not in (None, "menu", "web"):
            _require_cli_auth()

    # Router vers la fonction appropriée selon la commande
    if args.command == "setup":
        if args.all:
            if not args.directory:
                raise SystemExit("Erreur: fournissez un dossier. Exemple: setup /tmp/test --all")
            setup_watch_all(args.directory)
        elif args.file:
            if len(args.filenames) != 1:
                raise SystemExit("Erreur: fournissez exactement 1 chemin de fichier. Exemple: setup --file /home/user/test.txt")
            setup_watch_file(args.filenames[0])
    elif args.command == "add":
        add_file(args.filename)
    elif args.command == "rm":
        remove_file(args.filename)
    elif args.command == "remove":
        remove_watch()
    elif args.command == "list":
        list_watch()
    elif args.command == "chmod":
        config = load_config()
        watch_dir = config.get("watch_directory")
        filenames = _ensure_list(config.get("filenames") or config.get("filename"))
        if not watch_dir or not filenames:
            log_and_print(
                "[ERREUR] Aucune surveillance configurée.",
                level="error",
                color=COLOR_RED
            )
        else:
            target = args.filename if args.filename else filenames[0]
            chmod_file(normalize_path(os.path.join(watch_dir, target)), args.mode)
    elif args.command == "monitor":
        # Optionnel: override du probe_interval pour cette exécution
        if args.probe_interval is not None:
            config = load_config()
            config["probe_interval"] = int(args.probe_interval)
            save_config(config)
        start_monitor(scan_interval=args.interval)
    elif args.command == "web":
        import web_app

        web_app.run_web(
            host=args.host,
            port=args.port,
            debug=args.debug,
            start_surveillance=not args.no_monitor,
            scan_interval=args.scan_interval,
        )
    elif args.command == "menu" or args.command is None:
        # Menu interactif par défaut si aucune commande n'est fournie
        interactive_menu()
    else:
        # Afficher l'aide si la commande est invalide
        parser.print_help()


if __name__ == "__main__":
    # Point d'entrée du script
    main()