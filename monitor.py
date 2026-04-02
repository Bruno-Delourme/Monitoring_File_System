#!/usr/bin/env python3
"""
Script de surveillance de fichiers système.
Surveille un fichier spécifique dans un dossier donné et alerte en cas de modification.
"""

# Imports standard
import os
import json
import time
import argparse

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


def get_monitored_file_path():
    """
    Construit et retourne le chemin complet du fichier surveillé.
    
    Returns:
        str or None: Chemin absolu normalisé du fichier surveillé,
                     ou None si la configuration n'est pas complète.
    """
    config = load_config()
    watch_dir = config.get("watch_directory")
    filename = config.get("filename")
    
    # Vérifier que la configuration contient les informations nécessaires
    if not watch_dir or not filename:
        return None
    
    # Normaliser le chemin du dossier et construire le chemin complet
    watch_dir = normalize_path(watch_dir)
    file_path = os.path.join(watch_dir, filename)
    return normalize_path(file_path)


def setup_watch(watch_directory, filename):
    """
    Configure la surveillance d'un fichier dans un dossier spécifique.
    Le fichier sera surveillé dès qu'il apparaît dans le dossier.
    
    Args:
        watch_directory (str): Chemin du dossier à surveiller.
        filename (str): Nom du fichier à détecter et surveiller.
    """
    # Normaliser le chemin du dossier
    watch_directory = normalize_path(watch_directory)
    config = load_config()

    # Vérifier que le dossier existe
    if not os.path.isdir(watch_directory):
        log_and_print(
            f"[ERREUR] Le dossier n'existe pas : {watch_directory}",
            level="error",
            color=COLOR_RED
        )
        return

    # Enregistrer la configuration de surveillance
    config["watch_directory"] = watch_directory
    config["filename"] = filename
    config["file_metadata"] = None  # Sera rempli quand le fichier sera détecté
    save_config(config)

    file_path = os.path.join(watch_directory, filename)
    log_and_print(
        f"[+] Surveillance configurée : dossier '{watch_directory}' pour le fichier '{filename}'",
        color=COLOR_GREEN
    )
    
    # Si le fichier existe déjà, capturer ses métadonnées immédiatement
    if os.path.exists(file_path):
        file_path = normalize_path(file_path)
        config["file_metadata"] = get_file_metadata(file_path)
        save_config(config)
        log_and_print(
            f"[INFO] Le fichier existe déjà et est maintenant surveillé : {file_path}",
            color=COLOR_CYAN
        )


def remove_watch():
    """
    Supprime complètement la configuration de surveillance.
    Réinitialise le fichier de configuration à un état vide.
    """
    config = load_config()

    # Vérifier qu'une configuration existe
    if "watch_directory" not in config:
        log_and_print("[INFO] Aucune surveillance configurée.", color=COLOR_YELLOW)
        return

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


def list_watch():
    """
    Affiche la configuration de surveillance actuelle et le statut du fichier.
    Affiche les métadonnées si le fichier est présent et surveillé.
    """
    config = load_config()

    # Vérifier qu'une configuration existe
    if "watch_directory" not in config:
        print("Aucune surveillance configurée.")
        return

    # Récupérer les informations de configuration
    watch_dir = config.get("watch_directory")
    filename = config.get("filename")
    file_path = os.path.join(watch_dir, filename)
    file_path = normalize_path(file_path)
    
    # Afficher la configuration
    print("\n=== Configuration de surveillance ===")
    print(f"Dossier surveillé : {watch_dir}")
    print(f"Fichier recherché : {filename}")
    print(f"Chemin complet : {file_path}")
    
    # Afficher le statut et les métadonnées si le fichier existe
    if os.path.exists(file_path):
        meta = config.get("file_metadata")
        if meta:
            # Fichier présent avec métadonnées enregistrées
            print(f"Statut : présent et surveillé")
            print(f"  - Permissions : {_describe_permissions(meta.get('mode'))}")
            print(f"  - Propriétaire : {meta.get('uid', 'N/A')}:{meta.get('gid', 'N/A')}")
            print(f"  - Dernière modification : {meta.get('mtime', 'N/A')}")
        else:
            # Fichier présent mais métadonnées pas encore chargées
            print("Statut : présent (métadonnées en cours de chargement)")
    else:
        # Fichier absent, en attente de son apparition
        print("Statut : absent (en attente de l'apparition du fichier)")


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
        return

    try:
        # Convertir la chaîne octale en entier (base 8)
        mode = int(mode_str, 8)
        # Appliquer les nouvelles permissions
        os.chmod(path, mode)
        log_and_print(f"[ADMIN] Permissions modifiées : {path} -> {mode_str}", color=COLOR_CYAN)
    except ValueError:
        # Erreur si le format du mode est invalide
        log_and_print(
            "[ERREUR] Mode invalide. Utilise une valeur octale comme 644, 600, 755.",
            level="error",
            color=COLOR_RED
        )
    except PermissionError:
        # Erreur si l'utilisateur n'a pas les droits
        log_and_print(
            f"[ERREUR] Permission refusée pour modifier {path}. Essaie avec sudo.",
            level="error",
            color=COLOR_RED
        )
    except OSError as e:
        # Autre erreur système
        log_and_print(f"[ERREUR] chmod impossible : {e}", level="error", color=COLOR_RED)


class MonitorHandler(FileSystemEventHandler):
    """
    Gestionnaire d'événements pour la surveillance du système de fichiers.
    Hérite de FileSystemEventHandler pour intercepter les événements watchdog.
    """
    
    def __init__(self):
        """Initialise le handler et charge la configuration."""
        self.watch_directory = None  # Dossier surveillé
        self.filename = None  # Nom du fichier recherché
        self.monitored_file_path = None  # Chemin complet du fichier surveillé
        self._load_config()

    def _load_config(self):
        """
        Charge la configuration de surveillance depuis le fichier JSON.
        Construit le chemin complet du fichier à surveiller.
        """
        config = load_config()
        self.watch_directory = normalize_path(config.get("watch_directory", ""))
        self.filename = config.get("filename", "")
        
        # Construire le chemin complet si la configuration est valide
        if self.watch_directory and self.filename:
            self.monitored_file_path = normalize_path(
                os.path.join(self.watch_directory, self.filename)
            )
        else:
            self.monitored_file_path = None

    def _is_monitored_file(self, path):
        """
        Vérifie si le chemin correspond au fichier surveillé.
        
        Args:
            path (str): Chemin à vérifier.
            
        Returns:
            bool: True si le chemin correspond au fichier surveillé, False sinon.
        """
        if not self.monitored_file_path:
            return False
        # Comparer les chemins normalisés pour éviter les problèmes de format
        return normalize_path(path) == self.monitored_file_path

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
        old = config.get("file_metadata")  # Métadonnées précédentes
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

        # Si des changements ont été détectés, alerter et mettre à jour la config
        if changes:
            log_and_print(
                f"[ALERTE] Modification détectée sur : {path}",
                level="warning",
                color=COLOR_RED
            )

            # Afficher chaque changement détecté
            for change in changes:
                log_and_print(f" - {change}", level="warning", color=COLOR_YELLOW)

            # Afficher l'ancien et le nouvel état pour comparaison
            if old:
                log_and_print(f" - Ancien état : {old}", level="warning")
            log_and_print(f" - Nouvel état : {new}", level="warning")

            # Sauvegarder les nouvelles métadonnées
            config["file_metadata"] = new
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
    filename = config.get("filename")

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
        f"[WATCH] Fichier recherché : {filename}",
        color=COLOR_CYAN
    )

    # Démarrer l'observer
    observer.start()
    log_and_print("Surveillance en cours... Ctrl+C pour arrêter.", color=COLOR_GREEN)

    try:
        # Boucle principale : scan périodique complémentaire
        while True:
            time.sleep(scan_interval)

            # Vérification périodique du fichier (complémentaire à watchdog)
            # Cela permet de détecter les changements même si watchdog rate un événement
            monitored_file_path = get_monitored_file_path()
            if monitored_file_path and os.path.exists(monitored_file_path):
                handler.compare_and_alert(monitored_file_path)

    except KeyboardInterrupt:
        # Arrêt propre lors de Ctrl+C
        log_and_print("Arrêt de la surveillance...", color=COLOR_YELLOW)
        observer.stop()

    # Attendre que l'observer se termine proprement
    observer.join()


def interactive_menu():
    """
    Menu interactif pour configurer et utiliser la surveillance.
    Permet de configurer, lister, modifier et lancer la surveillance via une interface texte.
    """
    while True:
        # Afficher le menu principal
        print("\n=== FILE SYSTEM MONITOR ===")
        print("1. Configurer la surveillance (dossier + nom de fichier)")
        print("2. Supprimer la configuration de surveillance")
        print("3. Afficher la configuration actuelle")
        print("4. Modifier les permissions du fichier surveillé")
        print("5. Lancer la surveillance")
        print("6. Quitter")

        choice = input("Choix : ").strip()

        # Option 1: Configuration de la surveillance
        if choice == "1":
            watch_dir = input("Dossier à surveiller : ").strip()
            filename = input("Nom du fichier à surveiller : ").strip()
            setup_watch(watch_dir, filename)

        # Option 2: Suppression de la configuration
        elif choice == "2":
            remove_watch()

        # Option 3: Affichage de la configuration
        elif choice == "3":
            list_watch()

        # Option 4: Modification des permissions
        elif choice == "4":
            file_path = get_monitored_file_path()
            if not file_path:
                log_and_print(
                    "[ERREUR] Aucune surveillance configurée.",
                    level="error",
                    color=COLOR_RED
                )
            else:
                mode = input("Nouvelles permissions (ex: 644, 600, 755) : ").strip()
                chmod_file(file_path, mode)

        # Option 5: Lancement de la surveillance
        elif choice == "5":
            interval_raw = input("Intervalle de scan en secondes (défaut 1) : ").strip()
            try:
                interval = int(interval_raw) if interval_raw else 1
            except ValueError:
                # Valeur par défaut si l'entrée est invalide
                interval = 1
            start_monitor(scan_interval=interval)

        # Option 6: Quitter
        elif choice == "6":
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
        help="Configurer la surveillance (dossier + nom de fichier)"
    )
    parser_setup.add_argument("directory", help="Dossier à surveiller")
    parser_setup.add_argument("filename", help="Nom du fichier à surveiller")

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

    # Commande monitor: lancer la surveillance
    parser_monitor = subparsers.add_parser("monitor", help="Lancer la surveillance")
    parser_monitor.add_argument(
        "--interval",
        type=int,
        default=1,
        help="Intervalle de scan complémentaire en secondes (défaut: 1)"
    )

    # Commande menu: lancer le menu interactif
    subparsers.add_parser("menu", help="Lancer le menu interactif")

    return parser


def main():
    """
    Point d'entrée principal du programme.
    Parse les arguments de la ligne de commande et exécute la commande demandée.
    """
    parser = build_parser()
    args = parser.parse_args()

    # Router vers la fonction appropriée selon la commande
    if args.command == "setup":
        setup_watch(args.directory, args.filename)
    elif args.command == "remove":
        remove_watch()
    elif args.command == "list":
        list_watch()
    elif args.command == "chmod":
        file_path = get_monitored_file_path()
        if not file_path:
            log_and_print(
                "[ERREUR] Aucune surveillance configurée.",
                level="error",
                color=COLOR_RED
            )
        else:
            chmod_file(file_path, args.mode)
    elif args.command == "monitor":
        start_monitor(scan_interval=args.interval)
    elif args.command == "menu" or args.command is None:
        # Menu interactif par défaut si aucune commande n'est fournie
        interactive_menu()
    else:
        # Afficher l'aide si la commande est invalide
        parser.print_help()


if __name__ == "__main__":
    # Point d'entrée du script
    main()