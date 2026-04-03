"""
Authentification CLI désactivée pour les tests (identifiants valides en variables d'environnement).
"""
import os

os.environ.setdefault("FSM_USERNAME", "Laurent")
os.environ.setdefault("FSM_PASSWORD", "motdepasse123!!")
