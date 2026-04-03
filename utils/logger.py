import os
import logging
from datetime import datetime

# Toujours écrire sous la racine du projet (même chemin que web_app.py lit pour le panel)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(_PROJECT_ROOT, "logs")
LOG_FILE = os.path.join(LOG_DIR, "monitor.log")

os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_CYAN = "\033[96m"


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def color_text(text, color):
    return f"{color}{text}{COLOR_RESET}"


def log_and_print(message, level="info", color=None):
    timestamped = f"[{now_str()}] {message}"

    if color:
        print(color_text(timestamped, color))
    else:
        print(timestamped)

    if level == "warning":
        logging.warning(message)
    elif level == "error":
        logging.error(message)
    else:
        logging.info(message)