import logging
import os
from datetime import datetime

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# nome do arquivo de log com timestamp do dia
log_filename = f"{LOG_DIR}/sentinel_{datetime.now().strftime('%Y%m%d')}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(log_filename, encoding="utf-8"),
        logging.StreamHandler(),  # continua aparecendo no terminal
    ],
)

def get_logger(name: str) -> logging.Logger:
    """
    Retorna logger nomeado por módulo.
    Uso: logger = get_logger(__name__)
    """
    return logging.getLogger(name)