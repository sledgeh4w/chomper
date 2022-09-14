import logging
from typing import Optional

default_handler = logging.StreamHandler()
default_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(name)s - %(levelname)s: %(message)s")
)


def get_logger(name: Optional[str] = None, level: int = logging.INFO) -> logging.Logger:
    """Get default logger."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(default_handler)
    return logger
