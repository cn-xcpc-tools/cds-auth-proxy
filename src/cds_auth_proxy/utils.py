import logging

from dotenv import dotenv_values

from .model import AuthConfig, CDSConfig

logger = logging.getLogger(__name__)


def booleanize(value: str | None) -> bool:
    if value is None:
        return False

    falsy = ["no", "n", "0", "false"]
    truly = ["yes", "y", "1", "true"]

    if value.lower() in falsy:
        return False
    elif value.lower() in truly:
        return True
    else:
        raise TypeError("Non boolean-like value {}".format(value))


def load_config() -> CDSConfig:
    """Load configuration from .env file"""

    cfg = dotenv_values(".env", verbose=True)
    logger.info("Loading configuration")

    base_url = cfg.get("BASE_URL")
    username = cfg.get("USERNAME", "")
    password = cfg.get("PASSWORD", "")
    allow_insecure = booleanize(cfg.get("ALLOW_INSECURE", "false"))

    if not base_url:
        logger.warning("BASE_URL not set, running without cds.")
        logger.warning("Use POST /admin/config endpoint to update config and reload teams data from cds.")
        logger.warning("To proxy a stream without cds, use GET /stream endpoint.")
    else:
        logger.info("base_url: %s", base_url)
        logger.info("username: %s", username)
        logger.info("password: %s", "<hidden>")
        logger.info("allow_insecure: %s", allow_insecure)
        if allow_insecure:
            logger.warning("Running with insecure mode enabled. This is not recommended for production use.")
            logger.warning("Use a valid certificate in CDS server for production use.")

    auth = AuthConfig(username=username, password=password) if username else None
    return CDSConfig(base_url=base_url, auth=auth, allow_insecure=allow_insecure)
