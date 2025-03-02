LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "default": {"class": "rich.logging.RichHandler", "show_time": True, "show_path": True, "rich_tracebacks": True}
    },
    "loggers": {
        "_granian": {"level": "INFO", "handlers": ["default"], "propagate": False},
        "granian.access": {"level": "INFO", "handlers": ["default"], "propagate": False},
        "httpx": {"level": "INFO", "handlers": ["default"]},
        "httpcore": {"level": "INFO", "handlers": ["default"]},
        "app": {"level": "INFO", "handlers": ["default"], "propagate": False},
    },
}
