LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "default": {"class": "rich.logging.RichHandler", "show_time": True, "show_path": True, "rich_tracebacks": True}
    },
    "loggers": {
        "root": {"level": "INFO", "handlers": ["default"]},
    },
}
