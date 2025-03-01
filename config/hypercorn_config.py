import logging

bind = ["0.0.0.0:5283"]

keyfile = "key.pem"
certfile = "cert.pem"

accesslog = logging.getLogger("hypercorn.access")
errorlog = logging.getLogger("hypercorn.error")
