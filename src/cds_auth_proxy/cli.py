from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from granian import Granian
from granian.constants import HTTPModes, Interfaces
from granian.log import LogLevels, log_levels_map

from ._version import __version__
from .constants import LOGGING_CONFIG


def _print_banner() -> None:
    print(f"""\
╔════════════════════════════════════════════════╗
║ Contest Data Server Media Authentication Proxy ║
║ Version {__version__:<38} ║
║ Licensed under the MIT License                 ║
╚════════════════════════════════════════════════╝
""")


def _generate_certificate() -> None:
    certs_dir = Path("certs")
    certs_dir.mkdir(exist_ok=True)
    if (certs_dir / "key.pem").exists():
        print("key.pem already exists, skipping certificate generation.")
        print()
        return

    print("Generating self-signed certificate...")
    print("For production use, please use a valid certificate.")
    print()

    # Generate EC private key using NIST P-256 curve (prime256v1)
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Generate certificate
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    # Write certificate and private key to certs directory
    (certs_dir / "key.pem").write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (certs_dir / "key.pem").chmod(0o600)
    (certs_dir / "cert.pem").write_bytes(cert.public_bytes(encoding=serialization.Encoding.PEM))


@click.command()
@click.option(
    "--host",
    default="127.0.0.1",
    help="Host address to bind to",
)
@click.option("--port", type=int, default=8000, help="Port to bind to.")
@click.option("--ssl-cert", type=Path, help="Path to SSL certificate")
@click.option("--ssl-key", type=Path, help="Path to SSL private key")
@click.option("--http", type=HTTPModes, default=HTTPModes.auto, help="HTTP version")
@click.option("--log/--no-log", "log_enabled", default=True, help="Enable logging")
@click.option("--log-level", type=LogLevels, default=LogLevels.info, help="Log level")
@click.option("--access-log/--no-access-log", "log_access_enabled", default=False, help="Enable access log")
@click.option("--access-log-fmt", "log_access_fmt", help="Access log format")
@click.option("--url-path-prefix", help="URL path prefix the app is mounted on")
@click.version_option(message="%(prog)s %(version)s")
def _run_server(
    host: str,
    port: int,
    http: HTTPModes,
    ssl_cert: Path,
    ssl_key: Path,
    log_enabled: bool,
    log_level: LogLevels,
    log_access_enabled: bool,
    log_access_fmt: str,
    url_path_prefix: str,
) -> None:
    _print_banner()

    log_dictconfig = deepcopy(LOGGING_CONFIG)
    if log_level != LogLevels.notset:
        log_dictconfig["loggers"]["root"]["level"] = log_levels_map[log_level]  # type: ignore

    if ssl_key is None or ssl_cert is None:
        ssl_key = Path("certs/key.pem")
        ssl_cert = Path("certs/cert.pem")
        _generate_certificate()

    Granian(
        target=f"{__package__}.app:app",
        address=host,
        port=port,
        interface=Interfaces.ASGI,
        log_dictconfig=log_dictconfig,
        ssl_cert=ssl_cert,
        ssl_key=ssl_key,
        http=http,
        log_enabled=log_enabled,
        log_level=log_level,
        log_access=log_access_enabled,
        log_access_format=log_access_fmt,
        url_path_prefix=url_path_prefix,
    ).serve()


def entrypoint() -> None:
    _run_server()
