from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from granian import Granian
from granian.constants import HTTPModes, Interfaces, Loops, ThreadModes
from granian.http import HTTP1Settings, HTTP2Settings
from granian.log import LogLevels, log_levels_map

from . import __version__
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
@click.option("--http", type=HTTPModes, default=HTTPModes.auto, help="HTTP version")
@click.option("--ws/--no-ws", "websockets", default=True, help="Enable websockets handling")
@click.option("--workers", type=click.IntRange(1), default=1, help="Number of worker processes")
@click.option("--threads", type=click.IntRange(1), default=1, help="Number of threads (per worker)")
@click.option(
    "--blocking-threads",
    type=click.IntRange(1),
    help="Number of blocking threads (per worker)",
)
@click.option(
    "--threading-mode",
    type=ThreadModes,
    default=ThreadModes.workers,
    help="Threading mode to use",
)
@click.option("--loop", type=Loops, default=Loops.auto, help="Event loop implementation")
@click.option(
    "--backlog",
    type=click.IntRange(128),
    default=1024,
    help="Maximum number of connections to hold in backlog (globally)",
)
@click.option(
    "--backpressure",
    type=click.IntRange(1),
    show_default="backlog/workers",
    help="Maximum number of requests to process concurrently (per worker)",
)
@click.option(
    "--http1-buffer-size",
    type=click.IntRange(8192),
    default=HTTP1Settings.max_buffer_size,
    help="Sets the maximum buffer size for HTTP/1 connections",
)
@click.option(
    "--http1-keep-alive/--no-http1-keep-alive",
    default=HTTP1Settings.keep_alive,
    help="Enables or disables HTTP/1 keep-alive",
)
@click.option(
    "--http1-pipeline-flush/--no-http1-pipeline-flush",
    default=HTTP1Settings.pipeline_flush,
    help="Aggregates HTTP/1 flushes to better support pipelined responses (experimental)",
)
@click.option(
    "--http2-adaptive-window/--no-http2-adaptive-window",
    default=HTTP2Settings.adaptive_window,
    help="Sets whether to use an adaptive flow control for HTTP2",
)
@click.option(
    "--http2-initial-connection-window-size",
    type=click.IntRange(1024),
    default=HTTP2Settings.initial_connection_window_size,
    help="Sets the max connection-level flow control for HTTP2",
)
@click.option(
    "--http2-initial-stream-window-size",
    type=click.IntRange(1024),
    default=HTTP2Settings.initial_stream_window_size,
    help="Sets the `SETTINGS_INITIAL_WINDOW_SIZE` option for HTTP2 stream-level flow control",
)
@click.option(
    "--http2-keep-alive-interval",
    type=click.IntRange(1, 60_000),
    default=HTTP2Settings.keep_alive_interval,
    help="Sets an interval (in milliseconds) for HTTP2 Ping frames should be sent to keep a connection alive",
)
@click.option(
    "--http2-keep-alive-timeout",
    type=click.IntRange(1),
    default=HTTP2Settings.keep_alive_timeout,
    help="Sets a timeout (in seconds) for receiving an acknowledgement of the HTTP2 keep-alive ping",
)
@click.option(
    "--http2-max-concurrent-streams",
    type=click.IntRange(10),
    default=HTTP2Settings.max_concurrent_streams,
    help="Sets the SETTINGS_MAX_CONCURRENT_STREAMS option for HTTP2 connections",
)
@click.option(
    "--http2-max-frame-size",
    type=click.IntRange(1024),
    default=HTTP2Settings.max_frame_size,
    help="Sets the maximum frame size to use for HTTP2",
)
@click.option(
    "--http2-max-headers-size",
    type=click.IntRange(1),
    default=HTTP2Settings.max_headers_size,
    help="Sets the max size of received header frames",
)
@click.option(
    "--http2-max-send-buffer-size",
    type=click.IntRange(1024),
    default=HTTP2Settings.max_send_buffer_size,
    help="Set the maximum write buffer size for each HTTP/2 stream",
)
@click.option("--log/--no-log", "log_enabled", default=True, help="Enable logging")
@click.option("--log-level", type=LogLevels, default=LogLevels.info, help="Log level")
@click.option("--access-log/--no-access-log", "log_access_enabled", default=False, help="Enable access log")
@click.option("--access-log-fmt", "log_access_fmt", help="Access log format")
@click.option("--url-path-prefix", help="URL path prefix the app is mounted on")
@click.option(
    "--respawn-failed-workers/--no-respawn-failed-workers",
    default=False,
    help="Enable workers respawn on unexpected exit",
)
@click.option(
    "--respawn-interval",
    default=3.5,
    help="The number of seconds to sleep between workers respawn",
)
@click.option(
    "--workers-lifetime",
    type=click.IntRange(60),
    help="The maximum amount of time in seconds a worker will be kept alive before respawn",
)
@click.option(
    "--workers-kill-timeout",
    type=click.IntRange(1, 1800),
    help="The amount of time in seconds to wait for killing workers that refused to gracefully stop",
    show_default="disabled",
)
@click.option(
    "--factory/--no-factory",
    default=False,
    help="Treat target as a factory function, that should be invoked to build the actual target",
)
@click.option(
    "--process-name",
    help="Set a custom name for processes (requires granian[pname] extra)",
)
@click.option(
    "--pid-file",
    type=click.Path(exists=False, file_okay=True, dir_okay=False, writable=True, path_type=Path),
    help="A path to write the PID file to",
)
@click.version_option(message="%(prog)s %(version)s")
def _run_server(
    host: str,
    port: int,
    http: HTTPModes,
    websockets: bool,
    workers: int,
    threads: int,
    blocking_threads: int,
    threading_mode: ThreadModes,
    loop: Loops,
    backlog: int,
    backpressure: int,
    http1_buffer_size: int,
    http1_keep_alive: bool,
    http1_pipeline_flush: bool,
    http2_adaptive_window: bool,
    http2_initial_connection_window_size: int,
    http2_initial_stream_window_size: int,
    http2_keep_alive_interval: int,
    http2_keep_alive_timeout: int,
    http2_max_concurrent_streams: int,
    http2_max_frame_size: int,
    http2_max_headers_size: int,
    http2_max_send_buffer_size: int,
    log_enabled: bool,
    log_level: LogLevels,
    log_access_enabled: bool,
    log_access_fmt: str,
    url_path_prefix: str,
    respawn_failed_workers: bool,
    respawn_interval: float,
    workers_lifetime: int,
    workers_kill_timeout: int,
    factory: bool,
    process_name: str,
    pid_file: Path,
) -> None:
    log_dictconfig = deepcopy(LOGGING_CONFIG)
    if log_level != LogLevels.notset:
        log_dictconfig["loggers"]["_granian"]["level"] = log_levels_map[log_level]  # type: ignore
        log_dictconfig["loggers"]["granian.access"]["level"] = log_levels_map[log_level]  # type: ignore
        log_dictconfig["loggers"]["httpx"]["level"] = log_levels_map[log_level]  # type: ignore
        log_dictconfig["loggers"]["httpcore"]["level"] = log_levels_map[log_level]  # type: ignore
        log_dictconfig["loggers"]["app"]["level"] = log_levels_map[log_level]  # type: ignore
    Granian(
        target="app.app:app",
        address=host,
        port=port,
        interface=Interfaces.ASGI,
        log_dictconfig=log_dictconfig,
        ssl_cert=Path("certs/cert.pem"),
        ssl_key=Path("certs/key.pem"),
        http=http,
        websockets=websockets,
        workers=workers,
        threads=threads,
        blocking_threads=blocking_threads,
        threading_mode=threading_mode,
        loop=loop,
        backlog=backlog,
        backpressure=backpressure,
        http1_settings=HTTP1Settings(
            max_buffer_size=http1_buffer_size,
            keep_alive=http1_keep_alive,
            pipeline_flush=http1_pipeline_flush,
        ),
        http2_settings=HTTP2Settings(
            adaptive_window=http2_adaptive_window,
            initial_connection_window_size=http2_initial_connection_window_size,
            initial_stream_window_size=http2_initial_stream_window_size,
            keep_alive_interval=http2_keep_alive_interval,
            keep_alive_timeout=http2_keep_alive_timeout,
            max_concurrent_streams=http2_max_concurrent_streams,
            max_frame_size=http2_max_frame_size,
            max_headers_size=http2_max_headers_size,
            max_send_buffer_size=http2_max_send_buffer_size,
        ),
        log_enabled=log_enabled,
        log_level=log_level,
        log_access=log_access_enabled,
        log_access_format=log_access_fmt,
        url_path_prefix=url_path_prefix,
        respawn_failed_workers=respawn_failed_workers,
        respawn_interval=respawn_interval,
        workers_lifetime=workers_lifetime,
        workers_kill_timeout=workers_kill_timeout,
        factory=factory,
        process_name=process_name,
        pid_file=pid_file,
    ).serve()


def entrypoint() -> None:
    _print_banner()
    _generate_certificate()
    _run_server()
