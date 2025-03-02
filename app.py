import logging
import os
import pathlib
import sys
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from http import HTTPStatus
from typing import Annotated, NoReturn
from urllib.parse import urljoin

import aiohttp
from dotenv import dotenv_values
from fastapi import FastAPI, HTTPException, Path, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, StreamingResponse
from pydantic import BaseModel, HttpUrl, SecretStr
from starlette.background import BackgroundTask

__version__ = "0.1.0"

logger = logging.getLogger(__name__)


class CDSConfig(BaseModel):
    base_url: HttpUrl | None = None
    username: str | None = None
    password: SecretStr | None = None
    allow_insecure: bool = False


def load_config() -> CDSConfig:
    """Load configuration from .env file"""

    def booleanize(value) -> bool:
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

    cfg = dotenv_values(".env", verbose=True)
    logger.info("Loading configuration")

    base_url = cfg.get("BASE_URL")
    username = cfg.get("USERNAME")
    password = cfg.get("PASSWORD")
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

    return CDSConfig(base_url=base_url, username=username, password=password, allow_insecure=allow_insecure)


class StreamType(StrEnum):
    desktop = "desktop"
    webcam = "webcam"
    audio = "audio"


# Data models
class StreamInfo(BaseModel):
    href: HttpUrl
    mime: str


class Team(BaseModel):
    id: str
    desktop: list[StreamInfo] | None = None
    webcam: list[StreamInfo] | None = None
    audio: list[StreamInfo] | None = None


# Store for team data
teams_data: dict[str, Team] = {}
cds_config = load_config()


async def update_teams_data() -> None:
    """
    Fetch and update teams data from the remote server
    """
    if not cds_config.base_url:
        return
    auth = aiohttp.BasicAuth(cds_config.username, cds_config.password.get_secret_value()) if cds_config.username else None
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(
                urljoin(str(cds_config.base_url), "teams"),
                auth=auth,
                ssl=(not cds_config.allow_insecure),
            ) as response:
                if response.status != 200:
                    raise HTTPException(status_code=response.status, detail=f"Failed to fetch teams data: {response.reason}")

                data = await response.json()

                # Clear existing data
                teams_data.clear()

                # Update with new data
                for team in data:
                    teams_data[team["id"]] = Team(**team)
                logger.info("Teams data updated, total teams = %d", len(teams_data))
                for team in teams_data.values():
                    logger.debug(
                        "Team %s: desktop=%d, webcam=%d, audio=%d",
                        team.id,
                        len(team.desktop or []),
                        len(team.webcam or []),
                        len(team.audio or []),
                    )

        except aiohttp.ClientError as e:
            raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=f"Failed to fetch teams data: {str(e)}")


def _get_stream_url(team_id: str, stream_type: StreamType, index: int) -> str:
    """
    Get the stream URL for a specific team and stream type
    """
    if team_id not in teams_data:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Team not found")

    team = teams_data[team_id]
    streams: list[StreamInfo] | None = getattr(team, stream_type)

    if not streams:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"No {stream_type} stream found for team",
        )

    if 0 <= index < len(streams):
        return streams[index].href
    raise HTTPException(
        status_code=HTTPStatus.NOT_FOUND,
        detail=f"Stream {index} not found for team",
    )


async def _proxy_stream(url: str, username: str = "", password: str = "", allow_insecure: bool = False) -> StreamingResponse:
    """
    Proxy the stream from the remote server with authentication
    """
    logger.info("Proxying stream %s", url)

    session = None
    response = None

    async def cleanup():
        nonlocal session, response
        if response:
            response.close()
        if session:
            await session.close()

    try:
        session = aiohttp.ClientSession()
        auth = aiohttp.BasicAuth(username, password) if username else None
        response = await session.get(
            url,
            auth=auth,
            ssl=(not allow_insecure),
            timeout=None,
        )

        if response.status != HTTPStatus.OK:
            await cleanup()
            raise HTTPException(status_code=response.status, detail="Failed to fetch stream")

        return StreamingResponse(
            response.content.iter_any(),
            media_type=response.headers.get("content-type"),
            background=BackgroundTask(cleanup),
        )
    except aiohttp.ClientError as e:
        await cleanup()
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail=f"Failed to proxy stream: {str(e)}",
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Update teams data on startup
    """

    try:
        await update_teams_data()
        logger.info("Teams data updated")
    except HTTPException as e:
        logger.error(f"Failed to initialize teams data: {e}")
    yield


app = FastAPI(title="CDS Auth Proxy", lifespan=lifespan, version=__version__)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", include_in_schema=False)
async def docs_redirect() -> RedirectResponse:
    return RedirectResponse("/docs")


@app.get("/admin/config", tags=["Admin"], summary="Get the current config")
async def get_config() -> CDSConfig:
    return cds_config


@app.post(
    "/admin/config",
    tags=["Admin"],
    summary="Update config and reload the teams data from the remote server",
    status_code=HTTPStatus.NO_CONTENT,
)
async def update_config(config: CDSConfig) -> None:
    global cds_config
    cds_config = config
    await update_teams_data()


@app.get("/teams", response_model=list[Team], tags=["Teams"], summary="Get all teams")
async def get_teams() -> list[Team]:
    return list(teams_data.values())


@app.get("/teams/{id}", response_model=Team, tags=["Teams"], summary="Get the given team")
async def get_team(
    team_id: Annotated[str, Path(title="Team ID", alias="id", description="The ID of the entity")],
) -> Team:
    if team_id not in teams_data:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Team not found")

    return teams_data[team_id]


@app.get(
    "/teams/{id}/{type}",
    tags=["Teams"],
    summary="Get stream for the given team and stream type",
)
async def get_stream(
    team_id: Annotated[str, Path(title="Team ID", alias="id", description="The ID of the entity")],
    stream_type: Annotated[
        StreamType,
        Path(title="Stream Type", alias="type", description="The type of the stream"),
    ],
    index: Annotated[
        int,
        Query(
            title="Stream ID",
            alias="index",
            description="Stream index when multiple streams are available",
            ge=0,
        ),
    ] = 0,
) -> StreamingResponse:
    url = _get_stream_url(team_id, stream_type, index)
    return await _proxy_stream(url, cds_config.username, cds_config.password.get_secret_value(), cds_config.allow_insecure)


@app.get("/stream", tags=["Stream"], summary="Proxy the given URL with authentication")
async def proxy_stream(
    url: Annotated[str, Query(title="Stream URL", description="The URL of the stream")],
    username: Annotated[str, Query(title="Username", description="The username for authentication")] = "",
    password: Annotated[str, Query(title="Password", description="The password for authentication")] = "",
    allow_insecure: Annotated[
        bool,
        Query(
            title="Allow Insecure",
            description="Allow insecure connections",
        ),
    ] = False,
) -> StreamingResponse:
    return await _proxy_stream(url, username, password, allow_insecure)


def _print_banner() -> None:
    print(f"""\
╔════════════════════════════════════════════════╗
║ Contest Data Server Media Authentication Proxy ║
║ Version {__version__:<38} ║
║ Licensed under the MIT License                 ║
╚════════════════════════════════════════════════╝
""")


def _generate_certificate() -> None:
    certs_dir = pathlib.Path("certs")
    certs_dir.mkdir(exist_ok=True)
    if (certs_dir / "key.pem").exists():
        print("key.pem already exists, skipping certificate generation.")
        print()
        return

    print("Generating self-signed certificate...")
    print("For production use, please use a valid certificate.")
    print()

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

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


def _run_server(argv: list[str] | None = None) -> NoReturn:
    if argv is None:
        argv = sys.argv[1:]

    ssl_cert = pathlib.Path("certs/cert.pem")
    ssl_key = pathlib.Path("certs/key.pem")
    log_config = pathlib.Path("config/logconfig.json")

    from granian.cli import cli

    cli.main(
        [
            "--interface",
            "asgi",
            "app:app",
            "--ssl-certificate",
            ssl_cert.as_posix(),
            "--ssl-keyfile",
            ssl_key.as_posix(),
            "--log-config",
            log_config.as_posix(),
        ]
        + argv
    )


if __name__ == "__main__":
    script_dir = pathlib.Path(__file__).parent.absolute()
    os.chdir(script_dir)

    _print_banner()
    _generate_certificate()
    _run_server(sys.argv[1:])
