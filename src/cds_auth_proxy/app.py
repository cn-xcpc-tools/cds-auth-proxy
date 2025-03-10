import asyncio
import logging
import logging.config
from contextlib import asynccontextmanager
from http import HTTPStatus
from typing import Annotated, AsyncGenerator
from urllib.parse import urljoin

from fastapi import FastAPI, HTTPException, Path, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, StreamingResponse
from httpx import AsyncClient, BasicAuth, HTTPError
from pydantic import HttpUrl
from starlette.background import BackgroundTask

from ._version import __version__
from .model import AuthConfig, CDSConfig, StreamInfo, StreamType, Team
from .utils import load_config

# Initialize logging configuration
logger = logging.getLogger(__name__)


teams: dict[str, Team] = {}
cds_config = CDSConfig()
teams_lock = asyncio.Lock()
cds_config_lock = asyncio.Lock()


def _get_basic_auth(auth_config: AuthConfig | None) -> BasicAuth | None:
    if not auth_config:
        return None
    return BasicAuth(auth_config.username, auth_config.password.get_secret_value())


async def load_teams_data(cfg: CDSConfig) -> dict[str, Team]:
    """
    Fetch and update teams data from the remote server
    """
    if not cfg.base_url:
        return {}

    # Fetch new data first before acquiring lock
    teams: dict[str, Team] = {}
    async with AsyncClient(auth=_get_basic_auth(cfg.auth), verify=not cfg.allow_insecure, timeout=None) as client:
        try:
            response = await client.get(urljoin(str(cfg.base_url), "teams"))
            if response.status_code != HTTPStatus.OK:
                raise HTTPException(response.status_code, detail=response.text)

            data = response.json()

            for team in data:
                teams[team["id"]] = Team(**team)

            logger.info("Teams data updated, total teams = %d", len(teams))
            for team in teams.values():
                logger.debug(
                    "Team %s: desktop=%d, webcam=%d, audio=%d",
                    team.id,
                    len(team.desktop or []),
                    len(team.webcam or []),
                    len(team.audio or []),
                )
        except HTTPError as e:
            raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=f"Failed to fetch teams data: {str(e)}")

    return teams


async def _get_stream_url(team_id: str, stream_type: StreamType, index: int) -> HttpUrl:
    """
    Get the stream URL for a specific team and stream type
    """
    async with teams_lock:
        if team_id not in teams:
            raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Team not found")

        team = teams[team_id]
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


async def _proxy_stream(
    req: Request, url: HttpUrl, auth_config: AuthConfig | None, allow_insecure: bool = False
) -> StreamingResponse:
    """
    Proxy the stream from the remote server with authentication
    """
    # Constants for header filtering
    hop_by_hop_headers = {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }

    client = AsyncClient(auth=_get_basic_auth(auth_config), verify=not allow_insecure, timeout=None)
    logger.info("Proxying stream: %s", url)

    try:
        response = await client.send(
            client.build_request("GET", str(url), headers=req.headers),
            stream=True,
        )
        if response.status_code != HTTPStatus.OK:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"HTTP {response.status_code} {response.reason_phrase}",
            )
        return StreamingResponse(
            response.aiter_bytes(),
            headers={k: v for k, v in response.headers.items() if k.lower() not in hop_by_hop_headers},
            media_type=response.headers.get("content-type", "application/octet-stream"),
            background=BackgroundTask(client.aclose),
        )
    except HTTPError as e:
        await client.aclose()
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail=f"Failed to proxy stream: {str(e)}",
        )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Update teams data on startup
    """
    global cds_config, teams
    try:
        async with cds_config_lock, teams_lock:
            cds_config = load_config()
            teams = await load_teams_data(cds_config)
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
    async with cds_config_lock:
        return cds_config


@app.post(
    "/admin/config",
    tags=["Admin"],
    summary="Update config and reload the teams data from the remote server",
    status_code=HTTPStatus.NO_CONTENT,
)
async def update_config(config: CDSConfig) -> None:
    global cds_config
    # Update config first
    async with cds_config_lock:
        cds_config = config
    # Then load teams with updated config
    async with teams_lock:
        new_teams = await load_teams_data(cds_config)
        teams.clear()
        teams.update(new_teams)


@app.get("/teams", response_model=list[Team], tags=["Teams"], summary="Get all teams")
async def get_teams() -> list[Team]:
    async with teams_lock:
        return list(teams.values())


@app.get("/teams/{id}", response_model=Team, tags=["Teams"], summary="Get the given team")
async def get_team(
    team_id: Annotated[str, Path(title="Team ID", alias="id", description="The ID of the entity")],
) -> Team:
    async with teams_lock:
        if team_id not in teams:
            raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Team not found")
        return teams[team_id]


@app.get(
    "/teams/{id}/{type}",
    tags=["Teams"],
    summary="Get stream for the given team and stream type",
)
async def get_stream(
    req: Request,
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
    url = await _get_stream_url(team_id, stream_type, index)
    return await _proxy_stream(req, url, cds_config.auth, cds_config.allow_insecure)


@app.get("/stream", tags=["Stream"], summary="Proxy the given URL with authentication")
async def proxy_stream(
    req: Request,
    url: Annotated[HttpUrl, Query(title="Stream URL", description="The URL of the stream")],
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
    auth = AuthConfig(username=username, password=password) if username else None
    return await _proxy_stream(req, url, auth, allow_insecure)
