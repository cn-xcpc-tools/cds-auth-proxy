import asyncio
import logging
from contextlib import asynccontextmanager
from http import HTTPStatus
from typing import Annotated, AsyncGenerator

from fastapi import FastAPI, HTTPException, Path, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, StreamingResponse
from httpx import AsyncClient, BasicAuth, HTTPError, HTTPStatusError
from pydantic import HttpUrl

from ._version import __version__
from .model import AuthConfig, CDSConfig, StreamInfo, StreamType, Team

logger = logging.getLogger(__name__)


class ConfigManager:
    def __init__(self):
        self.config = CDSConfig()
        self._lock = asyncio.Lock()

    async def update(self, new_config: CDSConfig) -> None:
        async with self._lock:
            self.config = new_config

    async def get(self) -> CDSConfig:
        async with self._lock:
            return self.config


class TeamManager:
    def __init__(self):
        self.teams: dict[str, Team] = {}
        self._lock = asyncio.Lock()

    async def update(self, teams_data: dict[str, Team]) -> None:
        async with self._lock:
            self.teams.clear()
            self.teams.update(teams_data)

    async def get_team(self, team_id: str) -> Team:
        async with self._lock:
            if team_id not in self.teams:
                raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Team not found")
            return self.teams[team_id]

    async def get_all_teams(self) -> list[Team]:
        async with self._lock:
            return list(self.teams.values())


class StreamService:
    def __init__(self, team_manager: TeamManager):
        self.team_manager = team_manager

    async def get_stream_url(self, team_id: str, stream_type: StreamType, index: int) -> HttpUrl:
        team = await self.team_manager.get_team(team_id)
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


class ProxyHandler:
    HOP_BY_HOP_HEADERS = {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }

    @staticmethod
    def _get_basic_auth(auth_config: AuthConfig | None) -> BasicAuth | None:
        if not auth_config:
            return None
        return BasicAuth(auth_config.username, auth_config.password.get_secret_value())

    async def proxy_stream(
        self, req: Request, url: HttpUrl, auth_config: AuthConfig | None, allow_insecure: bool = False
    ) -> StreamingResponse:
        client = AsyncClient(auth=self._get_basic_auth(auth_config), verify=not allow_insecure, timeout=None)
        logger.info("Proxying stream: %s", url)

        try:
            response = await client.send(
                client.build_request("GET", str(url), headers=req.headers),
                stream=True,
            )
            response.raise_for_status()
            return StreamingResponse(
                response.aiter_bytes(),
                headers={k: v for k, v in response.headers.items() if k.lower() not in self.HOP_BY_HOP_HEADERS},
                media_type=response.headers.get("content-type", "application/octet-stream"),
                background=client.aclose,
            )
        except HTTPStatusError as e:
            await client.aclose()
            raise HTTPException(
                status_code=e.response.status_code,
                detail=f"Failed to proxy stream: {e.response.text}",
            )
        except HTTPError as e:
            await client.aclose()
            raise HTTPException(
                status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                detail=f"Failed to proxy stream: {str(e)}",
            )


async def fetch_teams_data(cfg: CDSConfig) -> dict[str, Team]:
    if not cfg.base_url:
        return {}

    async with AsyncClient(
        base_url=cfg.base_url, auth=ProxyHandler._get_basic_auth(cfg.auth), verify=not cfg.allow_insecure, timeout=None
    ) as client:
        try:
            response = await client.get("/teams")
            response.raise_for_status()

            teams_data = {team["id"]: Team(**team) for team in response.json()}

            logger.info("Teams data updated, total teams = %d", len(teams_data))
            for team in teams_data.values():
                logger.debug(
                    "Team %s: desktop=%d, webcam=%d, audio=%d",
                    team.id,
                    len(team.desktop or []),
                    len(team.webcam or []),
                    len(team.audio or []),
                )
            return teams_data

        except HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=f"Failed to fetch teams data: {e.response.text}")

        except HTTPError as e:
            raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=f"Failed to fetch teams data: {str(e)}")


# Application state
config_manager = ConfigManager()
team_manager = TeamManager()
stream_service = StreamService(team_manager)
proxy_handler = ProxyHandler()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Initialize application state on startup"""
    try:
        from .utils import load_config

        await config_manager.update(load_config())
        teams_data = await fetch_teams_data(await config_manager.get())
        await team_manager.update(teams_data)
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
    return await config_manager.get()


@app.post(
    "/admin/config",
    tags=["Admin"],
    summary="Update config and reload the teams data from the remote server",
    status_code=HTTPStatus.NO_CONTENT,
)
async def update_config(config: CDSConfig) -> None:
    await config_manager.update(config)
    teams_data = await fetch_teams_data(config)
    await team_manager.update(teams_data)


@app.get("/teams", response_model=list[Team], tags=["Teams"], summary="Get all teams")
async def get_teams() -> list[Team]:
    return await team_manager.get_all_teams()


@app.get("/teams/{id}", response_model=Team, tags=["Teams"], summary="Get the given team")
async def get_team(
    team_id: Annotated[str, Path(title="Team ID", alias="id", description="The ID of the entity")],
) -> Team:
    return await team_manager.get_team(team_id)


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
    url = await stream_service.get_stream_url(team_id, stream_type, index)
    config = await config_manager.get()
    return await proxy_handler.proxy_stream(req, url, config.auth, config.allow_insecure)


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
    return await proxy_handler.proxy_stream(req, url, auth, allow_insecure)
