import json
import logging
import logging.config
import pathlib
from contextlib import asynccontextmanager
from enum import StrEnum
from http import HTTPStatus
from typing import Annotated
from urllib.parse import urljoin

import aiohttp
from dotenv import dotenv_values
from fastapi import FastAPI, HTTPException, Path, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, StreamingResponse
from pydantic import BaseModel
from starlette.background import BackgroundTask

try:
    logging.config.dictConfig(json.loads((pathlib.Path(__file__).parent / "config" / "logconfig.json").read_text()))
except FileNotFoundError:
    pass

logger = logging.getLogger(__name__)


def load_config():
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

    return (
        cfg.get("BASE_URL"),
        cfg.get("USERNAME"),
        cfg.get("PASSWORD"),
        booleanize(cfg.get("ALLOW_INSECURE", "false")),
    )


BASE_URL, USERNAME, PASSWORD, ALLOW_INSECURE = load_config()


class StreamType(StrEnum):
    desktop = "desktop"
    webcam = "webcam"
    audio = "audio"


# Data models
class StreamInfo(BaseModel):
    href: str
    mime: str


class Team(BaseModel):
    id: str
    desktop: list[StreamInfo] | None = None
    webcam: list[StreamInfo] | None = None
    audio: list[StreamInfo] | None = None


# Store for team data
teams_data: dict[str, Team] = {}


async def update_teams_data() -> None:
    """
    Fetch and update teams data from the remote server
    """
    global BASE_URL, USERNAME, PASSWORD, ALLOW_INSECURE
    BASE_URL, USERNAME, PASSWORD, ALLOW_INSECURE = load_config()
    if not BASE_URL:
        logger.warning("BASE_URL not set, running without cds.")
        logger.warning("Use POST /admin/reload endpoint to update teams data from cds after setting BASE_URL.")
        logger.warning("To proxy a stream without cds, use GET /stream endpoint.")
        teams_data.clear()
        return
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(
                urljoin(BASE_URL, "teams"),
                auth=aiohttp.BasicAuth(USERNAME, PASSWORD),
                ssl=(not ALLOW_INSECURE),
            ) as response:
                if response.status != 200:
                    raise HTTPException(status_code=response.status, detail="Failed to fetch teams data")

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

        except aiohttp.ClientError:
            raise HTTPException(status_code=500, detail="Failed to fetch teams data")


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


async def _proxy_stream(url: str, username: str, password: str, allow_insecure: bool) -> StreamingResponse:
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
        auth = aiohttp.BasicAuth(username, password) if username and password else None
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


app = FastAPI(title="CDS Auth Proxy", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", include_in_schema=False)
async def index():
    return RedirectResponse("/docs")


@app.post(
    "/admin/reload",
    tags=["Admin"],
    summary="Reload the teams data from the remote server",
)
async def reload_data():
    await update_teams_data()
    return {"message": "Data updated"}


@app.get("/teams", response_model=list[Team], tags=["Teams"], summary="Get all teams")
async def get_teams():
    return list(teams_data.values())


@app.get("/teams/{id}", response_model=Team, tags=["Teams"], summary="Get the given team")
async def get_team(
    team_id: Annotated[str, Path(title="Team ID", alias="id", description="The ID of the entity")],
):
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
):
    url = _get_stream_url(team_id, stream_type, index)
    return await _proxy_stream(url, USERNAME, PASSWORD, ALLOW_INSECURE)


@app.get("/stream", tags=["Stream"], summary="Proxy the given URL with authentication")
async def proxy_stream(
    url: Annotated[str, Query(title="Stream URL", description="The URL of the stream")],
    username: Annotated[str, Query(title="Username", description="The username for authentication")] = None,
    password: Annotated[str, Query(title="Password", description="The password for authentication")] = None,
    allow_insecure: Annotated[
        bool,
        Query(
            title="Allow Insecure",
            description="Allow insecure connections",
        ),
    ] = False,
):
    return await _proxy_stream(url, username, password, allow_insecure)
