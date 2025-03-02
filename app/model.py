from enum import StrEnum
from pydantic import BaseModel, HttpUrl, SecretStr


class AuthConfig(BaseModel):
    username: str
    password: SecretStr

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"username": "admin", "password": "p@s$w0rd"},
            ]
        }
    }


class CDSConfig(BaseModel):
    base_url: HttpUrl | None = None
    auth: AuthConfig | None = None
    allow_insecure: bool = False

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "base_url": "https://cds.example.com",
                    "auth": {"username": "admin", "password": "p@s$w0rd"},
                    "allow_insecure": False,
                }
            ]
        }
    }


class StreamType(StrEnum):
    desktop = "desktop"
    webcam = "webcam"
    audio = "audio"


class StreamInfo(BaseModel):
    href: HttpUrl
    mime: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"href": "https://cds.example.com/stream/0", "mime": "video/m2ts"},
            ]
        }
    }


class Team(BaseModel):
    id: str
    desktop: list[StreamInfo] | None = None
    webcam: list[StreamInfo] | None = None
    audio: list[StreamInfo] | None = None

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "id": "team1",
                    "desktop": [
                        {"href": "https://cds.example.com/stream/0", "mime": "video/m2ts"},
                    ],
                    "webcam": [
                        {"href": "https://cds.example.com/stream/1", "mime": "video/m2ts"},
                    ],
                    "audio": [
                        {"href": "https://cds.example.com/stream/2", "mime": "audio/mp4"},
                    ],
                }
            ]
        }
    }
