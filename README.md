# CDS Auth Proxy

A proxy server that handles authentication for CDS team streams.

It is intended to be used as a CORS-enabled endpoint for CDS team streams without authentication.
This can be useful for embedding team streams in external websites (e.g. [ICPC Live Overlay](https://github.com/icpc/live-v3))
when the contest is frozen and the CDS team stream is not publicly available without authentication.

## Installation

```bash
pipx install git+https://github.com/cn-xcpc-tools/cds-auth-proxy
```

## Usage

`.env` file:

```env
USERNAME=live
PASSWORD=l1ve
BASE_URL=https://cds/api/contests/test/
ALLOW_INSECURE=false
```

Change `USERNAME` and `PASSWORD` to your CDS credentials, and the `BASE_URL` to the URL of the CDS contest you want to access.
Change `ALLOW_INSECURE` to `true` if you want to allow insecure connections to cds (e.g. self-signed certificates).

- `cds-auth-proxy` will start the https server with `granian` on port 8000. (requires a certificate and key in the `certs` folder).
    You can use `--host` and `--port` to change the binding address and port.

> [!NOTE]
> Browsers limit the number of HTTP connections with the same domain name. This restriction is defined in the HTTP specification (RFC2616). Most modern browsers allow six connections per domain. Most older browsers allow only two connections per domain.
>
> When embedding multiple streams (such as ICPC Live Split Screen), you may need to avoid this limitation by running multiple instances of the proxy on different ports, or use HTTP/2 (this can be done by putting a "termination proxy" in front, like `Traefik`, `Caddy`, or `Nginx`, or setting up https with `granian`, which is done by automatically generating a self-signed certificate).

### Get Streams

Example usages:

- `https://localhost:8000/teams/{id}/webcam` gets the webcam stream.
- `https://localhost:8000/teams/{id}/desktop` gets the desktop stream.
- `https://localhost:8000/teams/{id}/webcam?index=1` gets the second webcam stream.
- `https://localhost:8000/streams?url={url}` gets the stream from the given URL (with CORS).

## Development

```bash
uv sync
fastapi dev src/cds_auth_proxy/app.py
```

---
Inspired by [kbats183/webrtc-proxy](https://github.com/kbats183/webrtc-proxy) and [Hydro/xcpc-tools](https://github.com/hydro-dev/xcpc-tools)
