#!/usr/bin/env python3
"""GitHub Actions Auth Broker sidecar.

Stdlib-only by design: urllib.request, urllib.parse, json, ssl, time, os, sys.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

CONNECT_TIMEOUT_SECONDS = 20
MAX_ATTEMPTS = 3
MAX_ERROR_BODY_CHARS = 4000


def eprint(message: str) -> None:
    print(message, file=sys.stderr)


def mask(value: str | None) -> None:
    if value:
        print(f"::add-mask::{value}")


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def require_env(name: str) -> str:
    value = env(name)
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def reject_header_value(name: str, value: str) -> None:
    if "\r" in value or "\n" in value:
        raise SystemExit(f"{name} must not contain CR/LF")


def validate_python_version() -> None:
    required = env("REQUIRED_PYTHON_PREFIX", "3.14").strip()
    if not required:
        return

    # The action is intentionally Python-3.14-first. Accept exact 3.14.x when the
    # requested setup-python input starts with 3.14. If the caller overrides the
    # input to something else, do not over-police it here.
    if required.startswith("3.14"):
        if sys.version_info < (3, 14) or sys.version_info >= (3, 15):
            raise SystemExit(
                f"Python 3.14.x is required by this action; got {sys.version.split()[0]}"
            )


def normalize_base_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise SystemExit("broker_url must be an https URL")
    if parsed.username or parsed.password:
        raise SystemExit("broker_url must not contain URL credentials")
    if any(ch.isspace() for ch in value):
        raise SystemExit("broker_url must not contain whitespace")
    return value.rstrip("/")


def join_url(base: str, path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def add_query(url: str, params: dict[str, str]) -> str:
    parts = urllib.parse.urlsplit(url)
    query = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    query.update(params)
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(query), parts.fragment)
    )


def json_dumps_bytes(data: dict[str, object]) -> bytes:
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def parse_json_or_none(body: bytes) -> object | None:
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        return None


def preview_body(body: bytes) -> str:
    text = body.decode("utf-8", errors="replace")
    text = text.replace("\r", "")
    if len(text) > MAX_ERROR_BODY_CHARS:
        return text[:MAX_ERROR_BODY_CHARS] + "\n...<truncated>"
    return text


def format_json_error(data: object | None) -> str | None:
    if not isinstance(data, dict):
        return None
    parts: list[str] = []
    for key in ("error", "message", "detail"):
        value = data.get(key)
        if isinstance(value, str) and value:
            parts.append(value)
    details = data.get("details")
    if details is not None:
        try:
            parts.append(json.dumps(details, ensure_ascii=False, separators=(",", ":")))
        except Exception:
            parts.append(str(details))
    return "\n".join(parts) if parts else None


def is_retryable(status: int | None, err: BaseException | None) -> bool:
    if err is not None:
        return True
    if status in (408, 409, 425, 429):
        return True
    if status is not None and 500 <= status <= 599:
        return True
    return False


def http_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None = None,
    expected_status: int | None = 200,
) -> tuple[int, dict[str, str], bytes]:
    last_status: int | None = None
    last_headers: dict[str, str] = {}
    last_body = b""
    last_err: BaseException | None = None

    context = ssl.create_default_context()

    for attempt in range(1, MAX_ATTEMPTS + 1):
        req = urllib.request.Request(url=url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=CONNECT_TIMEOUT_SECONDS, context=context) as resp:
                status = int(resp.status)
                resp_headers = dict(resp.headers.items())
                resp_body = resp.read()
                if expected_status is None or status == expected_status:
                    return status, resp_headers, resp_body
                last_status, last_headers, last_body, last_err = status, resp_headers, resp_body, None
        except urllib.error.HTTPError as exc:
            last_status = int(exc.code)
            last_headers = dict(exc.headers.items()) if exc.headers else {}
            last_body = exc.read() or b""
            last_err = None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_err = exc
            last_status = None
            last_headers = {}
            last_body = str(exc).encode("utf-8", errors="replace")

        if attempt < MAX_ATTEMPTS and is_retryable(last_status, last_err):
            delay = min(2 ** (attempt - 1), 4)
            eprint(f"request retrying attempt={attempt + 1}/{MAX_ATTEMPTS} method={method} status={last_status} delay_s={delay}")
            time.sleep(delay)
            continue
        break

    if expected_status is None:
        return last_status or 0, last_headers, last_body

    data = parse_json_or_none(last_body)
    json_error = format_json_error(data)
    eprint(f"request failed method={method} url={url} status={last_status}")
    if json_error:
        eprint(json_error)
    else:
        eprint(preview_body(last_body))
    print_status_diagnostic(last_status, last_headers, last_body)
    if last_err is not None:
        eprint(f"transport_error={last_err}")
    raise SystemExit(1)


def print_status_diagnostic(status: int | None, headers: dict[str, str], body: bytes) -> None:
    server = headers.get("server", "") or headers.get("Server", "")
    ray = headers.get("cf-ray", "") or headers.get("CF-RAY", "")
    body_text = body.decode("utf-8", errors="ignore").lower()
    has_cf = "cloudflare" in server.lower() or "cloudflare" in body_text or bool(ray)
    has_access = bool(env("CF_ACCESS_CLIENT_ID")) and bool(env("CF_ACCESS_CLIENT_SECRET"))

    if ray:
        eprint(f"cf_ray={ray}")

    if status == 403 and has_cf and not has_access:
        eprint("diagnostic=Cloudflare returned 403 and CF Access service-token headers were not configured.")
        eprint("diagnostic_hint=pass cf_access_client_id and cf_access_client_secret, then add a narrow WAF Skip rule for broker CI endpoints.")
    elif status == 403 and has_cf and has_access:
        eprint("diagnostic=Cloudflare returned 403 even with CF Access headers configured.")
        eprint("diagnostic_hint=check Access service-token policy, WAF Skip rule expression, and whether Bot Fight Mode is still enabled.")
    elif status == 429:
        eprint("diagnostic=rate limited. Check Cloudflare rate limiting/Bot rules and broker-side throttling.")
    elif status is not None and 520 <= status <= 526:
        eprint("diagnostic=Cloudflare edge/origin error. Check broker origin availability and TLS configuration.")


def common_headers(user_agent: str, cf_id: str, cf_secret: str) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": user_agent,
    }
    if cf_id or cf_secret:
        if not cf_id or not cf_secret:
            raise SystemExit("cf_access_client_id and cf_access_client_secret must be provided together")
        reject_header_value("CF_ACCESS_CLIENT_ID", cf_id)
        reject_header_value("CF_ACCESS_CLIENT_SECRET", cf_secret)
        mask(cf_id)
        mask(cf_secret)
        headers["CF-Access-Client-Id"] = cf_id
        headers["CF-Access-Client-Secret"] = cf_secret
    return headers


def get_github_oidc_token(audience: str, user_agent: str) -> str:
    request_url = require_env("ACTIONS_ID_TOKEN_REQUEST_URL")
    request_token = require_env("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    mask(request_token)

    oidc_url = add_query(request_url, {"audience": audience})
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {request_token}",
        "User-Agent": user_agent,
    }
    status, _headers, body = http_request("GET", oidc_url, headers, expected_status=200)
    data = parse_json_or_none(body)
    if not isinstance(data, dict):
        raise SystemExit(f"GitHub OIDC response was not JSON, status={status}")
    token = data.get("value")
    if not isinstance(token, str) or not token:
        msg = data.get("message") if isinstance(data.get("message"), str) else "oidc token request failed"
        raise SystemExit(f"Failed to resolve OIDC token from GitHub Actions runtime: {msg}")
    mask(token)
    return token


def write_output(name: str, value: str | None) -> None:
    path = env("GITHUB_OUTPUT")
    if not path:
        return
    value = value or ""
    # Outputs used here are expected to be single-line tokens/ids/timestamps.
    value = value.replace("\r", "").replace("\n", "")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"{name}={value}\n")


def probe_health(base_url: str, headers: dict[str, str]) -> None:
    url = join_url(base_url, "/healthz")
    status, resp_headers, body = http_request("GET", url, headers, expected_status=None)
    eprint(f"broker_health_status={status}")
    if status and 200 <= status < 500:
        return
    print_status_diagnostic(status, resp_headers, body)


def exchange_session(base_url: str, headers: dict[str, str], oidc_token: str) -> str:
    payload = {
        "provider": "github-actions",
        "project": require_env("PROJECT"),
        "repository": require_env("SOURCE_REPOSITORY"),
        "ref": require_env("GIT_REF"),
        "workflow": require_env("WORKFLOW_NAME"),
        "run_id": require_env("RUN_ID"),
        "actor": require_env("ACTOR"),
        "sha": require_env("COMMIT_SHA"),
        "oidc_token": oidc_token,
    }
    call_headers = dict(headers)
    call_headers["Content-Type"] = "application/json"
    status, _resp_headers, body = http_request(
        "POST",
        join_url(base_url, "/v1/ci/exchange"),
        call_headers,
        body=json_dumps_bytes(payload),
        expected_status=200,
    )
    data = parse_json_or_none(body)
    if not isinstance(data, dict):
        raise SystemExit(f"Broker exchange response was not JSON, status={status}")
    session_id = data.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise SystemExit("Broker exchange response did not include session_id")
    mask(session_id)
    write_output("session_id", session_id)
    return session_id


def request_repo_read(base_url: str, headers: dict[str, str], session_id: str) -> None:
    target_repo = env("TARGET_REPO")
    if not target_repo:
        write_output("grant_id", "")
        write_output("repo", "")
        write_output("token", "")
        write_output("expires_at", "")
        return

    payload = {
        "session_id": session_id,
        "project": require_env("PROJECT"),
        "target_repo": target_repo,
    }
    call_headers = dict(headers)
    call_headers["Content-Type"] = "application/json"
    status, _resp_headers, body = http_request(
        "POST",
        join_url(base_url, "/v1/grants/repo-read"),
        call_headers,
        body=json_dumps_bytes(payload),
        expected_status=200,
    )
    data = parse_json_or_none(body)
    if not isinstance(data, dict):
        raise SystemExit(f"Broker repo-read response was not JSON, status={status}")

    grant_id = data.get("grant_id")
    repo = data.get("repo")
    token = data.get("token")
    expires_at = data.get("expires_at")

    if not isinstance(token, str) or not token:
        raise SystemExit("Broker repo-read response did not include token")

    mask(session_id)
    mask(token)

    write_output("grant_id", grant_id if isinstance(grant_id, str) else "")
    write_output("repo", repo if isinstance(repo, str) else "")
    write_output("token", token)
    write_output("expires_at", expires_at if isinstance(expires_at, str) else "")


def main() -> int:
    validate_python_version()

    base_url = normalize_base_url(require_env("BROKER_URL"))
    user_agent = env("BROKER_USER_AGENT", "auth-broker-x-ci/1.0")
    reject_header_value("BROKER_USER_AGENT", user_agent)

    headers = common_headers(
        user_agent=user_agent,
        cf_id=env("CF_ACCESS_CLIENT_ID"),
        cf_secret=env("CF_ACCESS_CLIENT_SECRET"),
    )

    probe = env("PROBE_HEALTHZ", "true").strip().lower() in {"1", "true", "yes", "y"}
    if probe:
        probe_health(base_url, headers)

    oidc_token = get_github_oidc_token(env("BROKER_AUDIENCE", "cfw-zhi-auth-center"), user_agent)
    session_id = exchange_session(base_url, headers, oidc_token)
    request_repo_read(base_url, headers, session_id)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
