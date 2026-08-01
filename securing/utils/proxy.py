"""Sticky residential proxy helpers (host:port:user:pass).

Supports:
- niceproxy:     user ...-ssid-XXXX-sst-60
- vaultproxies:  user ...-s-XXXX-ttl-3600
- iproyal:       pass ..._session-XXXX_lifetime-30m  (session lives in password)
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import secrets
import string
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TypeVar
from urllib.parse import quote

import httpx

log = logging.getLogger(__name__)

_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.json"
# niceproxy: ssid-XXXX ; vaultproxies: -s-XXXX-ttl-N (avoid matching -sst-)
_SSID_RE = re.compile(r"(ssid-)([A-Za-z0-9]+)", re.I)
_VAULT_S_RE = re.compile(r"(?<![A-Za-z0-9])(s-)([A-Za-z0-9]+)(?=-ttl-)", re.I)
# iproyal: password like 8cMH…_country-us_session-ljur4QXZ_lifetime-30m
_IPROYAL_SESSION_RE = re.compile(
    r"(_session-)([A-Za-z0-9]+)(?=_lifetime-)", re.I
)

T = TypeVar("T")

# Proxy TLS / tunnel flakes (VaultProxies start_tls hangs, etc.)
# Ensure RemoteProtocolError is treated as proxy-retryable
PROXY_TRANSPORT_ERRORS = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    httpx.ProxyError,
    httpx.RemoteProtocolError,
    httpx.TransportError,
    httpx.TimeoutException,
)


def is_proxy_transport_error(exc: BaseException) -> bool:
    return isinstance(exc, PROXY_TRANSPORT_ERRORS)


def format_exception_reason(exc: BaseException) -> str:
    """Human-readable exception text — httpx timeouts often have empty ``str(exc)``.

    Without this, Discord showed ``Securing step failed:`` with nothing after the colon.
    """
    name = exc.__class__.__name__
    msg = str(exc).strip()
    # httpx.ReadTimeout / ConnectTimeout frequently stringify to ""
    if not msg:
        if isinstance(exc, httpx.ReadTimeout):
            return f"{name} (request timed out reading response)"
        if isinstance(exc, httpx.ConnectTimeout):
            return f"{name} (timed out connecting)"
        if isinstance(exc, httpx.TimeoutException):
            return f"{name} (request timed out)"
        if isinstance(exc, httpx.TransportError):
            return f"{name} (network/proxy transport error)"
        return name
    if msg.startswith(name):
        return msg
    return f"{name}: {msg}"


def _load_proxy_cfg() -> dict:
    try:
        cfg = json.loads(_CONFIG_PATH.read_text())
        return cfg.get("proxy") or {}
    except Exception:
        log.exception("Failed to load proxy config")
        return {}


def _random_ssid(length: int = 8, *, mixed_case: bool = False) -> str:
    alphabet = (
        (string.ascii_letters + string.digits)
        if mixed_case
        else (string.ascii_lowercase + string.digits)
    )
    return "".join(secrets.choice(alphabet) for _ in range(max(4, length)))


def _parse_line(line: str) -> dict | None:
    """Parse ``host:port:username:password`` (password may contain ``:``)."""
    line = (line or "").strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split(":", 3)
    if len(parts) != 4:
        log.warning("Invalid proxy line (need host:port:user:pass): %s", line[:60])
        return None
    host, port, user, password = parts
    if not host or not port.isdigit() or not user or not password:
        log.warning("Invalid proxy line fields: %s", line[:60])
        return None
    return {
        "host": host,
        "port": int(port),
        "username": user,
        "password": password,
    }


def _session_id_from_creds(username: str, password: str = "") -> str:
    for value in (username, password):
        if not value:
            continue
        for pat in (_SSID_RE, _VAULT_S_RE, _IPROYAL_SESSION_RE):
            m = pat.search(value)
            if m:
                return m.group(2)
    return "?"


def _session_id_from_user(username: str) -> str:
    """Back-compat helper — prefer ``_session_id_from_creds``."""
    return _session_id_from_creds(username, "")


def _rotate_sticky(username: str, password: str) -> tuple[str, str]:
    """Mint a fresh sticky session id for the configured provider.

    IPRoyal keeps ``_session-XXXX_lifetime-…`` in the *password*; Vault/Niceproxy
    keep it in the username. Never fall back to appending vault-style tags onto
    an IPRoyal username (that breaks auth).
    """
    if _SSID_RE.search(username):
        return (
            _SSID_RE.sub(
                lambda m: m.group(1) + _random_ssid(len(m.group(2)) or 10),
                username,
                count=1,
            ),
            password,
        )
    if _VAULT_S_RE.search(username):
        return (
            _VAULT_S_RE.sub(
                lambda m: m.group(1) + _random_ssid(len(m.group(2)) or 8),
                username,
                count=1,
            ),
            password,
        )
    # IPRoyal (and similar): session token in password
    if _IPROYAL_SESSION_RE.search(password):
        return (
            username,
            _IPROYAL_SESSION_RE.sub(
                lambda m: m.group(1)
                + _random_ssid(len(m.group(2)) or 8, mixed_case=True),
                password,
                count=1,
            ),
        )
    if _IPROYAL_SESSION_RE.search(username):
        return (
            _IPROYAL_SESSION_RE.sub(
                lambda m: m.group(1)
                + _random_ssid(len(m.group(2)) or 8, mixed_case=True),
                username,
                count=1,
            ),
            password,
        )
    # Fallback: append vault-style sticky segment (1h) to username
    return f"{username}-s-{_random_ssid(8)}-ttl-3600", password


def _with_fresh_ssid(username: str) -> str:
    """Replace sticky session id in username (Vault/Niceproxy). Prefer ``_rotate_sticky``."""
    user, _ = _rotate_sticky(username, "")
    return user


def build_proxy_url() -> str | None:
    """Pick a random proxy template and mint a fresh sticky session URL.

    Returns an httpx proxy URL like ``http://user:pass@host:port`` or None if disabled.
    """
    cfg = _load_proxy_cfg()
    if not cfg.get("enabled", False):
        return None

    lines = cfg.get("proxies") or []
    if isinstance(lines, str):
        lines = [lines]
    parsed = [p for p in (_parse_line(x) for x in lines) if p]
    if not parsed:
        log.warning("proxy.enabled but no valid proxies configured")
        return None

    base = random.choice(parsed)
    user, password = base["username"], base["password"]
    if cfg.get("rotate_ssid", True):
        user, password = _rotate_sticky(user, password)
    user_q = quote(user, safe="-._~")
    pass_q = quote(password, safe="-._~")
    scheme = (cfg.get("scheme") or "http").strip().lower()
    if scheme not in ("http", "https", "socks5", "socks5h"):
        scheme = "http"
    host = (cfg.get("host_override") or base["host"]).strip()
    url = f"{scheme}://{user_q}:{pass_q}@{host}:{base['port']}"
    sid = _session_id_from_creds(user, password)
    print(f"[~] - Proxy sticky s={sid} via {host}:{base['port']} ({scheme})")
    log.info("Using proxy %s:%s session=%s scheme=%s", host, base["port"], sid, scheme)
    return url


async def close_session(session: httpx.AsyncClient | None) -> None:
    if session is None:
        return
    try:
        await session.aclose()
    except Exception:
        pass


async def run_with_proxy_retry(
    session: httpx.AsyncClient,
    factory: Callable[[httpx.AsyncClient], Awaitable[T]],
    *,
    new_session: Callable[[], httpx.AsyncClient],
    attempts: int = 4,
    rotate_ssid_after: int = 2,
    label: str = "request",
    email: str | None = None,
) -> tuple[T, httpx.AsyncClient]:
    """Run ``factory(session)``, retrying proxy/connect failures.

    After each transport error the client is replaced (dead tunnels rarely recover).
    Once failures reach ``rotate_ssid_after`` (default 2), logs explicitly that a
    **new sticky SSID** is being minted via ``new_session()`` / ``build_proxy_url``.

    Returns ``(result, session)`` — caller must keep using the returned session.
    """
    if attempts < 1:
        attempts = 1
    if rotate_ssid_after < 1:
        rotate_ssid_after = 1

    current = session
    last_exc: BaseException | None = None
    who = email or label

    for attempt in range(1, attempts + 1):
        try:
            result = await factory(current)
            return result, current
        except PROXY_TRANSPORT_ERRORS as exc:
            last_exc = exc
            rotate = attempt >= rotate_ssid_after
            log.warning(
                "proxy retry %s/%s for %s (%s): %s — %s",
                attempt,
                attempts,
                who,
                label,
                exc.__class__.__name__,
                "rotating sticky SSID" if rotate else "new client (same pool)",
            )
            print(
                f"[!] - Proxy {exc.__class__.__name__} on {label} "
                f"({attempt}/{attempts})"
                + (" — new sticky SSID…" if rotate else " — retrying…")
            )
            if attempt >= attempts:
                break

            await close_session(current)
            # get_session() always mints a fresh SSID when rotate_ssid is enabled;
            # after rotate_ssid_after we call it again so the sticky exit changes.
            current = new_session()
            delay = 1.0 * attempt if not rotate else 1.5 * attempt
            await asyncio.sleep(delay)

    assert last_exc is not None
    raise last_exc
