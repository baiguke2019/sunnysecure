"""Add an outlook.com alias and promote it to primary.

HTTP flow aligned with dona-fork (names/manage canary → AddAssocId → MakePrimary):
- Canary comes from ``/names/manage``, not the AddAssocId HTML form.
- AddAssocId uses ``PostOption=NONE`` and treats ``alias=`` in the response
  (body or Location) as success — Microsoft often 302s without a clean HTML ok page.
- Verify by re-listing aliases on ``/names/manage``.
- MakePrimary uses ``removeOldPrimary=True`` like the working fork.
"""

from __future__ import annotations

from urllib.parse import unquote
import asyncio
import json
import logging
import re

import httpx

logger = logging.getLogger(__name__)

_CANARY_PATTERNS = (
    r'<input[^>]*id="canary"[^>]*name="canary"[^>]*value="([^"]+)"',
    r'<input[^>]*name="canary"[^>]*id="canary"[^>]*value="([^"]+)"',
    r'<input[^>]*name="canary"[^>]*value="([^"]+)"',
    r'id="canary"[^>]*value="([^"]+)"',
    r'name="canary"\s+value="([^"]+)"',
    r'"apiCanary"\s*:\s*"([^"]+)"',
    r'"canary"\s*:\s*"([^"]+)"',
)


def _extract_canary(html: str) -> str | None:
    for pat in _CANARY_PATTERNS:
        m = re.search(pat, html or "", re.I)
        if m:
            return m.group(1)
    return None


def _emails_from_manage(html: str) -> list[str]:
    """Collect alias emails from names/manage HTML."""
    found: list[str] = []
    for m in re.finditer(
        r'id="idAliasEmail\d+".*?<span class="dirltr\s*">([^<]+@[^<]+)</span>',
        html or "",
        re.DOTALL | re.I,
    ):
        found.append(m.group(1).strip().lower())
    if not found:
        # Fallback: any email-looking tokens on the manage page
        for m in re.finditer(
            r"([a-zA-Z0-9._+-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]{2,})",
            html or "",
        ):
            addr = m.group(1).strip().lower()
            if addr not in found and not addr.endswith((".png", ".jpg", ".css", ".js")):
                found.append(addr)
    # de-dupe preserve order
    out: list[str] = []
    seen: set[str] = set()
    for e in found:
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out


def _auth_redirect_fields(html: str) -> tuple[str, str] | None:
    """Extract code+state for account.live.com/auth/redirect continue forms."""
    code_m = re.search(r'<input[^>]*name="code"[^>]*value="([^"]+)"', html or "", re.I)
    state_m = re.search(r'<input[^>]*name="state"[^>]*value="([^"]+)"', html or "", re.I)
    if code_m and state_m:
        return unquote(code_m.group(1)), unquote(state_m.group(1))
    return None


async def _submit_auth_redirect(session: httpx.AsyncClient, html: str) -> str | None:
    """POST OAuth continue form → account.live.com/auth/redirect. Returns new HTML or None."""
    pair = _auth_redirect_fields(html)
    if not pair:
        return None
    code, state = pair
    print("[~] - Submitting account.live.com/auth/redirect (OAuth MFA continue)…")
    resp = await session.post(
        "https://account.live.com/auth/redirect",
        data={"code": code, "state": state},
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        follow_redirects=True,
    )
    return resp.text or ""


async def _get_manage(session: httpx.AsyncClient) -> tuple[str, str | None, list[str]]:
    """GET names/manage → (html, canary, emails). Handles auth/redirect bounce once."""
    resp = await session.get(
        "https://account.live.com/names/manage",
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        follow_redirects=True,
    )
    text = resp.text or ""

    redirected = await _submit_auth_redirect(session, text)
    if redirected is not None:
        text = redirected
        # Re-fetch manage after elevation
        resp = await session.get(
            "https://account.live.com/names/manage",
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
            follow_redirects=True,
        )
        text = resp.text or ""
        redirected2 = await _submit_auth_redirect(session, text)
        if redirected2 is not None:
            text = redirected2
            resp = await session.get(
                "https://account.live.com/names/manage",
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
                follow_redirects=True,
            )
            text = resp.text or ""

    canary = _extract_canary(text)
    if canary:
        try:
            session.cookies.set("canary", canary, domain="account.live.com")
        except Exception:
            pass
    return text, canary, _emails_from_manage(text)


def _add_looks_successful(resp: httpx.Response, local: str, full: str) -> bool:
    """Dona checks ``alias=`` in body; also honor Location / manage bounce."""
    body = resp.text or ""
    loc = ""
    try:
        loc = resp.headers.get("location") or ""
    except Exception:
        loc = ""
    blob = f"{body}\n{loc}".lower()
    full_l = full.lower()
    local_l = local.lower()

    if "alias=" in blob:
        return True
    if full_l in blob or f"associatedidlive={local_l}" in blob.replace(" ", ""):
        return True
    # Soft success tokens Microsoft uses on the confirm / names page
    if any(
        t in blob
        for t in (
            "note_associatedidadded",
            "associatedidadded",
            "aliasadded",
            "you've added",
            "you have added",
        )
    ):
        return True
    return False


def _add_hard_failure(resp: httpx.Response) -> str | None:
    """Return a reason string if the response is a clear hard reject."""
    body = (resp.text or "").lower()
    loc = (resp.headers.get("location") or "").lower()
    blob = f"{body}\n{loc}"
    checks = (
        ("already associated", "already associated"),
        ("already being used", "already being used"),
        ("not available", "not available"),
        ("isn't available", "not available"),
        ("is unavailable", "not available"),
        ("try again later", "try again later"),
        ("too many", "too many"),
        ("can't add", "can't add"),
        ("cannot add", "cannot add"),
        ("unable to add", "unable to add"),
    )
    for needle, label in checks:
        if needle in blob:
            return label
    return None


async def _add_outlook_alias(
    session: httpx.AsyncClient,
    local: str,
    canary: str,
    *,
    security_email: str | None = None,
    account_email: str | None = None,
    password: str | None = None,
) -> bool:
    """POST AddAssocId. Returns True if Microsoft accepted the new alias."""
    full = f"{local}@outlook.com"
    # Match dona: PostOption=NONE, no query string, do not follow redirects
    # (success often lives in a 302 Location with alias=).
    resp = await session.post(
        "https://account.live.com/AddAssocId",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://account.live.com",
            "Referer": "https://account.live.com/names/manage",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        data={
            "canary": canary,
            "PostOption": "NONE",
            "SingleDomain": "outlook.com",
            "UpSell": "",
            "AddAssocIdOptions": "LIVE",
            "AssociatedIdLive": local,
        },
        follow_redirects=False,
    )

    hard = _add_hard_failure(resp)
    if _add_looks_successful(resp, local, full):
        print(f"[+] - Added alias ({full})")
        return True

    loc = (resp.headers.get("location") or "").lower()
    # MFA / SA interrupt — follow, elevate, retry once
    if (
        resp.status_code in (301, 302, 303, 307, 308)
        and (
            "oauth" in loc
            or "login.live.com" in loc
            or "acr_values" in loc
            or "mfa" in loc
        )
        and security_email
    ):
        print("[~] - AddAssocId redirected to MFA — elevating then retrying…")
        followed = await session.get(
            resp.headers.get("location") or loc,
            follow_redirects=True,
        )
        # Often lands on fmHF continue form with code+state → auth/redirect
        # (NOT an i5600 OTC page). Submit that first.
        body = followed.text or ""
        redirected = await _submit_auth_redirect(session, body)
        if redirected is not None:
            body = redirected
        else:
            # Genuine MFA challenge — try email OTC elevation
            body = await _follow_post_auth_forms(session, body, str(followed.url))
            html2, canary2, emails2 = await _elevate_for_names_manage(
                session,
                body,
                security_email=security_email,
                account_email=account_email,
                password=password,
            )
            body = html2
            if full.lower() in emails2:
                print(f"[+] - Added alias ({full}) — confirmed after MFA")
                return True
            if canary2:
                canary = canary2

        # After auth/redirect, refresh manage + retry AddAssocId
        _, canary2, emails2 = await _get_manage(session)
        if full.lower() in emails2:
            print(f"[+] - Added alias ({full}) — confirmed after auth/redirect")
            return True
        if canary2:
            resp = await session.post(
                "https://account.live.com/AddAssocId",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://account.live.com",
                    "Referer": "https://account.live.com/names/manage",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
                data={
                    "canary": canary2,
                    "PostOption": "NONE",
                    "SingleDomain": "outlook.com",
                    "UpSell": "",
                    "AddAssocIdOptions": "LIVE",
                    "AssociatedIdLive": local,
                },
                follow_redirects=False,
            )
            if _add_looks_successful(resp, local, full):
                print(f"[+] - Added alias ({full}) after MFA retry")
                return True
            # One more auth/redirect hop if still bouncing
            loc2 = resp.headers.get("location") or ""
            if resp.status_code in (301, 302, 303) and loc2:
                hop = await session.get(loc2, follow_redirects=True)
                await _submit_auth_redirect(session, hop.text or "")
                _, _, emails3 = await _get_manage(session)
                if full.lower() in emails3:
                    print(f"[+] - Added alias ({full}) — confirmed after 2nd auth/redirect")
                    return True

    # Always verify via names/manage — HTML error strings are noisy false positives
    # (old bug: "not available"/"can't add" in chrome → skip MakePrimary → delete alias).
    _, _, emails = await _get_manage(session)
    if full.lower() in emails:
        print(f"[+] - Added alias ({full}) — confirmed on names/manage")
        return True

    if hard:
        logger.error(
            "AddAssocId hard-reject %s status=%s reason=%s body=%s",
            full,
            resp.status_code,
            hard,
            (resp.text or "")[:400],
        )
        print(f"[X] - Failed to add alias ({full}) — {hard}")
        return False

    logger.error(
        "AddAssocId ambiguous fail %s status=%s loc=%s body=%s",
        full,
        resp.status_code,
        resp.headers.get("location"),
        (resp.text or "")[:500],
    )
    print(f"[X] - Failed to add alias ({full})")
    return False


async def _gct_exists(email: str) -> bool | None:
    """True/False if GetCredentialType is conclusive; None if unknown.

    IfExistsResult: 0 = exists, 1 = does not exist (MS convention).
    """
    email = (email or "").strip()
    if not email or "@" not in email:
        return None
    try:
        from securing.autobuy_hold_check import fetch_credential_type

        info = await fetch_credential_type(email)
    except Exception as exc:
        logger.warning("GCT exists-check failed for %s: %s", email, exc)
        return None
    if not info:
        return None
    flag = info.get("IfExistsResult")
    if flag in (1, "1"):
        return False
    if flag in (0, "0"):
        return True
    return None


async def _confirm_primary_switched(
    session: httpx.AsyncClient,
    new_full: str,
    old_email: str | None,
) -> bool:
    """Ground-truth check after MakePrimary — API often lies / returns opaque errors
    while ``removeOldPrimary`` already deleted the old Outlook login.
    """
    new_l = (new_full or "").strip().lower()
    old_l = (old_email or "").strip().lower()
    if not new_l:
        return False

    # 1) names/manage scrape (may be stale right after promote — still useful)
    try:
        await asyncio.sleep(1.0)
        _, _, aliases = await _get_manage(session)
        aliases_l = {a.strip().lower() for a in aliases}
        if new_l in aliases_l and old_l and old_l not in aliases_l:
            print(
                f"[+] - Primary switch confirmed on manage "
                f"(has {new_full}, old {old_email} gone)"
            )
            return True
    except Exception as exc:
        logger.warning("manage confirm after MakePrimary failed: %s", exc)

    # 2) GetCredentialType — authoritative for "account doesn't exist"
    if old_l and old_l != new_l:
        old_exists = await _gct_exists(old_l)
        new_exists = await _gct_exists(new_l)
        print(
            f"[~] - Primary switch GCT check "
            f"(old {old_l} exists={old_exists}, new {new_l} exists={new_exists})"
        )
        if old_exists is False and new_exists is True:
            print(
                f"[+] - Primary switch confirmed via GetCredentialType "
                f"(old login removed, {new_full} live)"
            )
            return True
        # Old gone + new unknown still strongly implies success
        if old_exists is False and new_exists is not False:
            print(
                f"[+] - Primary switch confirmed via GetCredentialType "
                f"(old login {old_email} no longer exists)"
            )
            return True
    else:
        new_exists = await _gct_exists(new_l)
        if new_exists is True:
            print(f"[+] - New primary exists on GCT ({new_full})")
            return True

    return False


async def _make_primary(
    session: httpx.AsyncClient,
    full: str,
    apicanary: str,
) -> bool:
    """POST /API/MakePrimary. Opaque error code 500 is treated as success (dona)."""
    uaid = None
    try:
        uaid = session.cookies.get("uaid") or session.cookies.get("MSPPre")
    except Exception:
        uaid = None

    payload = {
        "aliasName": full,
        "emailChecked": True,
        "removeOldPrimary": True,
        "uiflvr": 1001,
        "scid": 100141,
        "hpgid": 200176,
    }
    if uaid:
        payload["uaid"] = str(uaid)[:64]

    resp = await session.post(
        "https://account.live.com/API/MakePrimary",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "canary": apicanary,
            "hpgid": "200176",
            "scid": "100141",
            "uiflvr": "1001",
            "Origin": "https://account.live.com",
            "Referer": "https://account.live.com/names/manage",
        },
        content=json.dumps(payload),
    )

    try:
        data = resp.json() if (resp.text or "").strip() else {}
    except json.JSONDecodeError:
        # Socket hang / empty body after success is common
        if resp.status_code in (200, 204, 500) or not (resp.text or "").strip():
            print(f"[+] - Changed Primary Alias ({full}) — empty/non-JSON OK")
            return True
        logger.error(
            "MakePrimary non-JSON for %s status=%s body=%s",
            full,
            resp.status_code,
            (resp.text or "")[:400],
        )
        print(f"[X] - Failed to change primary alias ({full})")
        return False

    if "error" in data:
        err = data.get("error") or {}
        code = str(err.get("code", ""))
        if code == "500":
            print(f"[+] - Changed Primary Alias ({full})")
            return True
        logger.error("MakePrimary error for %s: %s", full, err)
        print(f"[X] - Failed to change primary alias ({full}) — {code or err}")
        return False

    print(f"[+] - Changed Primary Alias ({full})")
    return True


async def _follow_post_auth_forms(session: httpx.AsyncClient, text: str, url: str = "") -> str:
    """Submit obvious SSO / continue forms after i5600 so cookies elevate."""
    from securing.utils.security_information import (
        _extract_form_action,
        _extract_hidden_fields,
        _sso_fields,
        _object_moved_href,
        _page_id,
    )

    current = text or ""
    current_url = url or ""
    for _ in range(8):
        # OAuth MFA continue → account.live.com/auth/redirect
        redirected = await _submit_auth_redirect(session, current)
        if redirected is not None:
            current = redirected
            current_url = "https://account.live.com/auth/redirect"
            continue
        moved = _object_moved_href(current)
        if moved:
            r = await session.get(moved, follow_redirects=True)
            current, current_url = r.text or "", str(r.url)
            continue
        # Accrou / proofs skip
        skip = None
        for pat in (
            r'"skip"\s*:\s*\{\s*"url"\s*:\s*"([^"]+)"',
            r'"skipUrl"\s*:\s*"([^"]+)"',
            r'"cancel"\s*:\s*\{\s*"url"\s*:\s*"([^"]+)"',
        ):
            m = re.search(pat, current)
            if m:
                skip = m.group(1).replace("\\u0026", "&").replace("\\/", "/")
                break
        if skip and ("account.live.com" in skip or "login.live.com" in skip):
            # Prefer skip on Accrou/recover interrupts so we don't stick on t0-only pages
            if "recover" in current_url.lower() or "help us secure" in current.lower():
                r = await session.get(skip, follow_redirects=True)
                current, current_url = r.text or "", str(r.url)
                continue
        sso, _missing = _sso_fields(current)
        if sso:
            r = await session.post(
                sso["action"],
                data={
                    "pprid": sso["pprid"],
                    "NAP": sso["NAP"],
                    "ANON": sso["ANON"],
                    "t": sso["t"],
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                follow_redirects=True,
            )
            current, current_url = r.text or "", str(r.url)
            continue
        fields = _extract_hidden_fields(current)
        action = _extract_form_action(current, current_url)
        if action and "pprid" in fields and ("ipt" in fields or "NAP" in fields or "t" in fields):
            r = await session.post(
                action,
                data=fields,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                follow_redirects=True,
            )
            current, current_url = r.text or "", str(r.url)
            continue
        pid = _page_id(current)
        if pid not in ("i5600", "i5030"):
            break
        break
    return current


async def _elevate_for_names_manage(
    session: httpx.AsyncClient,
    html: str,
    *,
    security_email: str | None,
    account_email: str | None,
    password: str | None,
) -> tuple[str, str | None, list[str]]:
    """Pass SA_20MIN / recover / i5600 so names/manage returns a real canary.

    Live flow for compromised accounts:
      names/manage → login.srf?wp=SA_20MIN → fmHF → account.live.com/recover
      → (skip) or i5600 Help-us-protect → OTC → manage canary

    Clean accounts hit i5600 directly on SA_20MIN with
    ``fProofConfirmationRequired: true``.
    """
    from securing.utils.security_information import (
        _complete_i5600_email_otc,
        _page_id,
        _extract_url_post_sft,
        _extract_email_otc_proof,
    )

    text = html or ""
    # Always chase continue / recover forms first
    text = await _follow_post_auth_forms(session, text, "")
    canary = _extract_canary(text)
    if canary and "names/manage" in text.lower() and _page_id(text) not in ("i5600", "i5030"):
        return text, canary, _emails_from_manage(text)

    pid = _page_id(text)
    needs_i5600 = pid == "i5600" or (
        "help us protect" in text.lower() and "arrUserProofs" in text
    )
    # OAuth MFA interrupt (AddAssocId / manage sometimes lands here)
    needs_oauth = (
        "acr_values" in text.lower()
        or "urn:microsoft:policies:mfa" in text.lower()
        or (
            "oauth20_authorize" in text.lower()
            and _extract_email_otc_proof(text) is not None
        )
    )

    if not needs_i5600 and not needs_oauth:
        # Re-hit manage after form chasing
        return await _get_manage(session)

    if not security_email or security_email in ("Couldn't Change!", "Unknown"):
        print("[X] - names/manage blocked by SA elevation and no security email")
        return text, None, _emails_from_manage(text)

    print("[~] - names/manage requires SA elevation — completing security-email MFA…")
    resp = await _complete_i5600_email_otc(
        session,
        text,
        security_email=security_email,
        account_email=account_email,
        password=password,
        wait_slices=(20.0, 30.0),
        label="Names MFA",
        try_password_first=bool(password),
    )
    if resp is None:
        print("[X] - Failed to elevate session for names/manage")
        return text, None, _emails_from_manage(text)

    await _follow_post_auth_forms(session, resp.text or "", str(getattr(resp, "url", "")))
    return await _get_manage(session)


async def change_primary_alias(
    session: httpx.AsyncClient,
    email: str,
    apicanary: str,
    *,
    security_email: str | None = None,
    account_email: str | None = None,
    password: str | None = None,
) -> bool:
    """
    ``email`` is the local-part only (e.g. sunnyabc123).
    Returns True only when the new address is confirmed primary-capable
    (added + MakePrimary accepted, or already listed after promote).
    """
    local = (email or "").strip().split("@", 1)[0]
    if not local:
        return False
    full = f"{local}@outlook.com"

    try:
        if not apicanary:
            print(f"[X] - Failed to change primary alias ({full}) — no apicanary")
            return False

        html, canary, before = await _get_manage(session)
        if not canary:
            html, canary, before = await _elevate_for_names_manage(
                session,
                html,
                security_email=security_email,
                account_email=(
                    account_email
                    or (before[0] if before else None)
                ),
                password=password,
            )

        if not canary:
            # Fallback: try AddAssocId page canary (legacy path) after elevation
            add_page = await session.get(
                "https://account.live.com/AddAssocId",
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                },
                follow_redirects=True,
            )
            add_html = add_page.text or ""
            canary = _extract_canary(add_html)
            if not canary:
                from securing.utils.security_information import _page_id as _pid

                # Do NOT re-run Names MFA here — first elevate already burned the
                # OTP/password attempt. A second 2–3 minute wait is pure waste.
                if _pid(add_html) == "i5600" or "help us protect" in add_html.lower():
                    print(
                        "[!] - AddAssocId still on SA MFA after elevate — "
                        "not retrying OTP wait"
                    )
                    logger.warning(
                        "change_primary_alias: skipping second elevate on i5600"
                    )
        if not canary:
            print(f"[X] - Failed to change primary alias ({full}) — no canary")
            logger.error(
                "change_primary_alias: no canary (manage len=%s login_hint=%s)",
                len(html or ""),
                "login.live.com" in (html or "").lower(),
            )
            return False

        already = full.lower() in before
        if already:
            print(f"[~] - Alias already present ({full}) — promoting")
        else:
            added = await _add_outlook_alias(
                session,
                local,
                canary,
                security_email=security_email,
                account_email=account_email,
                password=password,
            )
            if not added:
                # One retry with a fresh manage canary
                _, canary2, emails2 = await _get_manage(session)
                if full.lower() in emails2:
                    print(f"[+] - Alias present after add attempt ({full})")
                elif canary2:
                    added = await _add_outlook_alias(
                        session,
                        local,
                        canary2,
                        security_email=security_email,
                        account_email=account_email,
                        password=password,
                    )
                    if not added:
                        return False
                else:
                    return False

        # MakePrimary often flakes right after AddAssocId MFA (stale canary /
        # session). Retry promote with a fresh canary before giving up — the
        # alias is already on the account; inventing a NEW sunny on the outer
        # loop just hits "try again later".
        ok = False
        for promo_try in range(1, 4):
            try:
                from securing.utils.cookies.get_cookies import get_cookies

                fresh = await get_cookies(session)
                if fresh:
                    apicanary = fresh
            except Exception:
                pass
            # Also pull canary from names/manage (more reliable post-MFA)
            try:
                _, manage_canary, on_manage = await _get_manage(session)
                if manage_canary:
                    apicanary = manage_canary
                if full.lower() not in [e.lower() for e in on_manage]:
                    # Alias vanished — don't keep promoting a ghost
                    if promo_try == 1:
                        print(f"[X] - Alias missing before MakePrimary ({full})")
                    break
            except Exception:
                on_manage = []

            print(f"[~] - MakePrimary attempt {promo_try}/3 ({full})")
            ok = await _make_primary(session, full, apicanary)
            if ok:
                break
            # Even on API "failure", MS may have already applied removeOldPrimary.
            if await _confirm_primary_switched(session, full, account_email):
                return True
            await asyncio.sleep(1.5 * promo_try)

        # Final ground-truth — never trust MakePrimary JSON alone (sale2026025 case:
        # API reported fail, old Outlook deleted, sunny* became the only login).
        if await _confirm_primary_switched(session, full, account_email):
            return True

        if ok:
            _, _, after = await _get_manage(session)
            if full.lower() in {a.lower() for a in after}:
                return True
            logger.warning(
                "MakePrimary OK but %s not scraped on manage (aliases=%s) — trusting API",
                full,
                after[:8],
            )
            return True

        print(f"[X] - Failed to change primary alias ({full})")
        return False

    except Exception as e:
        logger.exception("Error changing primary alias: %s", e)
        # Last-chance: MakePrimary may have thrown after MS already switched
        try:
            if await _confirm_primary_switched(session, full, account_email):
                return True
        except Exception:
            pass
        print(f"[X] - Failed to change primary alias ({full})")
        return False
