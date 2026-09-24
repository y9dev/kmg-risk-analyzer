
from __future__ import annotations

import json
import os
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Inventory adapters. LDAP uses an encrypted connection and a read-only bind.

FORBIDDEN_KEYS = {"password", "passwd", "pwd", "secret", "credential", "token", "unicodepwd", "ntpassword", "hash"}


def reject_secrets(node: Any):
    if isinstance(node, dict):
        for key, val in node.items():
            if str(key).casefold().replace("_", "").replace("-", "") in FORBIDDEN_KEYS:
                raise ValueError("Во входных данных запрещены поля с паролями или секретами")
            reject_secrets(val)
    elif isinstance(node, list):
        for val in node:
            reject_secrets(val)


def snapshot(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    reject_secrets(data)
    if not isinstance(data, dict):
        raise ValueError("Инвентаризация должна быть объектом JSON")
    data["source"] = "snapshot"
    return data


def _filetime(value: Any) -> str | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    try:
        n = int(value)
        if n <= 0 or n >= 9223372036854775807:
            return None
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=n // 10)).isoformat()
    except (TypeError, ValueError, OverflowError):
        return None


def _iso(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    return _filetime(value)


def ldap_inventory() -> dict:
    try:
        from ldap3 import ALL, BASE, SUBTREE, Connection, Server, Tls
    except ImportError as exc:
        raise RuntimeError("Установите зависимости: pip install -r requirements.txt") from exc
    host = os.environ.get("RADAR_LDAP_HOST")
    bind_dn = os.environ.get("RADAR_LDAP_BIND_DN")
    bind_password = os.environ.get("RADAR_LDAP_BIND_PASSWORD")
    base = os.environ.get("RADAR_LDAP_BASE_DN")
    if not all((host, bind_dn, bind_password, base)):
        raise ValueError("Нужны RADAR_LDAP_HOST, RADAR_LDAP_BASE_DN и учётные данные bind в переменных среды")
    # TLS verification is mandatory; port 636, no plaintext LDAP or certificate bypass.
    tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=os.environ.get("RADAR_LDAP_CA_FILE"))
    server = Server(host, port=636, use_ssl=True, tls=tls, get_info=ALL, connect_timeout=8)
    conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True, receive_timeout=20, raise_exceptions=True, auto_referrals=False)
    attrs = ["distinguishedName", "sAMAccountName", "cn", "userAccountControl", "msDS-User-Account-Control-Computed", "lastLogonTimestamp", "pwdLastSet", "whenCreated", "accountExpires", "servicePrincipalName", "sIDHistory", "description"]
    result = {"users": [], "groups": [], "computers": [], "source": "ldaps", "domain": {}}

    def entries(filter_, attributes):
        # ldap3 pagination prevents silent truncation at AD's default page limit.
        yield from conn.extend.standard.paged_search(search_base=base, search_filter=filter_, search_scope=SUBTREE, attributes=attributes, paged_size=500, generator=True)

    def one(v):
        return v[0] if isinstance(v, list) and v else v

    def values(v):
        return v if isinstance(v, list) else ([] if v is None else [v])

    try:
        for entry in entries("(&(objectCategory=person)(objectClass=user))", attrs):
            if entry.get("type") != "searchResEntry":
                continue
            a = entry["attributes"]
            flags = int(one(a.get("userAccountControl")) or 0)
            computed = int(one(a.get("msDS-User-Account-Control-Computed")) or 0)
            dn = entry["dn"]
            spns = values(a.get("servicePrincipalName"))
            result["users"].append({
                "dn": dn, "name": str(one(a.get("sAMAccountName")) or one(a.get("cn")) or dn),
                "enabled": not bool(flags & 2), "locked": bool(computed & 16),
                "password_never_expires": bool(flags & 65536), "password_not_required": bool(flags & 32),
                "unconstrained_delegation": bool(flags & 524288), "password_last_set": _filetime(one(a.get("pwdLastSet"))),
                "last_logon": _filetime(one(a.get("lastLogonTimestamp"))), "created": _iso(one(a.get("whenCreated"))),
                "expires": _filetime(one(a.get("accountExpires"))), "spns": spns,
                "sid_history": bool(values(a.get("sIDHistory"))),
                "service": bool(spns) or "OU=Service Accounts,".casefold() in dn.casefold(),
                # Neither interactive login rights nor ownership can be inferred from SPN or description.
                "interactive_login_allowed": None,
            })
        for entry in entries("(objectClass=group)", ["cn", "member", "objectSid"]):
            if entry.get("type") == "searchResEntry":
                a = entry["attributes"]
                sid = str(one(a.get("objectSid")) or "")
                # Builtin operators and well-known domain admin RIDs survive localized CNs.
                important_sid = sid in ("S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-551") or sid.rsplit("-", 1)[-1] in ("512", "518", "519")
                members = values(a.get("member"))
                # AD returns members in ranges for large groups; fetch the remainder.
                if any(k.lower().startswith("member;range=") for k in a):
                    members = []
                    offset = 0
                    while True:
                        attr = f"member;range={offset}-{offset + 999}"
                        if not conn.search(entry["dn"], "(objectClass=group)", search_scope=BASE, attributes=[attr]):
                            break
                        returned = conn.entries[0].entry_attributes_as_dict
                        ranged = next((k for k in returned if k.lower().startswith("member;range=")), None)
                        if not ranged:
                            break
                        batch = values(returned[ranged])
                        members.extend(batch)
                        if ranged.endswith("*"):
                            break
                        offset += len(batch)
                        if not batch:
                            break
                result["groups"].append({"dn": entry["dn"], "name": str(one(a.get("cn")) or entry["dn"]), "members": members, "critical": important_sid})
        for entry in entries("(objectCategory=computer)", attrs):
            if entry.get("type") == "searchResEntry":
                a = entry["attributes"]
                flags = int(one(a.get("userAccountControl")) or 0)
                result["computers"].append({"dn": entry["dn"], "name": str(one(a.get("sAMAccountName")) or entry["dn"]), "enabled": not bool(flags & 2), "last_logon": _filetime(one(a.get("lastLogonTimestamp"))), "spns": values(a.get("servicePrincipalName"))})
        if conn.search(base, "(objectClass=domainDNS)", search_scope=BASE, attributes=["minPwdLength", "pwdProperties", "distinguishedName"]):
            a = conn.entries[0].entry_attributes_as_dict
            result["domain"] = {"dn": base, "name": base, "minimum_password_length": int(one(a.get("minPwdLength")) or 0), "password_complexity_enabled": bool(int(one(a.get("pwdProperties")) or 0) & 1)}
    finally:
        conn.unbind()
    return result
