
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

# Read-only risk rules. Inputs are normalized inventory, never credentials.
DEFAULTS = {
    "inactive_days": 90,
    "service_inactive_days": 90,
    "password_age_days": 365,
    "stale_computer_days": 120,
    "minimum_password_length": 12,
    "spray_min_users": 8,
    "spray_window_minutes": 15,
    "brute_min_failures": 10,
    "low_score": 1,
    "medium_score": 25,
    "high_score": 50,
    "critical_score": 75,
}

RULES = {
    "INACTIVE_ENABLED": (27, "Включённая учётная запись давно не использовалась", "Проверьте владельца и необходимость доступа; затем отключите учётную запись по процедуре."),
    "NEVER_USED": (20, "Нет зарегистрированного входа после создания учётной записи", "Уточните назначение и отключите ненужную учётную запись."),
    "PASSWORD_NEVER_EXPIRES": (26, "Срок действия пароля не ограничен", "Проверьте обоснование исключения; настройте ротацию пароля или используйте gMSA."),
    "PASSWORD_OLD": (26, "Пароль давно не менялся", "Организуйте смену пароля согласно политике и проверьте зависимости сервиса."),
    "PASSWORD_NOT_REQUIRED": (48, "Для учётной записи не требуется пароль", "Уберите флаг Password Not Required и проверьте фактическую политику входа."),
    "LOCKED": (7, "Учётная запись заблокирована", "Выясните причину блокировки по журналам аутентификации."),
    "EXPIRED": (8, "Срок действия учётной записи истёк", "Проверьте необходимость записи и архивируйте либо отключите её."),
    "PRIVILEGED_INACTIVE": (46, "Привилегированная учётная запись неактивна", "Срочно проверьте назначение привилегий и необходимость доступа."),
    "PRIVILEGED_DISABLED": (12, "Отключённая учётная запись сохраняет административные назначения", "Проверьте и удалите ненужные членства в административных группах."),
    "MULTIPLE_PRIVILEGES": (35, "Назначено несколько критических административных групп", "Пересмотрите назначения по принципу минимальных прав."),
    "NESTED_PRIVILEGE": (30, "Административные права получены через вложенную группу", "Проверьте цепочку вложенного членства и её обоснование."),
    "SERVICE_INTERACTIVE": (42, "Для сервисной записи разрешён интерактивный вход (по предоставленным данным)", "Запретите интерактивный вход через применимую политику после проверки сервиса."),
    "SERVICE_NO_OWNER": (15, "У сервисной учётной записи не указан владелец", "Назначьте владельца и документируйте назначение записи."),
    "SERVICE_PRIVILEGED": (37, "Сервисная учётная запись имеет административные права", "Снизьте привилегии до необходимого минимума и проверьте возможность gMSA."),
    "DOMAIN_PASSWORD_LENGTH": (20, "Минимальная длина доменного пароля ниже заданного порога", "Проверьте доменную и индивидуальные парольные политики и согласуйте усиление."),
    "DOMAIN_COMPLEXITY_DISABLED": (20, "Сложность паролей отключена в доменной политике", "Проверьте применимые политики и включите требования сложности по согласованной процедуре."),
    "SID_HISTORY": (20, "У учётной записи присутствует SIDHistory", "Проверьте происхождение SIDHistory и необходимость миграционного исключения."),
    "DUPLICATE_SPN": (45, "Одинаковый SPN назначен нескольким объектам", "Уточните владельца сервиса и устраните дублирующее назначение SPN."),
    "UNCONSTRAINED_DELEGATION": (60, "Включено неограниченное делегирование Kerberos", "Проверьте необходимость и замените ограниченным делегированием после оценки зависимостей."),
    "STALE_COMPUTER": (12, "Компьютер давно не использовался", "Проверьте существование узла и отключите неиспользуемый объект."),
    "PASSWORD_SPRAY_SIGNAL": (55, "В журналах замечены массовые неуспешные входы по разным аккаунтам", "Проверьте события на контроллерах домена и источник попыток; эскалируйте в ИБ."),
    "BRUTE_FORCE_SIGNAL": (40, "В журналах замечено много неуспешных входов в одну учётную запись", "Проверьте источник, интервалы и успешные входы; эскалируйте в ИБ."),
}


def iso(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)
    except ValueError:
        return None


def validate_thresholds(values: dict[str, Any]) -> dict[str, int]:
    if not isinstance(values, dict) or set(values) - set(DEFAULTS):
        raise ValueError("Неизвестные пороги")
    result = DEFAULTS | values
    if any(type(v) is not int or v < 1 or v > 10000 for v in result.values()):
        raise ValueError("Пороги должны быть целыми числами от 1 до 10000")
    if not (result["low_score"] < result["medium_score"] < result["high_score"] < result["critical_score"] <= 100):
        raise ValueError("Пороги риска должны возрастать и не превышать 100")
    return result


def severity(score: int, t: dict[str, int]) -> str:
    for name in ("critical", "high", "medium", "low"):
        if score >= t[f"{name}_score"]:
            return name.capitalize()
    return "None"


def analyze(inventory: dict[str, Any], thresholds: dict[str, int] | None = None, now: datetime | None = None) -> dict[str, Any]:
    t = validate_thresholds(thresholds or {})
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    users = inventory.get("users", [])
    groups = inventory.get("groups", [])
    computers = inventory.get("computers", [])
    if not isinstance(users, list) or not isinstance(groups, list) or not isinstance(computers, list):
        raise ValueError("users, groups и computers должны быть массивами")
    for u in users + groups + computers:
        if not isinstance(u, dict) or not u.get("dn") or not u.get("name"):
            raise ValueError("У каждого объекта обязательны dn и name")
    ids = [o["dn"].casefold() for o in users + groups + computers]
    if len(ids) != len(set(ids)):
        raise ValueError("Найдены повторяющиеся DN")

    # Traverse upwards through group membership, including nested groups, with cycle protection.
    parents: dict[str, list[dict]] = defaultdict(list)
    critical = {str(n).casefold() for n in inventory.get("critical_groups", ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Server Operators", "Backup Operators", "DNSAdmins"])}
    for g in groups:
        for member in g.get("members", []):
            parents[str(member).casefold()].append(g)
    privilege: dict[str, dict[str, Any]] = {}
    for u in users:
        start = u["dn"].casefold()
        queue = [(start, 0)]
        seen = {start}
        direct, nested = set(), set()
        while queue:
            dn, depth = queue.pop(0)
            for g in parents.get(dn, []):
                gid = g["dn"].casefold()
                if str(g["name"]).casefold() in critical or g.get("critical") is True:
                    (direct if depth == 0 else nested).add(g["name"])
                if gid not in seen:
                    seen.add(gid)
                    queue.append((gid, depth + 1))
        privilege[start] = {"direct": sorted(direct), "nested": sorted(nested)}

    spn_owners: dict[str, set[str]] = defaultdict(set)
    for u in users + computers:
        for spn in u.get("spns", []):
            spn_owners[str(spn).casefold()].add(u["dn"].casefold())

    findings = []
    scores = []
    summaries = []
    def add(obj: dict, code: str, evidence: dict | None = None):
        base, description, recommendation = RULES[code]
        is_privileged = bool(privilege.get(obj["dn"].casefold(), {}).get("direct") or privilege.get(obj["dn"].casefold(), {}).get("nested"))
        score = min(100, base + (10 if is_privileged and not code.startswith("PRIVILEGED") else 0))
        findings.append({"object_dn": obj["dn"], "object_name": obj["name"], "rule": code, "score": score, "severity": severity(score, t), "description": description, "evidence": evidence or {}, "recommendation": recommendation})

    for u in users:
        dn = u["dn"].casefold()
        kind = "service" if u.get("service") is True else "user"
        enabled = u.get("enabled") is True
        p = privilege[dn]
        privileged = bool(p["direct"] or p["nested"])
        last = iso(u.get("last_logon"))
        created = iso(u.get("created"))
        inactivity_days = (now - last).days if last else None
        limit = t["service_inactive_days"] if kind == "service" else t["inactive_days"]
        if enabled and inactivity_days is not None and inactivity_days >= limit:
            add(u, "INACTIVE_ENABLED", {"days": inactivity_days, "last_logon_is_approximate": True})
        if enabled and last is None and created and (now - created).days >= limit:
            add(u, "NEVER_USED", {"days_since_creation": (now - created).days, "last_logon_missing": True})
        if u.get("password_never_expires") is True:
            add(u, "PASSWORD_NEVER_EXPIRES")
        pwd = iso(u.get("password_last_set"))
        if enabled and pwd and (now - pwd).days >= t["password_age_days"]:
            add(u, "PASSWORD_OLD", {"days": (now - pwd).days})
        if u.get("password_not_required") is True:
            add(u, "PASSWORD_NOT_REQUIRED")
        if u.get("locked") is True:
            add(u, "LOCKED")
        expiry = iso(u.get("expires"))
        if expiry and expiry <= now:
            add(u, "EXPIRED", {"expired_at": expiry.isoformat()})
        if privileged and enabled and inactivity_days is not None and inactivity_days >= limit:
            add(u, "PRIVILEGED_INACTIVE", {"days": inactivity_days})
        if privileged and not enabled:
            add(u, "PRIVILEGED_DISABLED", {"groups": p["direct"] + p["nested"]})
        if len(set(p["direct"] + p["nested"])) > 1:
            add(u, "MULTIPLE_PRIVILEGES", {"groups": p["direct"] + p["nested"]})
        if p["nested"]:
            add(u, "NESTED_PRIVILEGE", {"groups": p["nested"]})
        if kind == "service":
            if u.get("interactive_login_allowed") is True:
                add(u, "SERVICE_INTERACTIVE", {"source": "provided policy assessment"})
            if "owner" in u and not u.get("owner"):
                add(u, "SERVICE_NO_OWNER")
            if privileged:
                add(u, "SERVICE_PRIVILEGED", {"groups": p["direct"] + p["nested"]})
        if u.get("sid_history") is True:
            add(u, "SID_HISTORY")
        if u.get("unconstrained_delegation") is True:
            add(u, "UNCONSTRAINED_DELEGATION")
        duplicates = sorted({s for s in u.get("spns", []) if len(spn_owners[str(s).casefold()]) > 1})
        if duplicates:
            add(u, "DUPLICATE_SPN", {"spns": duplicates})
        summaries.append({"dn": u["dn"], "name": u["name"], "kind": kind, "enabled": enabled, "privileged": privileged, "direct_groups": p["direct"], "nested_groups": p["nested"]})

    for c in computers:
        last = iso(c.get("last_logon"))
        if c.get("enabled") is True and last and (now - last).days >= t["stale_computer_days"]:
            add(c, "STALE_COMPUTER", {"days": (now - last).days})
        duplicates = sorted({s for s in c.get("spns", []) if len(spn_owners[str(s).casefold()]) > 1})
        if duplicates:
            add(c, "DUPLICATE_SPN", {"spns": duplicates})

    domain = inventory.get("domain", {})
    if domain:
        obj = {"dn": domain.get("dn", "domain"), "name": domain.get("name", "Domain")}
        if domain.get("minimum_password_length") is not None and domain["minimum_password_length"] < t["minimum_password_length"]:
            add(obj, "DOMAIN_PASSWORD_LENGTH", {"actual": domain["minimum_password_length"], "minimum": t["minimum_password_length"]})
        if domain.get("password_complexity_enabled") is False:
            add(obj, "DOMAIN_COMPLEXITY_DISABLED")

    # Logs contain aggregate failed attempts only. They must not carry submitted passwords.
    events = inventory.get("failed_logons", [])
    if not isinstance(events, list):
        raise ValueError("failed_logons должен быть массивом")
    by_source = defaultdict(list)
    by_account = Counter()
    for event in events:
        when = iso(event.get("time"))
        if when and 0 <= (now - when).total_seconds() <= t["spray_window_minutes"] * 60:
            by_source[str(event.get("source", "unknown"))].append(str(event.get("account", "unknown")))
            by_account[str(event.get("account", "unknown"))] += 1
    log_obj = {"dn": "security-events", "name": "Security Event Log"}
    for source, accounts in by_source.items():
        if len(set(accounts)) >= t["spray_min_users"]:
            add(log_obj, "PASSWORD_SPRAY_SIGNAL", {"source": source, "unique_accounts": len(set(accounts)), "window_minutes": t["spray_window_minutes"]})
    for account, count in by_account.items():
        if count >= t["brute_min_failures"]:
            add(log_obj, "BRUTE_FORCE_SIGNAL", {"account": account, "failures": count, "window_minutes": t["spray_window_minutes"]})

    grouped = defaultdict(list)
    for f in findings:
        grouped[f["object_dn"]].append(f)
    for obj in summaries:
        fs = grouped[obj["dn"]]
        obj["risk_score"] = min(100, sum(f["score"] for f in fs))
        obj["severity"] = severity(obj["risk_score"], t)
        obj["findings_count"] = len(fs)
        scores.append(obj["risk_score"])
    summaries.sort(key=lambda a: (-a["risk_score"], a["name"]))
    findings.sort(key=lambda f: (-f["score"], f["object_name"], f["rule"]))
    counts = Counter(f["severity"] for f in findings)
    return {
        "generated_at": now.isoformat(), "source": inventory.get("source", "snapshot"),
        "security_score": max(0, 100 - round(sum(scores) / len(scores))) if scores else None,
        "security_score_note": "100 минус средний риск пользовательских и сервисных учётных записей; null при отсутствии записей",
        "counts": {level: counts[level] for level in ("Critical", "High", "Medium", "Low")},
        "inventory": {"users": sum(x["kind"] == "user" for x in summaries), "service_accounts": sum(x["kind"] == "service" for x in summaries), "privileged_accounts": sum(x["privileged"] for x in summaries), "computers": len(computers)},
        "categories": dict(Counter(f["rule"] for f in findings)), "accounts": summaries, "findings": findings,
        "coverage": {"interactive_login": "только при переданной оценке политики входа", "authentication_signals": "только при переданных событиях 4625", "last_logon": "lastLogonTimestamp может отставать от фактического входа", "password_policy": "доменная политика, без оценки FGPP"},
        "thresholds": t,
    }
