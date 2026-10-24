"""ScopeGuard: the single URL egress check for all target-facing actions.

Rules:
- scheme must be http/https; userinfo is forbidden.
- host must match at least one include rule (exact host or bounded suffix).
- bare IPs must be explicitly registered with an exact host rule.
- path must not match any exclude path_regex.
"""

import ipaddress
import re
from urllib.parse import urlparse

from .enums import ScopeKind, ScopeRuleType
from .errors import ScopeViolationError
from .models import ScopeEntry


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class ScopeGuard:
    def __init__(self, entries: list[ScopeEntry]):
        self.includes = [e for e in entries if e.kind == ScopeKind.INCLUDE.value]
        excludes = [e for e in entries if e.kind == ScopeKind.EXCLUDE.value]
        self._excludes: list[tuple[str, re.Pattern[str]]] = []
        for entry in excludes:
            try:
                self._excludes.append((entry.value, re.compile(entry.value)))
            except re.error as exc:
                raise ScopeViolationError(f"排除规则不是合法正则: {entry.value} ({exc})") from exc

    def check(self, url: str) -> tuple[bool, str]:
        """Return (allowed, reason). Never raises; pure decision for easy testing."""
        try:
            parsed = urlparse(url)
        except ValueError:
            return False, "URL 无法解析"

        if parsed.scheme not in ("http", "https"):
            return False, f"scheme 不允许: {parsed.scheme!r}"
        if not parsed.hostname:
            return False, "URL 缺少 host"
        if parsed.username or parsed.password:
            return False, "URL 不允许包含用户名/密码"

        host = parsed.hostname.lower()

        if is_ip_literal(host):
            if not self._ip_explicitly_allowed(host):
                return False, f"裸 IP 未在 scope 中显式登记: {host}"
        elif not any(self._host_matches(host, e) for e in self.includes):
            return False, f"host 不在授权 scope 内: {host}"

        path = parsed.path or "/"
        for raw, pattern in self._excludes:
            if pattern.search(path):
                return False, f"路径命中排除规则 {raw!r}: {path}"

        return True, "ok"

    def assert_url_allowed(self, url: str) -> None:
        """Raise ScopeViolationError when the URL is not authorized."""
        allowed, reason = self.check(url)
        if not allowed:
            raise ScopeViolationError(reason)

    def _ip_explicitly_allowed(self, host: str) -> bool:
        for entry in self.includes:
            if entry.rule_type != ScopeRuleType.HOST.value:
                continue
            if entry.value.lower().strip() == host:
                return True
        return False

    @staticmethod
    def _host_matches(host: str, entry: ScopeEntry) -> bool:
        value = entry.value.lower().strip()
        if entry.rule_type == ScopeRuleType.HOST.value:
            return host == value
        if entry.rule_type == ScopeRuleType.HOST_SUFFIX.value:
            # Bounded suffix: prevent evil-example.com matching suffix example.com
            return host == value or host.endswith("." + value)
        return False
