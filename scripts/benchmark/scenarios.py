"""Centralized attack-scenario definitions for the AEGIS live KPI harness.

Single source of truth (replaces the old load-test runbook). Each scenario maps
to either HTTP request paths replayed against the Juice Shop target (always
available, no external tool) or to optional external Kali tools (nmap, nikto,
gobuster, sqlmap, hydra) that are skipped gracefully when not installed.

Intensity scales the volume: smoke (a few alerts), standard (dozens), soak
(hundreds, run in parallel — the "beaucoup de logs" load test).
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Repeats applied to each web request path, per intensity.
INTENSITY_REPEATS: dict[str, int] = {"once": 1, "smoke": 2, "standard": 10, "soak": 60}
# Soak adds parallelism + a loop count to sustain a high log rate.
SOAK_PARALLELISM = 6
SOAK_LOOPS = 4


@dataclass(frozen=True)
class WebScenario:
    """A scenario expressed as URL paths replayed against the web target."""

    scenario_id: str
    description: str
    expected_rules: tuple[int, ...]
    paths: tuple[str, ...]


@dataclass(frozen=True)
class ToolScenario:
    """A scenario expressed as an external Kali tool command (argv template).

    ``argv`` uses ``{url}`` / ``{host}`` placeholders, filled at run time.
    Skipped with a warning when the binary is absent.
    """

    scenario_id: str
    description: str
    expected_rules: tuple[int, ...]
    argv: tuple[str, ...]


WEB_SCENARIOS: dict[str, WebScenario] = {
    "A": WebScenario(
        "A",
        "Recon / scanning (404 sweep, hidden paths)",
        (31151, 31108),
        (
            "/admin",
            "/.git/config",
            "/backup.zip",
            "/.env",
            "/phpmyadmin",
            "/server-status",
            "/api/internal",
            "/wp-login.php",
        ),
    ),
    "B": WebScenario(
        "B",
        "SQL injection",
        (31103, 31152),
        (
            "/rest/products/search?q=test%27%20UNION%20SELECT%20username,password%20FROM%20Users--",
            "/rest/products/search?q=1%27%20OR%20%271%27=%271",
            "/rest/products/search?q=%27%3B%20DROP%20TABLE%20Users--",
        ),
    ),
    "C": WebScenario(
        "C",
        "Cross-site scripting (XSS)",
        (31105, 31154),
        (
            "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E",
        ),
    ),
    "D": WebScenario(
        "D",
        "Path traversal / LFI",
        (31153, 31104),
        (
            "/iisadmpwd/..%c0%af../winnt/system32/cmd.exe?/c+dir",
            "/ftp/..%2f..%2f..%2fetc%2fpasswd",
            "/?file=../../../../etc/passwd",
        ),
    ),
    "E": WebScenario(
        "E",
        "Command injection",
        (31103,),
        (
            "/api/run?cmd=ls%3Bid",
            "/api/run?cmd=cat%20/etc/passwd%7Cwhoami",
        ),
    ),
}

TOOL_SCENARIOS: dict[str, ToolScenario] = {
    "A": ToolScenario(
        "A",
        "Recon — nikto / gobuster",
        (31151, 31108),
        ("nikto", "-h", "{url}", "-Tuning", "9b", "-maxtime", "60s"),
    ),
    "F": ToolScenario(
        "F",
        "Brute force — hydra HTTP login form",
        (31151,),
        (
            "hydra",
            "-l",
            "admin@juice-sh.op",
            "-P",
            "/usr/share/wordlists/rockyou.txt",
            "{host}",
            "-s",
            "9080",
            "http-post-form",
            "/rest/user/login:email=^USER^&password=^PASS^:Invalid email",
        ),
    ),
}

ALL_SCENARIO_IDS: tuple[str, ...] = ("A", "B", "C", "D", "E", "F")


@dataclass(frozen=True)
class ResolvedRun:
    """A scenario resolved to concrete web requests + optional tool commands."""

    web_requests: list[str] = field(default_factory=list)
    tool_commands: list[list[str]] = field(default_factory=list)


def resolve(scenario_ids: list[str], base_url: str, host: str, intensity: str) -> ResolvedRun:
    """Resolve selected scenarios into concrete requests/commands for an intensity."""
    repeats = INTENSITY_REPEATS[intensity]
    run = ResolvedRun()
    for sid in scenario_ids:
        web = WEB_SCENARIOS.get(sid)
        if web is not None:
            for path in web.paths:
                run.web_requests.extend([base_url.rstrip("/") + path] * repeats)
        tool = TOOL_SCENARIOS.get(sid)
        if tool is not None:
            argv = [a.format(url=base_url, host=host) for a in tool.argv]
            run.tool_commands.append(argv)
    return run
