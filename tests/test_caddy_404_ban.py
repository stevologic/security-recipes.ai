from __future__ import annotations

import configparser
import ipaddress
import json
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FILTER_CONFIG = ROOT / "config" / "fail2ban" / "filter.d" / "security-recipes-caddy-404.conf"
JAIL_CONFIG = ROOT / "config" / "fail2ban" / "jail.d" / "security-recipes-caddy-404.local"
INSTALLER = ROOT / "scripts" / "configure_caddy_404_ban.sh"
FIXTURE = ROOT / "tests" / "fixtures" / "caddy-404-mixed.jsonl"
JAIL_NAME = "security-recipes-caddy-404"

HOST_PATTERN = (
    r"(?P<host>(?:[0-9]{1,3}\.){3}[0-9]{1,3}|"
    r"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})"
)


def load_ini(path: Path) -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser(interpolation=None, strict=True)
    with path.open(encoding="utf-8") as stream:
        parser.read_file(stream)
    return parser


def duration_seconds(raw_value: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*([smhd]?)\s*", raw_value.lower())
    if not match:
        raise AssertionError(f"Unsupported Fail2Ban duration: {raw_value!r}")
    amount = int(match.group(1))
    multiplier = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
    return amount * multiplier


def expanded_filter_patterns(filter_config: configparser.RawConfigParser) -> list[re.Pattern[str]]:
    raw_patterns = filter_config.get("Definition", "failregex")
    patterns: list[re.Pattern[str]] = []
    for raw_pattern in raw_patterns.splitlines():
        raw_pattern = raw_pattern.strip()
        if not raw_pattern:
            continue
        expanded = raw_pattern.replace("<HOST>", HOST_PATTERN)
        expanded = re.sub(r"</?F-[A-Z0-9_-]+>", "", expanded)
        patterns.append(re.compile(expanded))
    return patterns


class Caddy404BanStaticTests(unittest.TestCase):
    def test_policy_has_exact_threshold_window_and_expiry_without_escalation(self) -> None:
        jail = load_ini(JAIL_CONFIG)

        self.assertTrue(jail.has_section(JAIL_NAME))
        self.assertTrue(jail.getboolean(JAIL_NAME, "enabled"))
        self.assertEqual(jail.getint(JAIL_NAME, "maxretry"), 5)
        self.assertEqual(duration_seconds(jail.get(JAIL_NAME, "findtime")), 5)
        self.assertEqual(duration_seconds(jail.get(JAIL_NAME, "bantime")), 3600)
        self.assertFalse(jail.getboolean(JAIL_NAME, "bantime.increment"))
        for escalation_option in ("bantime.factor", "bantime.maxtime", "bantime.overalljails"):
            self.assertFalse(jail.has_option(JAIL_NAME, escalation_option))

    def test_filter_uses_caddy_client_ip_and_only_top_level_404_status(self) -> None:
        filter_config = load_ini(FILTER_CONFIG)
        failregex = filter_config.get("Definition", "failregex")

        self.assertIn('"client_ip"', failregex)
        self.assertIn("<HOST>", failregex)
        self.assertIn(r'"http\.log\.access"', failregex)
        self.assertIn('"status"', failregex)
        self.assertIn("404", failregex)
        self.assertNotIn('"remote_ip"', failregex)
        self.assertEqual(
            filter_config.get("Definition", "datepattern"),
            '"ts":{EPOCH}',
        )
        configured_patterns = [
            pattern for pattern in failregex.splitlines() if pattern.strip()
        ]
        self.assertTrue(all(pattern.startswith("^") for pattern in configured_patterns))
        self.assertTrue(all(pattern.endswith("$") for pattern in configured_patterns))

        lines = FIXTURE.read_text(encoding="utf-8").splitlines()
        records = [json.loads(line) for line in lines]
        expected = [
            record.get("status") == 404
            and isinstance(record.get("request"), dict)
            and bool(record["request"].get("client_ip"))
            for record in records
        ]
        self.assertEqual(expected, [True, True, True, True, True, False, False, False, False, False])
        triggering_records = [
            record
            for record, should_match in zip(records, expected, strict=True)
            if should_match
        ]
        self.assertEqual(
            {record["request"]["client_ip"] for record in triggering_records},
            {"203.0.113.42"},
        )
        self.assertLessEqual(
            max(record["ts"] for record in triggering_records)
            - min(record["ts"] for record in triggering_records),
            5,
        )

        patterns = expanded_filter_patterns(filter_config)
        self.assertGreaterEqual(len(patterns), 1)
        actual = [any(pattern.search(line) for pattern in patterns) for line in lines]
        self.assertEqual(actual, expected)

    def test_loopback_and_private_networks_are_ignored(self) -> None:
        jail = load_ini(JAIL_CONFIG)
        configured_networks = [
            ipaddress.ip_network(token, strict=False)
            for token in re.split(r"[\s,]+", jail.get(JAIL_NAME, "ignoreip").strip())
            if token
        ]

        for address in (
            "127.0.0.1",
            "::1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "fc00::1",
            "fe80::1",
        ):
            ip = ipaddress.ip_address(address)
            self.assertTrue(
                any(ip.version == network.version and ip in network for network in configured_networks),
                f"{address} is not covered by ignoreip",
            )

    def test_actions_cover_input_and_forward_for_tcp_and_udp(self) -> None:
        jail = load_ini(JAIL_CONFIG)
        action = jail.get(JAIL_NAME, "action")
        nftables_actions = re.findall(r"\bnftables(?:-[a-z0-9_-]+)?\s*\[([^]]+)\]", action, re.IGNORECASE)

        self.assertEqual(len(nftables_actions), 4, action)
        combinations: set[tuple[str, str]] = set()
        for parameters in nftables_actions:
            chain_match = re.search(r"\bchain_hook\s*=\s*[\"']?([a-z]+)", parameters, re.IGNORECASE)
            protocol_match = re.search(r"\bprotocol\s*=\s*[\"']?([a-z]+)", parameters, re.IGNORECASE)
            self.assertIsNotNone(chain_match, parameters)
            self.assertIsNotNone(protocol_match, parameters)
            combinations.add((chain_match.group(1).lower(), protocol_match.group(1).lower()))

        self.assertEqual(
            combinations,
            {
                ("input", "tcp"),
                ("input", "udp"),
                ("forward", "tcp"),
                ("forward", "udp"),
            },
        )

    def test_installer_validates_filter_and_configuration_before_reload(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertRegex(source, r"(?m)^set -[Eeuo]+ pipefail$")

        filter_validations = [
            match
            for match in re.finditer(
                r"(?m)^[^#\n]*(?:fail2ban-regex|FAIL2BAN_REGEX)[^#\n]*$",
                source,
            )
            if "command -v" not in match.group(0)
        ]
        filter_validation = filter_validations[-1] if filter_validations else None
        client_validation = re.search(
            r"(?m)^[^#\n]*(?:fail2ban-client|FAIL2BAN_CLIENT)[^#\n]*(?:\s-t\b|--test\b)[^#\n]*$",
            source,
        )
        reload_command = re.search(
            r"(?m)^[^#\n]*(?:systemctl\s+reload\s+fail2ban|"
            r"(?:fail2ban-client|FAIL2BAN_CLIENT)[^#\n]*\breload\b)[^#\n]*$",
            source,
        )

        self.assertIsNotNone(filter_validation, "installer must run fail2ban-regex")
        self.assertIsNotNone(client_validation, "installer must run fail2ban-client -t")
        self.assertIsNotNone(reload_command, "installer must reload Fail2Ban")
        self.assertLess(filter_validation.start(), reload_command.start())
        self.assertLess(client_validation.start(), reload_command.start())

        bash = shutil.which("bash")
        if os.name != "nt" and bash:
            subprocess.run([bash, "-n", str(INSTALLER)], cwd=ROOT, check=True)


class Caddy404BanNativeToolTests(unittest.TestCase):
    def test_fail2ban_regex_matches_only_the_five_real_404s_when_available(self) -> None:
        fail2ban_regex = shutil.which("fail2ban-regex")
        if not fail2ban_regex:
            self.skipTest("fail2ban-regex is not installed")

        result = subprocess.run(
            [fail2ban_regex, str(FIXTURE), str(FILTER_CONFIG)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        summary = re.search(
            r"Lines:\s+\d+\s+lines,\s+\d+\s+ignored,\s+(\d+)\s+matched,\s+(\d+)\s+missed",
            output,
        )
        self.assertIsNotNone(summary, output)
        self.assertEqual((int(summary.group(1)), int(summary.group(2))), (5, 5))

    def test_fail2ban_client_binary_is_healthy_when_available(self) -> None:
        fail2ban_client = shutil.which("fail2ban-client")
        if not fail2ban_client:
            self.skipTest("fail2ban-client is not installed")

        result = subprocess.run(
            [fail2ban_client, "-V"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
