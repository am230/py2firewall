from __future__ import annotations

import abc
import subprocess
from dataclasses import dataclass
from typing import List, NotRequired, TypedDict

from ..address import IpSelector, PortSelector
from ..firewall import NetFilter
from ..rule import Action, Direction, Protocol, Rule

try:
    import winreg
except ImportError:
    winreg = None

REGISTRY_KEY_FIREWALL = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"


class Terminal(abc.ABC):
    @abc.abstractmethod
    def run(self, command: List[str]) -> CommandResult:
        pass


class SubprocessTerminal(Terminal):
    def run(self, command: List[str]) -> CommandResult:
        result = subprocess.run(command)
        return CommandResult(
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
        )


class Registry(abc.ABC):
    @abc.abstractmethod
    def get_values(self, key: str) -> List[str]:
        pass


class WindowsRegistry(Registry):
    def get_values(self, key: str) -> List[str]:
        if winreg is None:
            raise RuntimeError("winreg module not found")
        _key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key)
        values = []
        i = 0
        while True:
            try:
                values.append(winreg.EnumValue(_key, i))
                i += 1
            except OSError:
                break
        return values


class WindowsFirewall(NetFilter):
    def __init__(
        self,
        terminal: Terminal = SubprocessTerminal(),
        registry: Registry = WindowsRegistry(),
    ):
        self.terminal = terminal
        self.registry = registry

    def add_rule(self, rule: Rule):
        args = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule.name}",
            f"dir={rule.direction.value}",
            f"action={rule.action.value}",
            f"protocol={'any' if rule.protocol == Protocol.ANY else rule.protocol.value}",
        ]

        if rule.protocol != Protocol.ANY:
            args.extend(
                [
                    f"localport={'any' if rule.local_port.is_any() else rule.local_port}",
                    f"remoteport={'any' if rule.remote_port.is_any() else rule.remote_port}",
                    f"localip={'any' if rule.local_ip.is_any() else rule.local_ip}",
                    f"remoteip={'any' if rule.remote_ip.is_any() else rule.remote_ip}",
                ]
            )
        elif not rule.local_port.is_any() and not rule.remote_port.is_any():
            raise ValueError("Cannot use any port with any protocol")

        if (
            self.terminal.run(
                args,
            ).returncode
            != 0
        ):
            raise RuntimeError("Failed to add rule")

    def remove_rule(self, rule: Rule):
        if (
            self.terminal.run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    f"name={rule.name}",
                ]
            ).returncode
            != 0
        ):
            raise RuntimeError("Failed to remove rule")

    def _parse_rule(self, attrs: RuleDict) -> Rule:
        return Rule(
            name=attrs["Name"],
            direction={"In": Direction.INBOUND, "Out": Direction.OUTBOUND}[
                attrs["Dir"]
            ],
            action={"Block": Action.BLOCK, "Allow": Action.ALLOW}[attrs["Action"]],
            protocol={
                6: Protocol.TCP,
                17: Protocol.UDP,
            }.get(attrs.get("Protocol", "*"), Protocol.ANY),
            local_port=PortSelector.from_str(attrs.get("LPort", "*")),
            remote_port=PortSelector.from_str(attrs.get("RPort", "*")),
            local_ip=IpSelector.from_str(attrs.get("LAddr", "*")),
            remote_ip=IpSelector.from_str(attrs.get("RAddr", "*")),
        )

    def get_rules(self) -> List[Rule]:
        rules = []
        for rule in self.registry.get_values(
            REGISTRY_KEY_FIREWALL,
        ):
            attrs = {}
            for attr in rule[1].split("|"):
                if "=" not in attr:
                    continue
                key, value = attr.split("=")
                attrs[key] = value
            rules.append(self._parse_rule(RuleDict(**attrs)))
        return rules

    def get_rules_by_name(self, name: str) -> List[Rule]:
        rules = []
        for rule in self.registry.get_values(
            REGISTRY_KEY_FIREWALL,
        ):
            attrs = {}
            for attr in rule[1].split("|"):
                if "=" not in attr:
                    continue
                key, value = attr.split("=")
                attrs[key] = value
            if attrs["Name"] == name:
                rules.append(self._parse_rule(RuleDict(**attrs)))
        return rules


@dataclass
class CommandResult:
    stdout: bytes
    stderr: bytes
    returncode: int


class TestTerminal(Terminal):
    def run(self, command: List[str]) -> CommandResult:
        print("Executing command:", command)
        return CommandResult(
            stdout=b"",
            stderr=b"",
            returncode=0,
        )


class RuleDict(TypedDict):
    Name: str
    Dir: str
    Action: str
    Protocol: NotRequired[str]
    LPort: NotRequired[str]
    RPort: NotRequired[str]
    LAddr: NotRequired[str]
    RAddr: NotRequired[str]
