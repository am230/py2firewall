import abc
import os
from typing import List

from .rule import Rule


class Firewall(abc.ABC):
    @abc.abstractmethod
    def add_rule(self, rule: Rule):
        pass

    @abc.abstractmethod
    def remove_rule(self, rule: Rule):
        pass

    @abc.abstractmethod
    def get_rules_by_name(self, name: str) -> List[Rule]:
        pass

    @abc.abstractmethod
    def get_rules(self) -> List[Rule]:
        pass


def get_firewall() -> Firewall:
    if os.name == "nt":
        from .impl.windows import WindowsFirewall

        return WindowsFirewall()
    else:
        from .impl.test import TestFirewall

        return TestFirewall()
