from py2firewall.impl.test import TestFirewall
from py2firewall.rule import RuleBuilder


def test():
    firewall = TestFirewall()
    rule = RuleBuilder("test").build()
    firewall.add_rule(rule)
    firewall.get_rules_by_name("test")
    firewall.remove_rule(rule)
    print("Test passed!")
