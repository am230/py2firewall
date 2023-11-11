from py2firewall.impl.windows import TestTerminal, WindowsFirewall
from py2firewall.rule import RuleBuilder


def test():
    test_terminal = TestTerminal()
    firewall = WindowsFirewall(test_terminal)
    rule = RuleBuilder("test").build()
    firewall.add_rule(rule)
    firewall.remove_rule(rule)
    print("Test passed!")
