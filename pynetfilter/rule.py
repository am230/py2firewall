import dataclasses
import enum

from pynetfilter.address import (
    AnyIp,
    AnyPort,
    IpSelector,
    IpUnion,
    PortSelector,
    PortUnion,
    SinglePort,
)
from pynetfilter.helper import get_ip_list


class Direction(str, enum.Enum):
    INBOUND = "in"
    OUTBOUND = "out"


class Action(str, enum.Enum):
    ALLOW = "allow"
    BLOCK = "block"


class Protocol(str, enum.Enum):
    TCP = "tcp"
    UDP = "udp"
    ANY = "*"


@dataclasses.dataclass
class Rule:
    name: str
    direction: Direction
    action: Action
    protocol: Protocol
    local_port: PortSelector
    remote_port: PortSelector
    local_ip: IpSelector
    remote_ip: IpSelector


class RuleBuilder:
    def __init__(self, name: str):
        if not name:
            raise ValueError("Rule name cannot be empty")
        self.name = name
        self.direction = Direction.INBOUND
        self.action = Action.BLOCK
        self.protocol = Protocol.ANY
        self.local_port = PortUnion()
        self.remote_port = PortUnion()
        self.local_ip = IpUnion()
        self.remote_ip = IpUnion()

        self.building = True

    def build(self) -> Rule:
        if not self.building:
            raise RuntimeError("RuleBuilder already built")
        self.building = False
        return Rule(
            self.name,
            self.direction,
            self.action,
            self.protocol,
            self.local_port or AnyPort(),
            self.remote_port or AnyPort(),
            self.local_ip or AnyIp(),
            self.remote_ip or AnyIp(),
        )

    def set_direction(self, direction: Direction):
        self.direction = direction
        return self

    def set_action(self, action: Action):
        self.action = action
        return self

    def set_protocol(self, protocol: Protocol):
        self.protocol = protocol
        return self

    def add_local_port(self, port_number: int):
        self.local_port.append(SinglePort(port_number))
        return self

    def add_remote_port(self, port_number: int):
        self.remote_port.append(SinglePort(port_number))
        return self

    def add_local_port_str(self, port_str: str):
        self.local_port.append(PortSelector.from_str(port_str))
        return self

    def add_remote_port_str(self, port_str: str):
        self.remote_port.append(PortSelector.from_str(port_str))
        return self

    def add_local_ip(self, ip: str):
        self.local_ip.append(IpSelector.from_str(ip))
        return self

    def add_remote_ip(self, ip: str):
        self.remote_ip.append(IpSelector.from_str(ip))
        return self

    def add_local_domain(self, domain: str):
        self.local_ip.append(IpUnion.from_str_list(get_ip_list(domain)))
        return self

    def add_remote_domain(self, domain: str):
        self.remote_ip.append(IpUnion.from_str_list(get_ip_list(domain)))
        return self
